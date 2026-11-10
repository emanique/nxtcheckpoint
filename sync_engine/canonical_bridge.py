"""Private canonical bridge: NSX Infra export -> offline disabled Check Point candidate.

No Check Point API calls. Rejects unsupported rules and requires an independently
approved rule-content hash. All results contain sensitive configuration.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from .candidate import ref_name
from .group_logic import resolve_group_expression, UnsafeExpression
from .inventory import load_private_inventory
from .model import digest
from .dependency_hash import semantic_rule_hash, DependencyHashError
from .precedence import analyze_precedence
from .offline import assess, load_export, unwrap, service_compat
from .object_plan import build_plan, PlanError


class CanonicalError(ValueError):
    pass


def _network_object(cidr):
    net = ipaddress.ip_network(cidr, strict=True)
    if net.version != 4:
        raise CanonicalError("unsupported_ip_family")
    ref = "address:" + str(net)
    name = ref_name("NSXMIG_A_", ref)
    if net.prefixlen == 32:
        return name, {"kind": "host", "name": name,
                      "ip": str(net.network_address), "source_ref": ref}
    return name, {"kind": "network", "name": name,
                  "network": str(net.network_address),
                  "prefix": net.prefixlen, "source_ref": ref}


def _service_objects(service):
    if service_compat(service)[0] != "A":
        raise CanonicalError("service_not_supported")
    result = []
    for entry in service["service_entries"]:
        for port in entry["destination_ports"]:
            proto = entry["l4_protocol"]
            ref = "service:" + str(service["path"]) + ":" + proto + ":" + str(port)
            name = ref_name("NSXMIG_S_", ref)
            result.append((name, {"kind": "service", "name": name,
                                  "protocol": proto, "port": str(port),
                                  "source_ref": ref}))
    return result


def _groups_for_rule(rule, catalog, inventory):
    output = {}
    refs = {}
    for field in ("source_groups", "destination_groups"):
        names = []
        for path in rule.get(field, []):
            if path == "ANY":
                raise CanonicalError("any_operand_not_supported")
            group = catalog.get(path)
            if group is None:
                raise CanonicalError("missing_group")
            resolved = resolve_group_expression(group, catalog, inventory["identity_map"])
            if not resolved.networks:
                raise CanonicalError("empty_group")
            member_names = []
            for cidr in resolved.networks:
                name, obj = _network_object(cidr)
                output[name] = obj
                member_names.append(name)
            group_name = ref_name("NSXMIG_G_", path)
            output[group_name] = {
                "kind": "group", "name": group_name,
                "members": sorted(set(member_names)), "source_ref": path,
            }
            names.append(group_name)
        if not names:
            raise CanonicalError("empty_group_operand")
        refs[field] = names
    return output, refs


def compile_private_candidate(root, inventory, approvals=None):
    """Conservative all-or-nothing canonical bridge; no persistence or API."""
    if not inventory or not isinstance(inventory.get("effective_group_members"), dict):
        raise CanonicalError("verified_inventory_required")
    assessment = assess(root, inventory=inventory,
                        identity_map=inventory.get("identity_map"))
    ordering = analyze_precedence(root)
    position_by_id = {row["anonymous_id"]: row for row in ordering["rows"]}
    data = unwrap(root)
    groups = {obj["path"]: obj for obj in data["Group"] if obj.get("path")}
    services = {obj["path"]: obj for obj in data["Service"] if obj.get("path")}
    index = {}
    for policy in data["SecurityPolicy"]:
        for child in policy.get("children", []):
            rule = child.get("Rule") if isinstance(child, dict) else None
            if not isinstance(rule, dict):
                continue
            ref = str(rule.get("path") or (
                str(policy.get("path", "")) + "/" + str(rule.get("id", ""))))
            fingerprint = hashlib.sha256(ref.encode()).hexdigest()[:16]
            if fingerprint in index:
                raise CanonicalError("ambiguous_rule_identity")
            index[fingerprint] = rule

    desired = {}
    rules, rejected = [], []
    approvals = approvals or {}
    for entry in assessment["rules"]:
        anon = entry["anonymous_id"]
        rule = index[anon]
        blockers = list(entry["reason_codes"])
        if entry["class"] != "B":
            rejected.append({"anonymous_id": anon, "reasons": blockers})
            continue
        # The B label indicates only syntax eligibility. Approval must bind the
        # complete source rule payload and a documented gateway path review.
        try:
            rule_hash = semantic_rule_hash(rule, groups, services, inventory["identity_map"])
        except DependencyHashError as exc:
            rejected.append({"anonymous_id": anon, "reasons": [str(exc)]})
            continue
        approval = approvals.get(anon, {})
        if (approval.get("rule_hash") != rule_hash
                or not approval.get("approver")
                or not approval.get("topology_evidence")
                or not approval.get("precedence_evidence")
                or approval.get("source_order_hash") != ordering["source_order_hash"]):
            rejected.append({"anonymous_id": anon,
                             "reasons": ["approval_or_topology_evidence_missing"]})
            continue
        try:
            objects, endpoints = _groups_for_rule(rule, groups, inventory)
            target_services = []
            for path in rule.get("services", []):
                if path == "ANY":
                    raise CanonicalError("any_service_not_supported")
                service = services.get(path)
                if service is None:
                    raise CanonicalError("missing_service")
                for name, obj in _service_objects(service):
                    objects[name] = obj
                    target_services.append(name)
            if not target_services:
                raise CanonicalError("no_services")
        except (UnsafeExpression, CanonicalError, ValueError, KeyError) as exc:
            reason = (exc.code if isinstance(exc, UnsafeExpression) else
                      str(exc) if isinstance(exc, CanonicalError) else
                      "object_resolution_error")
            rejected.append({"anonymous_id": anon, "reasons": [reason]})
            continue

        desired.update(objects)
        sid = "sha256:" + hashlib.sha256(
            str(rule.get("path", anon)).encode()).hexdigest()
        rules.append({
            "name": ref_name("NSXMIG_R_", sid),
            "source": endpoints["source_groups"],
            "destination": endpoints["destination_groups"],
            "service": sorted(set(target_services)),
            "action": {"ALLOW": "Accept", "DROP": "Drop"}[rule["action"]],
            "track": {"type": "Log" if rule.get("logged") else "None"},
            "enabled": False,
            "comments": "NXTCP-RULE:" + rule_hash[:32],
            "source_id": sid, "hash": rule_hash,
            "indicative_source_position": position_by_id[anon]["indicative_position"],
            "precedence_status": position_by_id[anon]["status"],
        })
    candidate = {
        "schema": "nxtcheckpoint.canonical-candidate.v1",
        "objects": [desired[k] for k in sorted(desired)],
        "rules": sorted(rules, key=lambda r: r["indicative_source_position"]),
        "rejected": rejected,
        "read_only": True,
        "enforcement_authorized": False,
        "reconciliation": assessment["reconciliation"],
        "precedence": {k: v for k, v in ordering.items() if k != "rows"},
    }
    candidate["candidate_hash"] = digest({
        "objects": candidate["objects"], "rules": candidate["rules"]})
    return candidate


def save_private_candidate(candidate, destination):
    output = Path(destination)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.is_symlink():
        raise CanonicalError("symlink_output_directory")
    path = output / "canonical_candidate.private.json"
    if path.exists() or path.is_symlink():
        raise CanonicalError("output_exists")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(candidate, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="Private NSX canonical candidate; NO writes")
    ap.add_argument("--input", required=True, help="Private hierarchical NSX Infra export")
    ap.add_argument("--inventory-file", required=True, help="Private fresh NSX identity/membership file")
    ap.add_argument("--approvals", help="Private JSON: anonymous_id -> hash and evidence")
    ap.add_argument("--max-inventory-age-seconds", type=int, default=600)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    if args.max_inventory_age_seconds <= 0:
        ap.error("Invalid inventory age")
    inventory = load_private_inventory(
        args.inventory_file, max_age_seconds=args.max_inventory_age_seconds)
    approvals = json.loads(Path(args.approvals).read_text()) if args.approvals else {}
    candidate = compile_private_candidate(load_export(args.input), inventory, approvals)
    save_private_candidate(candidate, args.output)
    print(json.dumps({
        "read_only": True, "candidate_rules": len(candidate["rules"]),
        "rejected_rules": len(candidate["rejected"]),
        "candidate_objects": len(candidate["objects"]),
        "candidate_hash": candidate["candidate_hash"],
    }))


if __name__ == "__main__":
    main()
