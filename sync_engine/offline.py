"""Offline hierarchical NSX Infra export assessment; no Check Point writes.

Public reports contain only generated anonymous IDs, reason codes and counts.
"""
import argparse
import collections
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
from .group_logic import resolve_group_expression, UnsafeExpression

KINDS = ("SecurityPolicy", "Rule", "Group", "Service")


def load_export(path):
    raw = Path(path).read_bytes()
    encoding = ("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff"))
                else "utf-8-sig")
    data = json.loads(raw.decode(encoding))
    if not isinstance(data, dict) or data.get("resource_type") != "Infra":
        raise ValueError("Expected NSX Infra JSON export")
    return data


def unwrap(root):
    """Traverse Child* wrappers once; preserve embedded object children."""
    objects = {kind: [] for kind in KINDS}

    def visit(node):
        if isinstance(node, list):
            for item in node:
                visit(item)
        elif isinstance(node, dict):
            kind = node.get("resource_type")
            if kind in objects:
                objects[kind].append(node)
            for child in node.get("children", []):
                if isinstance(child, dict):
                    inner = next((v for k, v in child.items()
                                  if not k.startswith("Child")
                                  and isinstance(v, dict) and v.get("resource_type")), None)
                    visit(inner if inner is not None else child)

    visit(root)
    return objects


def ipv4_valid(value):
    try:
        if "-" in value:
            first, last = value.split("-", 1)
            a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
            return a.version == b.version == 4 and int(a) <= int(b)
        return ipaddress.ip_network(value, strict=False).version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def group_compat(group):
    expression = group.get("expression") or []
    if group.get("extended_expression"):
        return "C", "extended_group_expression"
    if len(expression) != 1:
        return "C", "compound_or_empty_group"
    item = expression[0]
    if item.get("resource_type") != "IPAddressExpression":
        return "C", "identity_or_dynamic_group"
    addresses = item.get("ip_addresses") or []
    if not addresses or not all(ipv4_valid(x) for x in addresses):
        return "C", "non_ipv4_or_invalid_address"
    return "A", "static_ipv4"


def service_compat(service):
    entries = service.get("service_entries") or []
    if not entries:
        return "C", "empty_service"
    for entry in entries:
        if entry.get("resource_type") != "L4PortSetServiceEntry" or entry.get("l4_protocol") not in ("TCP", "UDP"):
            return "C", "non_l4_service"
        if entry.get("source_ports"):
            return "C", "source_port_constraint"
        ports = entry.get("destination_ports") or []
        if not ports:
            return "C", "empty_destination_ports"
        for port in ports:
            parts = str(port).split("-")
            if len(parts) > 2 or not all(x.isdecimal() for x in parts):
                return "C", "invalid_port"
            numbers = [int(x) for x in parts]
            if not all(1 <= n <= 65535 for n in numbers) or numbers != sorted(numbers):
                return "C", "invalid_port"
    return "A", "l4_tcp_udp"


def assess(root, identity_map=None):
    objects = unwrap(root)
    group_objects = {g["path"]: g for g in objects["Group"] if g.get("path")}
    groups = {}
    for path, group in group_objects.items():
        try:
            resolved = resolve_group_expression(group, group_objects, identity_map)
            label = "resolved_identity_or_path" if (
                resolved.identity_dependencies or resolved.group_dependencies
            ) else "static_ipv4"
            groups[path] = ("A", label)
        except UnsafeExpression as error:
            groups[path] = ("C", error.code)
    services = {s["path"]: service_compat(s) for s in objects["Service"] if s.get("path")}
    reasons = collections.Counter()
    rows = []
    for policy in objects["SecurityPolicy"]:
        for child in policy.get("children", []):
            rule = child.get("Rule") if isinstance(child, dict) else None
            if not isinstance(rule, dict):
                continue
            issues = set()
            if rule.get("action") not in ("ALLOW", "DROP"):
                issues.add("unsupported_action")
            if rule.get("disabled") or policy.get("marked_for_delete") or rule.get("marked_for_delete"):
                issues.add("inactive_or_deleted")
            if rule.get("direction") != "IN_OUT":
                issues.add("direction_requires_analysis")
            if rule.get("sources_excluded") or rule.get("destinations_excluded"):
                issues.add("negation_requires_analysis")
            if policy.get("stateful") is False or policy.get("tcp_strict") is not None:
                issues.add("stateful_semantics_review")
            if policy.get("scope") not in (None, [], ["ANY"]) or rule.get("scope") not in (None, [], ["ANY"]):
                issues.add("scoped_enforcement")
            if rule.get("ip_protocol") not in ("IPV4", None):
                issues.add("ipv6_or_dual_stack")
            if rule.get("profiles"):
                issues.add("security_profiles_review")
            if any(rule.get(k) == ["ANY"] for k in ("services", "source_groups", "destination_groups")):
                issues.add("any_operand_review")
            for field in ("source_groups", "destination_groups"):
                for ref in rule.get(field, []):
                    if ref == "ANY":
                        continue
                    if ref not in groups:
                        issues.add("unknown_group_reference")
                    elif groups[ref][0] != "A":
                        issues.add("complex_group_reference")
            for ref in rule.get("services", []):
                if ref == "ANY":
                    continue
                if ref not in services:
                    issues.add("unknown_service_reference")
                elif services[ref][0] != "A":
                    issues.add("complex_service_reference")
            if policy.get("category") not in ("Emergency", "Infrastructure", "Environment", "Application"):
                issues.add("category_requires_analysis")
            classification = "C" if issues else "B"
            source_ref = str(rule.get("path") or (str(policy.get("path", "")) + "/" + str(rule.get("id", ""))))
            anonymous_id = hashlib.sha256(source_ref.encode()).hexdigest()[:16]
            codes = sorted(issues) or ["topology_and_rule_order_review"]
            rows.append({"anonymous_id": anonymous_id, "class": classification, "reason_codes": codes})
            reasons.update(codes)
    classes = collections.Counter(r["class"] for r in rows)
    return {
        "schema": "nxtcheckpoint.offline-assessment.v1",
        "source_format": "NSX Infra hierarchical export",
        "counts": {{"SecurityPolicy": "policies", "Rule": "rules", "Group": "groups", "Service": "services"}[k]: len(objects[k]) for k in KINDS},
        "groups": dict(collections.Counter(v[1] for v in groups.values())),
        "services": dict(collections.Counter(v[1] for v in services.values())),
        "rule_classes": {k: classes.get(k, 0) for k in ("A", "B", "C")},
        "reason_counts": dict(sorted(reasons.items())),
        "rules": rows,
        "notes": [
            "No source IP addresses, names, paths or VM identities are exported.",
            "Classification does not prove enforcement equivalence.",
            "No Check Point API writes are performed."
        ]
    }


def write_report(report, destination):
    target = Path(destination)
    target.mkdir(parents=True, exist_ok=True)
    summary = {k: v for k, v in report.items() if k != "rules"}
    (target / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (target / "rules.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["anonymous_id", "class", "reason_codes"])
        writer.writeheader()
        for row in report["rules"]:
            writer.writerow({**row, "reason_codes": ";".join(row["reason_codes"])})
    for name in ("summary.json", "rules.csv"):
        (target / name).chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description="Offline private NSX hierarchical export assessment")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--identity-map",
        help="PRIVATE JSON mapping from workload IDs to verified IPv4 address lists; never commit",
    )
    args = parser.parse_args()
    identity_map = None
    if args.identity_map:
        identity_map = json.loads(Path(args.identity_map).read_text(encoding="utf-8"))
        if not isinstance(identity_map, dict):
            parser.error("--identity-map must contain a JSON object")
    write_report(assess(load_export(args.input), identity_map=identity_map), args.output)
    print("Sanitized assessment written: summary.json, rules.csv")


if __name__ == "__main__":
    main()
