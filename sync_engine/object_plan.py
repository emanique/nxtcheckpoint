"""Read-only, deterministic Check Point object reconciliation.

All inputs and detailed outputs are PRIVATE. No write, publish or install calls.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
from .model import digest
from .checkpoint import CheckPointClient

KINDS = ("host", "network", "group", "service-tcp", "service-udp")

class PlanError(ValueError):
    pass

def _name(value):
    if not isinstance(value, str) or not value.startswith("NSXMIG_") or len(value) > 80:
        raise PlanError("invalid_object_name")
    if not all(c.isascii() and (c.isalnum() or c in "._-") for c in value):
        raise PlanError("invalid_object_name")
    return value

def canonical_object(source):
    name = _name(source.get("name"))
    source_ref = source.get("source_ref")
    if not isinstance(source_ref, str) or not source_ref:
        raise PlanError("missing_source_reference")
    tag = "NXTCP:" + hashlib.sha256(source_ref.encode()).hexdigest()[:24]
    kind = source.get("kind")
    if kind == "host":
        ip = ipaddress.ip_address(source["ip"])
        if ip.version != 4:
            raise PlanError("non_ipv4")
        return kind, {"name": name, "ip-address": str(ip), "comments": tag}
    if kind == "network":
        net = ipaddress.ip_network(f'{source["network"]}/{source["prefix"]}', strict=True)
        if net.version != 4:
            raise PlanError("non_ipv4")
        return kind, {"name": name, "subnet": str(net.network_address),
                      "mask-length": net.prefixlen, "comments": tag}
    if kind == "group":
        members = source.get("members")
        if not isinstance(members, list) or not members or len(set(members)) != len(members):
            raise PlanError("invalid_members")
        return kind, {"name": name, "members": sorted(_name(m) for m in members),
                      "comments": tag}
    if kind == "service":
        protocol = source.get("protocol")
        if protocol not in ("TCP", "UDP"):
            raise PlanError("unsupported_service")
        port = str(source.get("port", ""))
        fields = port.split("-")
        if not 1 <= len(fields) <= 2 or not all(x.isdecimal() for x in fields):
            raise PlanError("invalid_port")
        nums = [int(x) for x in fields]
        if any(x < 1 or x > 65535 for x in nums) or nums != sorted(nums):
            raise PlanError("invalid_port")
        return "service-" + protocol.lower(), {
            "name": name, "port": port, "comments": tag}
    raise PlanError("unsupported_kind")

def _meaning(kind, obj):
    if kind == "host":
        return ("host", str(ipaddress.ip_address(obj["ip-address"])))
    if kind == "network":
        addr = obj.get("subnet", obj.get("subnet4"))
        prefix = obj.get("mask-length", obj.get("mask-length4"))
        if addr is None or prefix is None:
            raise PlanError("unknown_target_network")
        net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        return ("network", str(net))
    if kind == "group":
        members = obj["members"]
        if not isinstance(members, list):
            raise PlanError("unknown_target_members")
        resolved = [m.get("name") if isinstance(m, dict) else m for m in members]
        if not all(isinstance(x, str) for x in resolved):
            raise PlanError("unknown_target_members")
        return ("group", tuple(sorted(resolved)))
    if kind in ("service-tcp", "service-udp"):
        return (kind, str(obj["port"]))
    raise PlanError("unknown_kind")

def build_plan(candidate, inventory):
    if not isinstance(candidate, dict) or not isinstance(inventory, dict):
        raise PlanError("invalid_input")
    if not candidate.get("candidate_hash") or candidate.get("rejected"):
        raise PlanError("candidate_incomplete")
    if set(inventory) != set(KINDS):
        raise PlanError("incomplete_target_inventory")
    desired = {}
    for source in candidate.get("objects", []):
        kind, payload = canonical_object(source)
        if payload["name"] in desired:
            raise PlanError("duplicate_desired_name")
        desired[payload["name"]] = (kind, payload)
    existing = {}
    for kind, records in inventory.items():
        if not isinstance(records, list):
            raise PlanError("invalid_inventory")
        for record in records:
            name = record.get("name")
            if not isinstance(name, str) or name in existing:
                raise PlanError("target_name_collision")
            existing[name] = (kind, record)
    steps = []
    for name, (kind, payload) in sorted(desired.items(), key=lambda x:
            (x[1][0] == "group", x[0])):
        old = existing.get(name)
        if old is None:
            action, reason = "CREATE", "not_found"
        elif old[0] != kind:
            action, reason = "CONFLICT", "type_collision"
        elif old[1].get("comments") != payload["comments"]:
            action, reason = "CONFLICT", "ownership_unverified"
        else:
            try:
                equal = _meaning(kind, old[1]) == _meaning(kind, payload)
                action, reason = (("REUSE", "owned_equal") if equal
                                  else ("CONFLICT", "object_drift"))
            except (ValueError, KeyError, TypeError):
                action, reason = "CONFLICT", "target_semantics_unknown"
        steps.append({"action": action, "reason": reason, "kind": kind,
                      "name": name, "payload": payload})
    counts = {a: sum(s["action"] == a for s in steps)
              for a in ("CREATE", "REUSE", "CONFLICT")}
    return {"schema": "nxtcheckpoint.object-dry-run.v1",
            "read_only": True, "candidate_hash": candidate["candidate_hash"],
            "counts": counts, "ready_for_review": counts["CONFLICT"] == 0,
            "steps": steps, "plan_hash": digest(steps)}

def main():
    ap = argparse.ArgumentParser(description="Check Point dry-run: NO writes")
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--target-snapshot")
    ap.add_argument("--config")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    if bool(args.target_snapshot) == bool(args.config):
        ap.error("Exactly one of --target-snapshot or --config required")
    candidate = json.loads(Path(args.candidate).read_text())
    if candidate.get("candidate_hash") != digest({
        "objects": candidate.get("objects"), "rules": candidate.get("rules")}):
        raise PlanError("candidate_hash_mismatch")
    if args.target_snapshot:
        inventory = json.loads(Path(args.target_snapshot).read_text())
    else:
        import yaml
        cfg = yaml.safe_load(Path(args.config).read_text())
        cp = CheckPointClient(cfg["checkpoint"], os.environ[cfg["checkpoint"]["api_key_env"]])
        try:
            cp.login(read_only=True)
            inventory = cp.object_inventory()
        finally:
            cp.logout()
    report = build_plan(candidate, inventory)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = output_dir / "object_plan.private.json"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(report, fh, sort_keys=True, indent=2)
        fh.write("\n")
    print(json.dumps({"counts": report["counts"], "read_only": True,
                      "ready_for_review": report["ready_for_review"],
                      "plan_hash": report["plan_hash"]}))

if __name__ == "__main__":
    main()
