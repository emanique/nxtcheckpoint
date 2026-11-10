"""Build a PRIVATE per-rule approval worksheet with no auto-approval."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from .inventory import load_private_inventory
from .model import digest
from .dependency_hash import semantic_rule_hash
from .offline import load_export, unwrap, assess


def make_template(root, inventory):
    report = assess(root, inventory=inventory, identity_map=inventory["identity_map"])
    objects = unwrap(root)
    groups = {o["path"]: o for o in objects["Group"] if o.get("path")}
    services = {o["path"]: o for o in objects["Service"] if o.get("path")}
    rule_map = {}
    for rule in objects["Rule"]:
        path = rule.get("path")
        if path:
            key = hashlib.sha256(str(path).encode()).hexdigest()[:16]
            if key in rule_map:
                raise ValueError("ambiguous_rule_identity")
            rule_map[key] = rule
    result = {}
    for item in report["rules"]:
        if item["class"] != "B":
            continue
        key = item["anonymous_id"]
        if key not in rule_map:
            raise ValueError("missing_rule_identity")
        result[key] = {
            "rule_hash": semantic_rule_hash(rule_map[key], groups, services, inventory["identity_map"]),
            "approver": "",
            "topology_evidence": "",
            "precedence_evidence": "",
        }
    return result


def main():
    ap = argparse.ArgumentParser(description="Private approval template, NOT authorization")
    ap.add_argument("--input", required=True)
    ap.add_argument("--inventory-file", required=True)
    ap.add_argument("--max-inventory-age-seconds", type=int, default=600)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    if args.max_inventory_age_seconds <= 0:
        ap.error("Invalid maximum inventory age")
    inventory = load_private_inventory(
        args.inventory_file, max_age_seconds=args.max_inventory_age_seconds)
    template = make_template(load_export(args.input), inventory)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(template, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps({"templates": len(template), "approved": 0, "read_only": True}))


if __name__ == "__main__":
    main()
