"""Read-only NSX realized membership and workload inventory collector.

Private raw data (VM IDs, IPs, group paths) must NEVER be committed to Git.
This module exports no payload to public assessment reports.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import quote

from .nsx import NSXClient


class InventoryError(ValueError):
    """Unsafe or unverifiable inventory data."""


def _ipv4_list(addresses):
    clean = set()
    for raw in addresses:
        try:
            value = ipaddress.ip_address(str(raw))
        except (ValueError, TypeError):
            raise InventoryError("invalid_ip_address") from None
        if value.version == 4:
            clean.add(str(value))
    return sorted(clean, key=lambda s: int(ipaddress.ip_address(s)))


def _normalize_vif_map(vifs, allowed_sources=("VM_TOOLS",)):
    by_vm = {}
    seen_addresses = {}
    for vif in vifs:
        vm_id = vif.get("owner_vm_id")
        if not isinstance(vm_id, str) or not vm_id:
            raise InventoryError("vif_missing_owner_vm_id")
        infos = vif.get("ip_address_info")
        if not isinstance(infos, list) or not infos:
            raise InventoryError("vif_missing_ip_information")
        ips = []
        for info in infos:
            if info.get("source") not in allowed_sources:
                raise InventoryError("untrusted_ip_provenance")
            values = info.get("ip_addresses")
            if not isinstance(values, list):
                raise InventoryError("invalid_vif_addresses")
            ips.extend(_ipv4_list(values))
        if not ips:
            raise InventoryError("vif_no_ipv4")
        for addr in ips:
            if addr in seen_addresses and seen_addresses[addr] != vm_id:
                raise InventoryError("duplicate_ipv4_across_workloads")
            seen_addresses[addr] = vm_id
        by_vm.setdefault(vm_id, set()).update(ips)
    return {vm_id: _ipv4_list(ips) for vm_id, ips in by_vm.items()}


def inventory_from_api(nsx, domains, groups=None, *, require_group_members=True):
    """Collect VMs/VIFs and optional realized group-IP members.

    Full collection required; no fallback on HTTP errors or pagination failures.
    """
    vms = nsx.paginate("/api/v1/fabric/virtual-machines")
    vifs = nsx.paginate("/api/v1/fabric/vifs")
    if not vms:
        raise InventoryError("empty_vm_inventory")
    vm_ids = set()
    for vm in vms:
        vm_id = vm.get("external_id")
        if not isinstance(vm_id, str) or not vm_id or vm_id in vm_ids:
            raise InventoryError("invalid_or_duplicate_vm_id")
        vm_ids.add(vm_id)
        if vm.get("source", {}).get("is_valid") is False:
            raise InventoryError("invalid_vm_source")
    by_vm = _normalize_vif_map(vifs)
    if not by_vm:
        raise InventoryError("empty_vif_inventory")
    if set(by_vm) - vm_ids:
        raise InventoryError("orphan_vif_vm_reference")

    effective = {}
    if groups is not None:
        for domain in domains:
            for group in groups:
                if group.get("_domain") != domain:
                    continue
                name = group.get("id")
                path = group.get("path")
                if not name or not path:
                    raise InventoryError("missing_group_identity")
                endpoint = (
                    "/policy/api/v1/infra/domains/"
                    + quote(domain, safe="")
                    + "/groups/" + quote(name, safe="")
                    + "/members/ip-addresses"
                )
                try:
                    values = nsx.paginate(endpoint)
                except Exception as exc:
                    if require_group_members:
                        raise InventoryError("group_membership_query_failed") from exc
                    continue
                if not all(isinstance(item, str) for item in values):
                    raise InventoryError("invalid_group_member_response")
                # Group membership may legitimately contain CIDRs/ranges; preserve
                # private raw shape and do NOT silently treat it as per-VM identity.
                effective[path] = values
    return {
        "schema": "nxtcheckpoint.private-inventory.v1",
        "collected_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "vm_count": len(vms),
        "vif_count": len(vifs),
        "identity_map": by_vm,
        "effective_group_members": effective,
        "source": "NSX read-only fabric and policy APIs",
    }


def save_private_inventory(result, output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink():
        raise InventoryError("symlink_output_directory_not_allowed")
    target = output / "inventory.private.json"
    if target.exists() or target.is_symlink():
        raise InventoryError("inventory_exists_use_new_directory")
    blob = json.dumps(result, sort_keys=True, separators=(",", ":"))
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(blob + "\n")
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def load_private_inventory(path, max_age_seconds=600, now=None):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != "nxtcheckpoint.private-inventory.v1":
        raise InventoryError("invalid_inventory_schema")
    if data.get("source") != "NSX read-only fabric and policy APIs":
        raise InventoryError("untrusted_inventory_source")
    timestamp = dt.datetime.fromisoformat(data["collected_utc"])
    if timestamp.tzinfo is None:
        raise InventoryError("naive_inventory_timestamp")
    current = now or dt.datetime.now(dt.timezone.utc)
    age = (current - timestamp).total_seconds()
    if age < -30 or age > max_age_seconds:
        raise InventoryError("stale_or_future_inventory")
    if not isinstance(data.get("identity_map"), dict) or not data["identity_map"]:
        raise InventoryError("empty_identity_map")
    return data


def main():
    ap = argparse.ArgumentParser(description="Collect private NSX identity inventory (read-only)")
    ap.add_argument("--config", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    import yaml
    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    client = NSXClient(
        cfg["nsx"],
        os.environ[cfg["nsx"]["username_env"]],
        os.environ[cfg["nsx"]["password_env"]],
    )
    snapshot = client.snapshot(cfg["nsx"]["domains"])
    inventory = inventory_from_api(client, cfg["nsx"]["domains"], snapshot["groups"])
    target = save_private_inventory(inventory, args.output)
    print("Private inventory saved with restricted permissions to:", str(target))
    print("Counts only: VMs =", inventory["vm_count"], "VIFs =", inventory["vif_count"])


if __name__ == "__main__":
    main()
