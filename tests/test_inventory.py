"""Synthetic NSX inventory fixtures: reserved documentation IP ranges only."""
import datetime as dt
import json
import pytest

from sync_engine.inventory import (
    InventoryError, _normalize_vif_map, inventory_from_api,
    load_private_inventory, save_private_inventory,
)


class FakeNSX:
    def __init__(self, failing=None):
        self.failing = failing

    def paginate(self, path):
        if self.failing and self.failing in path:
            raise RuntimeError("synthetic API failure")
        if path == "/api/v1/fabric/virtual-machines":
            return [{"external_id": "example-vm", "source": {"is_valid": True}}]
        if path == "/api/v1/fabric/vifs":
            return [{
                "owner_vm_id": "example-vm",
                "ip_address_info": [{
                    "source": "VM_TOOLS",
                    "ip_addresses": ["192.0.2.10", "2001:db8::1"],
                }],
            }]
        if path.endswith("/members/ip-addresses"):
            return ["192.0.2.10"]
        raise AssertionError("Unexpected API path " + path)


def test_inventory_read_only_and_group_members():
    groups = [{"_domain": "default", "id": "group-example",
               "path": "/infra/domains/default/groups/group-example"}]
    result = inventory_from_api(FakeNSX(), ["default"], groups)
    assert result["identity_map"] == {"example-vm": ["192.0.2.10"]}
    assert result["effective_group_members"][groups[0]["path"]] == ["192.0.2.10"]
    assert result["vm_count"] == 1


def test_fails_closed_on_membership_api_failure():
    groups = [{"_domain": "default", "id": "group-example",
               "path": "/infra/domains/default/groups/group-example"}]
    with pytest.raises(InventoryError, match="group_membership_query_failed"):
        inventory_from_api(FakeNSX(failing="members/ip-addresses"), ["default"], groups)


def test_duplicate_workload_ip_blocked():
    with pytest.raises(InventoryError, match="duplicate_ipv4_across_workloads"):
        _normalize_vif_map([
            {"owner_vm_id": "example-vm-1", "ip_address_info": [
                {"source": "VM_TOOLS", "ip_addresses": ["192.0.2.10"]}]},
            {"owner_vm_id": "example-vm-2", "ip_address_info": [
                {"source": "VM_TOOLS", "ip_addresses": ["192.0.2.10"]}]},
        ])


def test_untrusted_address_provenance_blocked():
    with pytest.raises(InventoryError, match="untrusted_ip_provenance"):
        _normalize_vif_map([{
            "owner_vm_id": "example-vm",
            "ip_address_info": [{"source": "UNKNOWN", "ip_addresses": ["192.0.2.10"]}],
        }])


def test_private_inventory_permissions_and_freshness(tmp_path):
    result = inventory_from_api(FakeNSX(), ["default"])
    target = save_private_inventory(result, tmp_path / "restricted")
    assert target.stat().st_mode & 0o777 == 0o600
    assert load_private_inventory(target)["identity_map"] == {"example-vm": ["192.0.2.10"]}
    with pytest.raises(InventoryError, match="inventory_exists"):
        save_private_inventory(result, tmp_path / "restricted")


def test_stale_inventory_blocked(tmp_path):
    result = inventory_from_api(FakeNSX(), ["default"])
    result["collected_utc"] = "2020-01-01T00:00:00+00:00"
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(result))
    with pytest.raises(InventoryError, match="stale_or_future_inventory"):
        load_private_inventory(path, now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))


def test_future_inventory_blocked(tmp_path):
    result = inventory_from_api(FakeNSX(), ["default"])
    result["collected_utc"] = "2035-01-01T00:00:00+00:00"
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(result))
    with pytest.raises(InventoryError, match="stale_or_future_inventory"):
        load_private_inventory(path)
