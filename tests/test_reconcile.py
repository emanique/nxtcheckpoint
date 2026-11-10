"""Synthetic-only tests for exact membership reconciliation and privacy."""
from sync_engine.reconcile import (
    _network_set, _subtract, compare_membership,
    reconcile_catalog, summarize_reconciliation,
)
from sync_engine.offline import assess, write_report
from tests.test_offline import synthetic_export

def group(path="/example/group", expr=None):
    return {
        "path": path,
        "expression": expr or [
            {"resource_type": "IPAddressExpression",
             "ip_addresses": ["192.0.2.0/25", "192.0.2.128/25"]}
        ],
    }

def test_cidr_merge_matches_flat_realized_ips():
    g = group()
    result = compare_membership(g, {g["path"]: g}, {}, ["192.0.2.0/24"])
    assert result["status"] == "MATCH"

def test_realized_range_matches_cidr():
    g = group()
    result = compare_membership(g, {g["path"]: g}, {}, ["192.0.2.0-192.0.2.255"])
    assert result["status"] == "MATCH"

def test_missing_address_detected_without_exposing_addresses():
    g = group()
    result = compare_membership(g, {g["path"]: g}, {}, ["192.0.2.0/25"])
    assert result["status"] == "MISMATCH"
    assert result["missing_blocks"] == 1
    assert "192.0.2" not in str(result)

def test_extra_address_detected():
    g = group()
    result = compare_membership(g, {g["path"]: g}, {},
                                ["192.0.2.0/24", "198.51.100.1"])
    assert result["status"] == "MISMATCH"
    assert result["extra_blocks"] == 1

def test_missing_realization_is_blocked():
    g = group()
    assert compare_membership(g, {g["path"]: g}, {}, None)["status"] == "BLOCKED"

def test_ipv6_realization_is_blocked():
    g = group()
    result = compare_membership(g, {g["path"]: g}, {}, ["2001:db8::1"])
    assert result["reason"] == "non_ipv4_membership"

def test_exact_subtraction():
    a = _network_set(["192.0.2.0/24"])
    b = _network_set(["192.0.2.0/25"])
    assert tuple(str(x) for x in _subtract(a,b)) == ("192.0.2.128/25",)

def test_empty_realized_does_not_match_nonempty():
    g=group()
    assert compare_membership(g,{g["path"]:g},{},[])["status"] == "MISMATCH"

def test_reconciliation_summary_is_anonymous():
    g=group()
    report = summarize_reconciliation(reconcile_catalog(
        [g], {"identity_map": {}, "effective_group_members": {g["path"]:["192.0.2.0/24"]}}
    ))
    assert report["match"] == 1
    assert report["go_for_conversion"]
    assert "192.0.2" not in str(report)
    assert "/example" not in str(report)

def test_offline_rule_blocked_on_membership_mismatch(tmp_path):
    src=synthetic_export()
    # Both groups are present, but actual membership of static group is incomplete.
    report = assess(src, inventory={
        "identity_map":{"fake-vm-001":["198.51.100.8"]},
        "effective_group_members":{
            "/synthetic/groups/g1":["198.51.100.0/25"],
            "/synthetic/groups/g2":["198.51.100.8"]
        }
    })
    assert report["reconciliation"]["mismatch"] == 1
    assert any("group_membership_not_verified" in row["reason_codes"] for row in report["rules"])
    write_report(report,tmp_path)
    output=(tmp_path/"summary.json").read_text()+(tmp_path/"rules.csv").read_text()
    for secret in ("fake-vm-001", "198.51.100", "/synthetic/"):
        assert secret not in output
