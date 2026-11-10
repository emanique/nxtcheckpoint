"""Synthetic-only fixtures; no production IP addresses or system names."""
import json

from sync_engine.offline import (
    assess, group_compat, load_export, service_compat, unwrap, write_report,
)


def synthetic_export():
    g1 = {"resource_type": "Group", "path": "/synthetic/groups/g1",
          "expression": [{"resource_type": "IPAddressExpression",
                          "ip_addresses": ["198.51.100.0/24"]}]}
    g2 = {"resource_type": "Group", "path": "/synthetic/groups/g2",
          "expression": [
              {"resource_type": "ExternalIDExpression", "member_type": "VirtualMachine", "external_ids": ["fake-vm-001"]},
              {"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"},
              {"resource_type": "IPAddressExpression", "ip_addresses": ["198.51.100.8"]},
          ]}
    svc = {"resource_type": "Service", "path": "/synthetic/services/tls",
           "service_entries": [
               {"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP",
                "source_ports": [], "destination_ports": ["443"]}
           ]}
    rule = {"resource_type": "Rule", "path": "/synthetic/policies/p1/rules/r1",
            "action": "ALLOW", "direction": "IN_OUT", "scope": ["ANY"],
            "ip_protocol": "IPV4", "source_groups": [g1["path"]],
            "destination_groups": [g2["path"]], "services": [svc["path"]]}
    pol = {"resource_type": "SecurityPolicy", "category": "Application",
           "scope": ["ANY"], "children": [{"resource_type": "ChildRule", "Rule": rule}]}
    return {"resource_type": "Infra", "children": [
        {"resource_type": "ChildDomain", "Domain": {
            "resource_type": "Domain", "children": [
                {"resource_type": "ChildSecurityPolicy", "SecurityPolicy": pol},
                {"resource_type": "ChildGroup", "Group": g1},
                {"resource_type": "ChildGroup", "Group": g2},
            ]}},
        {"resource_type": "ChildService", "Service": svc},
    ]}


def test_hierarchical_wrappers():
    o = unwrap(synthetic_export())
    assert {k: len(v) for k, v in o.items()} == {
        "SecurityPolicy": 1, "Rule": 1, "Group": 2, "Service": 1}


def test_compound_group_blocked():
    groups = unwrap(synthetic_export())["Group"]
    assert group_compat(groups[0])[0] == "A"
    assert group_compat(groups[1])[0] == "C"


def test_l4_service_supported():
    assert service_compat(unwrap(synthetic_export())["Service"][0])[0] == "A"


def test_no_raw_names_or_ips_in_reports(tmp_path):
    root = synthetic_export()
    source = tmp_path / "input.json"
    source.write_text(json.dumps(root))
    report = assess(load_export(source))
    assert report["counts"]["rules"] == 1
    assert report["rule_classes"]["C"] == 1
    write_report(report, tmp_path / "out")
    result = (tmp_path / "out" / "summary.json").read_text() + (tmp_path / "out" / "rules.csv").read_text()
    for marker in ("198.51.100", "fake-vm-001", "/synthetic/", "p1/rules/r1"):
        assert marker not in result


def test_utf16_bom(tmp_path):
    source = tmp_path / "input.json"
    source.write_bytes(json.dumps(synthetic_export()).encode("utf-16"))
    assert len(unwrap(load_export(source))["Rule"]) == 1


def test_invalid_l4_and_ipv6_group():
    assert service_compat({"service_entries": [
        {"resource_type": "ICMPTypeServiceEntry"}]})[0] == "C"
    assert group_compat({"expression": [
        {"resource_type": "IPAddressExpression", "ip_addresses": ["2001:db8::/64"]}]})[0] == "C"

def test_identity_map_changes_group_resolution_without_exposing_identity(tmp_path):
    source = synthetic_export()
    resolved = assess(source, identity_map={"fake-vm-001": ["198.51.100.8"]})
    assert resolved["groups"].get("resolved_identity_or_path", 0) == 1
    write_report(resolved, tmp_path / "report")
    output = (tmp_path / "report" / "summary.json").read_text() + (tmp_path / "report" / "rules.csv").read_text()
    assert "fake-vm-001" not in output
    assert "198.51.100.8" not in output


def test_unverified_identity_stays_blocked():
    result = assess(synthetic_export())
    assert result["groups"].get("unresolved_workload_identity", 0) == 1
    assert result["rule_classes"]["C"] == 1
