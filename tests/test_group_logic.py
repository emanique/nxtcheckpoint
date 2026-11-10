"""Public tests use only RFC 5737 documentation networks and synthetic identifiers."""
import pytest

from sync_engine.group_logic import UnsafeExpression, resolve_group_expression


def group(path, expression):
    return {"path": path, "expression": expression}


def ips(*items):
    return {"resource_type": "IPAddressExpression", "ip_addresses": list(items)}


def ids(*items):
    return {
        "resource_type": "ExternalIDExpression",
        "member_type": "VirtualMachine",
        "external_ids": list(items)
    }


def op(name):
    return {"resource_type": "ConjunctionOperator", "conjunction_operator": name}


def paths(*refs):
    return {"resource_type": "PathExpression", "paths": list(refs)}


def test_static_ipv4():
    r = resolve_group_expression(group("/example/a", [ips("192.0.2.0/24")]))
    assert r.networks == ("192.0.2.0/24",)


def test_vm_identity_requires_verification():
    with pytest.raises(UnsafeExpression, match="unresolved_workload_identity"):
        resolve_group_expression(group("/example/a", [ids("vm-example")]))


def test_vm_identity_and_ip_intersection():
    r = resolve_group_expression(
        group("/example/a", [ids("vm-example"), op("AND"), ips("192.0.2.0/24")]),
        identity_map={"vm-example": ["192.0.2.7", "198.51.100.9"]},
    )
    assert r.networks == ("192.0.2.7/32",)
    assert r.identity_dependencies == ("vm-example",)


def test_and_cannot_be_widened_to_union():
    with pytest.raises(UnsafeExpression, match="empty_resolved_intersection"):
        resolve_group_expression(group("/example/a", [
            ids("vm-example"), op("AND"), ips("192.0.2.0/24")
        ]), identity_map={"vm-example": ["203.0.113.10"]})


def test_static_or():
    r = resolve_group_expression(group("/example/a", [
        ips("192.0.2.0/25"), op("OR"), ips("192.0.2.128/25")
    ]))
    assert r.networks == ("192.0.2.0/24",)


def test_nested_group_path():
    a = group("/example/a", [ips("192.0.2.0/24")])
    b = group("/example/b", [paths("/example/a"), op("AND"), ips("192.0.2.64/26")])
    assert resolve_group_expression(b, {a["path"]: a, b["path"]: b}).networks == ("192.0.2.64/26",)


def test_cycle_blocked():
    a = group("/example/a", [paths("/example/b")])
    b = group("/example/b", [paths("/example/a")])
    with pytest.raises(UnsafeExpression, match="recursive_group_cycle"):
        resolve_group_expression(a, {a["path"]: a, b["path"]: b})


def test_mixed_boolean_precedence_blocked():
    with pytest.raises(UnsafeExpression, match="mixed_boolean_precedence_unverified"):
        resolve_group_expression(group("/example/a", [
            ips("192.0.2.1"), op("AND"), ips("192.0.2.0/24"),
            op("OR"), ips("203.0.113.1")
        ]))


def test_tag_condition_blocked():
    with pytest.raises(UnsafeExpression, match="unsupported_group_expression_type"):
        resolve_group_expression(group("/example/a", [
            {"resource_type": "Condition", "key": "Tag", "value": "example"}
        ]))


def test_ipv6_blocked():
    with pytest.raises(UnsafeExpression, match="non_ipv4_address"):
        resolve_group_expression(group("/example/a", [ips("2001:db8::/64")]))


def test_ip_range_blocked():
    with pytest.raises(UnsafeExpression, match="ip_range_requires_expansion"):
        resolve_group_expression(group("/example/a", [ips("192.0.2.1-192.0.2.3")]))


def test_missing_path_reference_blocked():
    with pytest.raises(UnsafeExpression, match="unresolved_group_path"):
        resolve_group_expression(group("/example/a", [paths("/example/missing")]))
