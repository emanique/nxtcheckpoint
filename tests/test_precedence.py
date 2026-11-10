"""Synthetic-only precedence tests, no real source names or addresses."""
import copy
from sync_engine.precedence import analyze_precedence

def mk_rule(identifier, seq):
    return {"resource_type": "Rule", "path": f"/infra/domains/default/security-policies/example/rules/{identifier}",
            "id": identifier, "sequence_number": seq, "action": "ALLOW"}

def policy(identifier, category, seq, rule_seqs):
    return {
        "resource_type": "SecurityPolicy",
        "path": f"/infra/domains/default/security-policies/{identifier}",
        "category": category,
        "sequence_number": seq,
        "children": [
            {"resource_type": "ChildRule", "Rule": mk_rule(f"{identifier}-{i}", value)}
            for i, value in enumerate(rule_seqs)
        ],
    }

def infra(*policies):
    return {"resource_type": "Infra", "children": [
        {"resource_type": "ChildSecurityPolicy", "SecurityPolicy": p}
        for p in policies
    ]}

def test_category_precedence_over_policy_sequence():
    report = analyze_precedence(infra(
        policy("app", "Application", 1, [20]),
        policy("infra", "Infrastructure", 300, [5]),
        policy("emergency", "Emergency", 1000, [2])))
    assert report["total"] == 3
    assert report["order_fields_valid"] == 3
    # Source order was Application first; category order is different.
    assert report["rows"][0]["anonymous_id"] != report["rows"][-1]["anonymous_id"]
    assert not report["effective_enforcement_verified"]

def test_policy_collision_is_not_silently_reordered():
    report = analyze_precedence(infra(
        policy("p1", "Application", 10, [1]),
        policy("p2", "Application", 10, [2])))
    assert report["unverified"] == 2
    assert report["reason_codes"]["policy_sequence_collision"] == 2

def test_rule_collision_detected():
    report = analyze_precedence(infra(policy("p1", "Application", 10, [1, 1])))
    assert report["reason_codes"]["rule_sequence_collision"] == 2

def test_missing_sequences_and_unsupported_category():
    report = analyze_precedence(infra(policy("p1", "Ethernet", None, [None])))
    codes = report["rows"][0]["reasons"]
    assert "unsupported_dfw_category" in codes
    assert "policy_sequence_missing" in codes
    assert "rule_sequence_missing" in codes

def test_resequence_invalidates_fingerprint_even_single_rule():
    root = infra(policy("p1", "Application", 10, [20]))
    initial = analyze_precedence(root)["source_order_hash"]
    root2 = copy.deepcopy(root)
    root2["children"][0]["SecurityPolicy"]["sequence_number"] = 30
    assert analyze_precedence(root2)["source_order_hash"] != initial

def test_reordering_rule_positions_invalidates_fingerprint():
    root = infra(policy("p1", "Application", 10, [10, 20]))
    modified = copy.deepcopy(root)
    children = modified["children"][0]["SecurityPolicy"]["children"]
    children[0], children[1] = children[1], children[0]
    assert analyze_precedence(modified)["source_order_hash"] != analyze_precedence(root)["source_order_hash"]

def test_no_source_names_or_paths_in_summary():
    report = analyze_precedence(infra(policy("app", "Application", 12, [1])))
    serialized = str(report)
    assert "/infra/" not in serialized
    assert "security-policies" not in serialized
