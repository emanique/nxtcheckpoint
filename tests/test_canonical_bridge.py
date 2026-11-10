"""Synthetic test of the private canonical bridge; no live endpoint or customer data."""
import json
import pytest

from sync_engine.canonical_bridge import (
    CanonicalError, compile_private_candidate, save_private_candidate,
)
from sync_engine.model import digest
from sync_engine.dependency_hash import semantic_rule_hash
from sync_engine.precedence import analyze_precedence
from sync_engine.offline import unwrap, assess
from sync_engine.object_plan import build_plan
from test_offline import synthetic_export


def private_inventory():
    return {
        "identity_map": {"fake-vm-001": ["198.51.100.8"]},
        "effective_group_members": {
            "/synthetic/groups/g1": ["198.51.100.0/24"],
            "/synthetic/groups/g2": ["198.51.100.8"],
        },
    }


def approvals(root):
    rule = unwrap(root)["Rule"][0]
    assessment = assess(root, inventory=private_inventory(),
                        identity_map=private_inventory()["identity_map"])
    key = assessment["rules"][0]["anonymous_id"]
    return {key: {"rule_hash": semantic_rule_hash(rule, {g["path"]: g for g in unwrap(root)["Group"]}, {s["path"]: s for s in unwrap(root)["Service"]}, private_inventory()["identity_map"]), "approver": "synthetic-approver",
                  "source_order_hash": analyze_precedence(root)["source_order_hash"],
                  "topology_evidence": "synthetic-routing-review",
                  "precedence_evidence": "synthetic-order-review"}}


def target_snapshot():
    return {k: [] for k in ("host", "network", "group", "service-tcp", "service-udp")}


def test_missing_inventory_blocks():
    with pytest.raises(CanonicalError, match="verified_inventory_required"):
        compile_private_candidate(synthetic_export(), None)


def test_absent_approval_rejects_without_objects():
    result = compile_private_candidate(synthetic_export(), private_inventory())
    assert len(result["rules"]) == 0
    assert len(result["objects"]) == 0
    assert result["rejected"][0]["reasons"] == ["approval_or_topology_evidence_missing"]


def test_full_bridge_to_dry_run_without_writes():
    root = synthetic_export()
    cand = compile_private_candidate(root, private_inventory(), approvals(root))
    assert cand["read_only"]
    assert not cand["enforcement_authorized"]
    assert cand["reconciliation"]["match"] == 2
    assert cand["rejected"] == []
    assert len(cand["rules"]) == 1
    assert cand["rules"][0]["enabled"] is False
    plan = build_plan(cand, target_snapshot())
    assert plan["ready_for_review"] and plan["read_only"]
    assert plan["counts"]["CREATE"] == len(cand["objects"])
    assert all(step["action"] == "CREATE" for step in plan["steps"])


def test_membership_mismatch_blocks_rule():
    inventory = private_inventory()
    inventory["effective_group_members"]["/synthetic/groups/g1"] = ["198.51.100.0/25"]
    root = synthetic_export()
    cand = compile_private_candidate(root, inventory, approvals(root))
    assert cand["rejected"]
    assert cand["rules"] == []


def test_rule_change_invalidates_approval():
    root = synthetic_export()
    authorized = approvals(root)
    unwrap(root)["Rule"][0]["action"] = "DROP"
    result = compile_private_candidate(root, private_inventory(), authorized)
    assert result["rules"] == []
    assert len(result["rejected"]) == 1


def test_missing_precedence_approval_blocks():
    root = synthetic_export()
    auth = approvals(root)
    next(iter(auth.values())).pop("precedence_evidence")
    cand = compile_private_candidate(root, private_inventory(), auth)
    assert cand["rules"] == []


def test_private_candidate_output_and_privacy(tmp_path):
    root = synthetic_export()
    result = compile_private_candidate(root, private_inventory(), approvals(root))
    target = save_private_candidate(result, tmp_path / "private")
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(CanonicalError, match="output_exists"):
        save_private_candidate(result, tmp_path / "private")
    assert json.loads(target.read_text())["candidate_hash"] == result["candidate_hash"]


def test_unsupported_scope_does_not_produce_candidate():
    root = synthetic_export()
    pol = unwrap(root)["SecurityPolicy"][0]
    pol["scope"] = ["/synthetic/groups/g1"]
    cand = compile_private_candidate(root, private_inventory(), approvals(root))
    assert cand["rules"] == []
    assert cand["rejected"]

def test_approval_template_never_grants_approval():
    from sync_engine.approval_template import make_template
    root = synthetic_export()
    mapping = make_template(root, private_inventory())
    assert len(mapping) == 1
    row = next(iter(mapping.values()))
    assert row["rule_hash"] == semantic_rule_hash(unwrap(root)["Rule"][0], {g["path"]: g for g in unwrap(root)["Group"]}, {s["path"]: s for s in unwrap(root)["Service"]}, private_inventory()["identity_map"])
    assert row["source_order_hash"] == analyze_precedence(root)["source_order_hash"]
    assert row["approver"] == ""
    assert row["topology_evidence"] == ""
    assert row["precedence_evidence"] == ""
    assert compile_private_candidate(root, private_inventory(), mapping)["rules"] == []

def test_group_membership_change_invalidates_old_approval():
    root = synthetic_export()
    auth = approvals(root)
    inventory = private_inventory()
    # Change membership consistently in the group definition, identity map and
    # realization: membership remains MATCH, but previously approved hash is stale.
    g2 = next(g for g in unwrap(root)["Group"] if g["path"].endswith("/g2"))
    g2["expression"][2]["ip_addresses"] = ["198.51.100.9"]
    inventory["identity_map"]["fake-vm-001"] = ["198.51.100.9"]
    inventory["effective_group_members"]["/synthetic/groups/g2"] = ["198.51.100.9"]
    cand = compile_private_candidate(root, inventory, auth)
    assert cand["rules"] == []
    assert cand["rejected"][0]["reasons"] == ["approval_or_topology_evidence_missing"]


def test_service_definition_change_invalidates_old_approval():
    root = synthetic_export()
    auth = approvals(root)
    unwrap(root)["Service"][0]["service_entries"][0]["destination_ports"] = ["8443"]
    cand = compile_private_candidate(root, private_inventory(), auth)
    assert cand["rules"] == []
    assert cand["rejected"][0]["reasons"] == ["approval_or_topology_evidence_missing"]

def test_resequencing_invalidates_prior_rule_approval():
    root = synthetic_export()
    original = approvals(root)
    policy = unwrap(root)["SecurityPolicy"][0]
    policy["sequence_number"] = 20
    cand = compile_private_candidate(root, private_inventory(), original)
    assert cand["rules"] == []
    assert cand["rejected"][0]["reasons"] == ["approval_or_topology_evidence_missing"]

def test_candidate_reports_order_not_verified():
    root = synthetic_export()
    cand = compile_private_candidate(root, private_inventory(), approvals(root))
    assert cand["precedence"]["effective_enforcement_verified"] is False
    assert cand["precedence"]["target_install_order_authorized"] is False
    assert cand["rules"][0]["precedence_status"] == "UNVERIFIED"
