"""Synthetic object plans only. No real configuration or production addresses."""
import copy
import pytest
from sync_engine.object_plan import build_plan, canonical_object, PlanError

def inventory():
    return {k: [] for k in ("host", "network", "group", "service-tcp", "service-udp")}

def source():
    return {"candidate_hash": "synthetic-hash", "rejected": [], "objects": [
        {"kind": "host", "name": "NSXMIG_A_HOST", "ip": "192.0.2.10", "source_ref": "/example/host"},
        {"kind": "network", "name": "NSXMIG_A_NET", "network": "198.51.100.0",
         "prefix": 24, "source_ref": "/example/network"},
        {"kind": "service", "name": "NSXMIG_S_TLS", "protocol": "TCP",
         "port": "443", "source_ref": "/example/service"},
        {"kind": "group", "name": "NSXMIG_G_WEB", "members": ["NSXMIG_A_HOST"],
         "source_ref": "/example/group"},
    ]}

def test_all_new_are_create():
    plan = build_plan(source(), inventory())
    assert plan["counts"] == {"CREATE": 4, "REUSE": 0, "CONFLICT": 0}
    assert plan["ready_for_review"]
    assert plan["read_only"]

def test_idempotent_after_target_matches():
    cand = source()
    first = build_plan(cand, inventory())
    target = inventory()
    for step in first["steps"]:
        target[step["kind"]].append(copy.deepcopy(step["payload"]))
    second = build_plan(cand, target)
    assert second["counts"] == {"CREATE": 0, "REUSE": 4, "CONFLICT": 0}
    assert second["plan_hash"] == build_plan(cand, target)["plan_hash"]

def test_unmanaged_name_collision_blocks():
    target = inventory()
    target["host"].append({"name": "NSXMIG_A_HOST", "ip-address": "192.0.2.10"})
    result = build_plan(source(), target)
    assert result["counts"]["CONFLICT"] == 1

def test_owned_drift_blocks():
    cand = source()
    initial = build_plan(cand, inventory())
    target = inventory()
    host = next(s for s in initial["steps"] if s["kind"] == "host")
    bad = dict(host["payload"], **{"ip-address": "192.0.2.11"})
    target["host"].append(bad)
    result = build_plan(cand, target)
    assert result["counts"]["CONFLICT"] == 1

def test_kind_collision_blocks():
    target = inventory()
    target["network"].append({"name": "NSXMIG_A_HOST", "subnet": "192.0.2.0",
                              "mask-length": 24})
    assert build_plan(source(), target)["counts"]["CONFLICT"] == 1

def test_incomplete_target_inventory_blocks():
    target = inventory()
    del target["group"]
    with pytest.raises(PlanError, match="incomplete_target_inventory"):
        build_plan(source(), target)

def test_rejected_candidate_blocks():
    cand = source()
    cand["rejected"] = [{"reason": "needs_review"}]
    with pytest.raises(PlanError, match="candidate_incomplete"):
        build_plan(cand, inventory())

def test_invalid_network_and_name_block():
    with pytest.raises(ValueError):
        canonical_object({"kind": "network", "name": "NSXMIG_A_NET",
                          "network": "192.0.2.1", "prefix": 24, "source_ref": "/example"})
    with pytest.raises(PlanError, match="invalid_object_name"):
        canonical_object({"kind": "host", "name": "unmanaged", "ip": "192.0.2.1",
                          "source_ref": "/example"})

def test_invalid_service_port_blocks():
    with pytest.raises(PlanError, match="invalid_port"):
        canonical_object({"kind": "service", "name": "NSXMIG_S_BAD",
                          "protocol": "TCP", "port": "70000", "source_ref": "/example"})
