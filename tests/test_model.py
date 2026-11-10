import pytest
from sync_engine.model import ip_to_object, resolve_expression, resolve_service, compile_snapshot
from sync_engine.cli import change_report, safety_check
from sync_engine.candidate import candidate

def fixture():
    group = {'path': '/g1', 'expression': [{'resource_type': 'IPAddressExpression', 'ip_addresses': ['10.1.2.0/24']}]}
    service = {'path': '/s1', 'service_entries': [{'resource_type': 'L4PortSetServiceEntry', 'l4_protocol': 'TCP', 'destination_ports': ['443']}]}
    rule = {'id': 'r1', 'display_name': 'TLS', 'sequence_number': 1, 'action': 'ALLOW',
            'source_groups': ['/g1'], 'destination_groups': ['/g1'], 'services': ['/s1']}
    pol = {'id': 'p1', '_domain': 'default', 'category': 'Application', 'sequence_number': 1, 'rules': [rule]}
    return {'groups': [group], 'services': [service], 'policies': [pol]}

def test_static_ipv4():
    assert ip_to_object('10.1.2.0/24')['prefix'] == 24

def test_reject_dynamic_group():
    with pytest.raises(ValueError):
        resolve_expression([{'resource_type': 'Condition', 'key': 'Tag', 'value': 'APP'}])

def test_reject_ipv6():
    with pytest.raises(ValueError):
        ip_to_object('2001:db8::/64')

def test_reject_source_ports():
    with pytest.raises(ValueError):
        resolve_service({'service_entries': [{'resource_type': 'L4PortSetServiceEntry',
                                              'l4_protocol': 'TCP', 'source_ports': ['80'],
                                              'destination_ports': ['443']}]})

def test_safe_rule_compiles():
    plan = compile_snapshot(fixture())
    assert plan['summary']['eligible_for_review'] == 1
    assert plan['rules'][0]['action'] == 'Accept'

def test_explicit_approval_required():
    snap = fixture()
    plan = compile_snapshot(snap)
    assert candidate(snap, plan, {})['rules'] == []
    rule = plan['rules'][0]
    approval = {rule['source_id']: {'hash': rule['hash'], 'approver': 'Change authority',
                                    'topology_evidence': 'Path verified'}}
    result = candidate(snap, plan, approval)
    assert len(result['rules']) == 1
    assert result['rules'][0]['enabled'] is False

def test_reject_different_hash():
    snap = fixture()
    plan = compile_snapshot(snap)
    rule = plan['rules'][0]
    approval = {rule['source_id']: {'hash': 'incorrect', 'approver': 'Change authority',
                                    'topology_evidence': 'Path verified'}}
    assert not candidate(snap, plan, approval)['rules']

def test_diff_and_max_threshold():
    old = compile_snapshot(fixture())
    snap = fixture()
    snap['policies'][0]['rules'][0]['action'] = 'DROP'
    new = compile_snapshot(snap)
    delta = change_report(old, new)
    assert len(delta['modified']) == 1
    with pytest.raises(RuntimeError):
        safety_check({'sync': {'max_change_percent': 15}}, old, new, delta)

def test_scope_blocks():
    snap = fixture()
    snap['policies'][0]['scope'] = ['/g1']
    assert compile_snapshot(snap)['summary']['blocked'] == 1
