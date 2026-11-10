"""Conservative offline Check Point candidate exporter; NEVER writes to management."""
import argparse, hashlib, json, pathlib
from .model import resolve_expression, resolve_service, digest

def ref_name(prefix, path):
    return prefix + hashlib.sha256(path.encode()).hexdigest()[:14].upper()

def candidate(snapshot, plan, approved):
    groups = {g.get('path'): g for g in snapshot['groups']}
    services = {s.get('path'): s for s in snapshot['services']}
    objects = {}
    cp_rules, rejected = [], []
    for rule in plan['rules']:
        sid = rule['source_id']
        approval = approved.get(sid, {})
        if rule['problems']:
            rejected.append({'source_id': sid, 'reason': rule['problems']})
            continue
        if approval.get('hash') != rule['hash'] or not approval.get('topology_evidence') or not approval.get('approver'):
            rejected.append({'source_id': sid, 'reason': ['Matching hash, approver and topology evidence required']})
            continue
        sources, destinations, rule_services = [], [], []
        try:
            for side, dest in [('sources', sources), ('destinations', destinations)]:
                for path in rule[side]:
                    group_name = ref_name('NSXMIG_G_', path)
                    members = []
                    for obj in resolve_expression(groups[path]['expression']):
                        ref = f'{obj["kind"]}:{obj.get("ip", obj.get("network"))}/{obj.get("prefix", 32)}'
                        name = ref_name('NSXMIG_A_', ref)
                        objects[name] = {'name': name, **obj, 'source_ref': ref}
                        members.append(name)
                    objects[group_name] = {'kind': 'group', 'name': group_name, 'members': sorted(set(members)), 'source_ref': path}
                    dest.append(group_name)
            for path in rule['services']:
                for s in resolve_service(services[path]):
                    name = ref_name('NSXMIG_S_', path + ':' + s['protocol'] + ':' + s['port'])
                    objects[name] = {'kind': 'service', 'name': name, **s, 'source_ref': path}
                    rule_services.append(name)
        except (KeyError, ValueError, TypeError) as e:
            rejected.append({'source_id': sid, 'reason': [str(e)]})
            continue
        cp_rules.append({
            'name': ref_name('NSXMIG_R_', sid), 'source': sources,
            'destination': destinations, 'service': rule_services,
            'action': rule['action'], 'track': {'type': 'Log' if rule['logged'] else 'None'},
            'enabled': False,
            'comments': f'NSX-ID={sid}; HASH={rule["hash"]}; Change evidence={approval["topology_evidence"]}',
            'source_id': sid, 'hash': rule['hash']
        })
    return {
        'objects': list(objects.values()), 'rules': cp_rules, 'rejected': rejected,
        'candidate_hash': digest({'objects': list(objects.values()), 'rules': cp_rules})
    }

def main():
    ap = argparse.ArgumentParser(description='Offline candidate generator; no API writes')
    ap.add_argument('--state-dir', required=True)
    ap.add_argument('--approvals', required=True)
    args = ap.parse_args()
    root = pathlib.Path(args.state_dir)
    snap = json.loads((root / 'latest_snapshot.json').read_text())
    plan = json.loads((root / 'latest_plan.json').read_text())
    approvals = json.loads(pathlib.Path(args.approvals).read_text())
    result = candidate(snap, plan, approvals)
    out = root / 'latest_candidate.json'
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    out.chmod(0o600)
    print(json.dumps({
        'approved_rules': len(result['rules']), 'rejected_rules': len(result['rejected']),
        'objects': len(result['objects']), 'candidate_hash': result['candidate_hash']
    }, indent=2))

if __name__ == '__main__':
    main()
