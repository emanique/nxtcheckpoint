import argparse, datetime, json, os, pathlib, sys, time
import yaml
from .nsx import NSXClient
from .checkpoint import CheckPointClient
from .model import compile_snapshot, digest

def write_json(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + '\n', encoding='utf-8')
    os.chmod(tmp, 0o600)
    tmp.replace(path)

def read_json(path, default=None):
    return json.loads(pathlib.Path(path).read_text()) if pathlib.Path(path).exists() else default

def change_report(previous, current):
    a = {r['source_id']: r['hash'] for r in (previous or {}).get('rules', [])}
    b = {r['source_id']: r['hash'] for r in current['rules']}
    return {
        'added': sorted(b.keys() - a.keys()),
        'removed': sorted(a.keys() - b.keys()),
        'modified': sorted(k for k in a.keys() & b.keys() if a[k] != b[k]),
        'unchanged': sum(a[k] == b[k] for k in a.keys() & b.keys())
    }

def safety_check(cfg, old, current, diff):
    if not current['rules']:
        raise RuntimeError('Empty rule snapshot: fail-closed')
    if old and old['rules']:
        n = len(diff['added']) + len(diff['removed']) + len(diff['modified'])
        percent = 100 * n / len(old['rules'])
        if percent > float(cfg['sync']['max_change_percent']):
            raise RuntimeError(f'Anomalous delta: {percent:.1f}% exceeds threshold')
    return True

def one_cycle(config, cp_check=False):
    cfg = yaml.safe_load(pathlib.Path(config).read_text())
    root = pathlib.Path(cfg['sync']['state_dir'])
    root.mkdir(parents=True, exist_ok=True)
    user = os.environ[cfg['nsx']['username_env']]
    password = os.environ[cfg['nsx']['password_env']]
    snapshot = NSXClient(cfg['nsx'], user, password).snapshot(cfg['nsx']['domains'])
    if not snapshot['policies']:
        raise RuntimeError('No policies returned by NSX: incomplete inventory or wrong domain')
    compiled = compile_snapshot(snapshot, int(cfg['sync']['max_rules']))
    old = read_json(root / 'last_good.json')
    diff = change_report(old, compiled)
    safety_check(cfg, old, compiled, diff)
    cp_status = {'checked': False}
    if cp_check:
        key = os.environ[cfg['checkpoint']['api_key_env']]
        cp = CheckPointClient(cfg['checkpoint'], key)
        try:
            cp.login(read_only=True)
            layer = cp.show_layer(cfg['checkpoint']['layer'])
            rulebase = cp.show_rulebase(cfg['checkpoint']['layer'])
            cp_status = {'checked': True, 'layer_uid': layer.get('uid'), 'target_rulebase_elements': len(rulebase)}
        finally:
            cp.logout()
    report = {
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'snapshot_hash': digest(snapshot), 'compiled_hash': digest(compiled),
        'delta': diff, 'summary': compiled['summary'], 'checkpoint': cp_status,
        'status': 'REVIEW_REQUIRED' if any(diff[k] for k in ('added', 'removed', 'modified')) or compiled['exceptions'] else 'NO_CHANGE'
    }
    write_json(root / 'latest_snapshot.json', snapshot)
    write_json(root / 'latest_plan.json', compiled)
    write_json(root / 'latest_report.json', report)
    write_json(root / 'last_good.json', compiled)
    write_json(root / 'history' / f"{int(time.time())}_{report['compiled_hash'][:10]}.json", report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report

def main():
    parser = argparse.ArgumentParser(description='NSX→Check Point guarded planner (no writes)')
    parser.add_argument('--config', default='/etc/nsxcp/config.yaml')
    parser.add_argument('--check-checkpoint', action='store_true')
    parser.add_argument('--loop', action='store_true')
    args = parser.parse_args()
    if not args.loop:
        try:
            one_cycle(args.config, args.check_checkpoint)
        except Exception as e:
            print(f'FAIL-CLOSED: {type(e).__name__}: {e}', file=sys.stderr)
            sys.exit(2)
    else:
        cfg = yaml.safe_load(pathlib.Path(args.config).read_text())
        while True:
            try:
                one_cycle(args.config, args.check_checkpoint)
            except Exception as e:
                print(f'FAIL-CLOSED: {type(e).__name__}: {e}', file=sys.stderr)
            time.sleep(max(30, int(cfg['sync']['interval_seconds'])))

if __name__ == '__main__':
    main()
