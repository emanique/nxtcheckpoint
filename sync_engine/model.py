import hashlib, ipaddress, json, re

CATEGORIES = {'Ethernet': 0, 'Emergency': 1, 'Infrastructure': 2, 'Environment': 3, 'Application': 4}
ACTIONS = {'ALLOW': 'Accept', 'DROP': 'Drop', 'REJECT': 'Reject'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def safe_name(value):
    return re.sub('[^A-Za-z0-9_.-]', '_', str(value))[:80]

def ip_to_object(addr):
    n = ipaddress.ip_network(addr, strict=False)
    if n.version != 4:
        raise ValueError('IPv6 not supported by this pilot')
    return {'kind': 'host', 'ip': str(n.network_address)} if n.prefixlen == 32 else {'kind': 'network', 'network': str(n.network_address), 'prefix': n.prefixlen}

def resolve_expression(expr):
    if not isinstance(expr, list) or len(expr) != 1:
        raise ValueError('Dynamic or complex group expression')
    entry = expr[0]
    if entry.get('resource_type') != 'IPAddressExpression':
        raise ValueError('Group is not a simple IPAddressExpression')
    addresses = entry.get('ip_addresses') or []
    if not addresses:
        raise ValueError('Empty group')
    return [ip_to_object(x) for x in addresses]

def resolve_service(service):
    entries = service.get('service_entries', [])
    if not entries:
        raise ValueError('Empty service')
    result = []
    for item in entries:
        if item.get('resource_type') != 'L4PortSetServiceEntry':
            raise ValueError('Non-L4 service')
        proto = item.get('l4_protocol')
        if proto not in ('TCP', 'UDP'):
            raise ValueError('Unsupported protocol')
        if item.get('source_ports'):
            raise ValueError('Source-port restrictions need review')
        ports = item.get('destination_ports') or []
        if not ports:
            raise ValueError('Missing destination ports')
        for port in ports:
            if not re.fullmatch(r'\d{1,5}(?:-\d{1,5})?', str(port)):
                raise ValueError('Invalid port')
            bounds = [int(x) for x in str(port).split('-')]
            if not all(1 <= x <= 65535 for x in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
                raise ValueError('Port outside allowed range')
            result.append({'protocol': proto, 'port': str(port)})
    return result

def compile_snapshot(snapshot, max_rules=5000):
    groups = {g.get('path'): g for g in snapshot['groups']}
    services = {s.get('path'): s for s in snapshot['services']}
    rules, exceptions = [], []
    policies = sorted(snapshot['policies'], key=lambda p: (CATEGORIES.get(p.get('category'), 99), p.get('sequence_number', 0), p.get('id', '')))
    for policy in policies:
        for rule in sorted(policy['rules'], key=lambda r: (r.get('sequence_number', 0), r.get('id', ''))):
            ref = policy['_domain'] + '/' + policy['id'] + '/' + rule['id']
            problems = []
            if policy.get('category') not in CATEGORIES:
                problems.append('Unrecognized category')
            if policy.get('category') == 'Ethernet':
                problems.append('Ethernet/L2 rule')
            if policy.get('scope'):
                problems.append('Policy scope requires DFW enforcement')
            if rule.get('scope'):
                problems.append('Rule scope requires DFW enforcement')
            if policy.get('connectivity_preference') not in (None, 'NONE'):
                problems.append('Implicit connectivity semantics')
            if policy.get('stateful') is False:
                problems.append('Stateless policy')
            if rule.get('disabled', False):
                problems.append('Disabled rule')
            if rule.get('direction', 'IN_OUT') != 'IN_OUT':
                problems.append('Non-bidirectional rule')
            action = ACTIONS.get(rule.get('action'))
            if not action:
                problems.append('Unsupported action')
            if rule.get('source_groups') == ['ANY'] or rule.get('destination_groups') == ['ANY']:
                problems.append('ANY requires scope review')
            for side in ('source_groups', 'destination_groups'):
                paths = rule.get(side) or []
                if not paths:
                    problems.append(side + ': empty')
                    continue
                for path in paths:
                    if path == 'ANY':
                        continue
                    try:
                        resolve_expression(groups[path]['expression'])
                    except (KeyError, TypeError, ValueError) as e:
                        problems.append(side + ': ' + str(e))
            service_paths = rule.get('services') or []
            if not service_paths:
                problems.append('Empty services')
            for path in service_paths:
                if path == 'ANY':
                    problems.append('ANY service requires review')
                    continue
                try:
                    resolve_service(services[path])
                except (KeyError, TypeError, ValueError) as e:
                    problems.append('Service: ' + str(e))
            if rule.get('profiles'):
                problems.append('Security profiles not transferred')
            item = {
                'source_id': ref, 'policy': policy.get('display_name'),
                'name': rule.get('display_name', rule['id']), 'action': action,
                'sources': rule.get('source_groups', []),
                'destinations': rule.get('destination_groups', []),
                'services': service_paths, 'logged': bool(rule.get('logged', False)),
                'problems': sorted(set(problems)), 'category': policy.get('category'),
                'sequence': rule.get('sequence_number', 0)
            }
            item['hash'] = digest({k: v for k, v in item.items() if k != 'hash'})
            rules.append(item)
            if problems:
                exceptions.append({'source_id': ref, 'problems': item['problems']})
    if len(rules) > max_rules:
        raise ValueError('Maximum rule count exceeded')
    return {
        'rules': rules, 'exceptions': exceptions,
        'summary': {'total': len(rules), 'blocked': len(exceptions), 'eligible_for_review': len(rules) - len(exceptions)}
    }
