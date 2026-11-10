from urllib.parse import quote
from .http import HTTPClient, APIError

class NSXClient:
    def __init__(self, cfg, user, password):
        self.http = HTTPClient(cfg['url'], cfg['ca_bundle'])
        self.http.session.auth = (user, password)

    def paginate(self, path):
        results = []
        cursor = None
        seen = set()
        while True:
            url = path + (('?' if '?' not in path else '&') + 'cursor=' + quote(cursor, safe='') if cursor else '')
            page = self.http.request('GET', url)
            if not isinstance(page.get('results'), list):
                raise APIError('Invalid NSX response: results')
            results.extend(page['results'])
            cursor = page.get('cursor')
            if not cursor:
                return results
            if cursor in seen:
                raise APIError('Repeated NSX pagination cursor')
            seen.add(cursor)

    def snapshot(self, domains):
        out = {'policies': [], 'groups': [], 'services': []}
        out['services'] = self.paginate('/policy/api/v1/infra/services')
        for domain in domains:
            d = quote(domain, safe='')
            base = f'/policy/api/v1/infra/domains/{d}'
            groups = self.paginate(base + '/groups')
            out['groups'].extend([{**g, '_domain': domain} for g in groups])
            policies = self.paginate(base + '/security-policies')
            for p in policies:
                policy_id = quote(p['id'], safe='')
                rules = self.paginate(base + f'/security-policies/{policy_id}/rules')
                out['policies'].append({**p, '_domain': domain, 'rules': rules})
        return out
