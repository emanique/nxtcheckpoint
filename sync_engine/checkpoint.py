from .http import HTTPClient

class CheckPointClient:
    def __init__(self, cfg, key):
        self.cfg = cfg
        self.http = HTTPClient(cfg['url'], cfg['ca_bundle'])
        self.key = key
        self.sid = None

    def call(self, method, payload=None):
        headers = {'Content-Type': 'application/json'}
        if self.sid:
            headers['X-chkp-sid'] = self.sid
        return self.http.request('POST', '/web_api/' + method, headers=headers, json=payload or {})

    def login(self, read_only=True):
        body = {'api-key': self.key, 'read-only': read_only}
        if self.cfg.get('management_domain'):
            body['domain'] = self.cfg['management_domain']
        result = self.call('login', body)
        self.sid = result['sid']
        return result

    def logout(self):
        if self.sid:
            try:
                self.call('logout')
            finally:
                self.sid = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.logout()

    def show_layer(self, layer):
        return self.call('show-access-layer', {'name': layer, 'details-level': 'standard'})

    def show_rulebase(self, layer):
        offset = 0
        results = []
        while True:
            data = self.call('show-access-rulebase', {'name': layer, 'offset': offset, 'limit': 100, 'details-level': 'standard'})
            batch = data.get('rulebase', [])
            results.extend(batch)
            offset += len(batch)
            if offset >= data.get('total', offset) or not batch:
                return results

    def discard(self):
        return self.call('discard')

    def publish(self):
        return self.call('publish')
