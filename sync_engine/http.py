import time
from urllib.parse import urlparse
import requests

class APIError(RuntimeError): pass

class HTTPClient:
    def __init__(self, base_url, ca_bundle, timeout=25, attempts=3):
        if urlparse(base_url).scheme != 'https':
            raise ValueError('HTTPS required')
        if ca_bundle is not True and (not isinstance(ca_bundle, str) or not ca_bundle):
            raise ValueError('CA bundle required')
        self.base = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = ca_bundle
        self.timeout, self.attempts = timeout, attempts

    def request(self, method, path, **kwargs):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('Invalid API path')
        for attempt in range(self.attempts):
            try:
                response = self.session.request(method, self.base+path, timeout=self.timeout, **kwargs)
            except requests.RequestException as e:
                if attempt == self.attempts-1:
                    raise APIError(f'Transport error: {type(e).__name__}') from e
                time.sleep(2**attempt)
                continue
            if response.status_code in (429, 502, 503, 504) and attempt < self.attempts-1:
                time.sleep(min(2**attempt, 8))
                continue
            if not response.ok:
                raise APIError(f'HTTP {response.status_code} on {method} {path}: {response.text[:300]}')
            try:
                return response.json()
            except ValueError as e:
                raise APIError('Non-JSON response') from e
        raise APIError('Retry limit exceeded')
