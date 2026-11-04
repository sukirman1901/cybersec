"""Preserve request context while replacing one query parameter."""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import json


class ObservedAsyncClient:
    """Count request failures even when a detector handles the exception locally."""
    def __init__(self, client):
        self.client = client
        self.attempted = 0
        self.failed = 0
        self.blocked = 0

    def __getattr__(self, name):
        return getattr(self.client, name)

    async def request(self, method, url, **kwargs):
        self.attempted += 1
        try:
            response = await self.client.request(method, url, **kwargs)
        except Exception:
            self.failed += 1
            raise
        if response.status_code in (401, 403, 429) or response.status_code >= 500:
            self.blocked += 1
        return response

    async def get(self, url, **kwargs):
        return await self.request('GET', url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request('POST', url, **kwargs)


def query_value(url, name, value):
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    result = []
    for key, old in pairs:
        if key == name and not replaced:
            result.append((key, value))
            replaced = True
        else:
            result.append((key, old))
    if not replaced:
        result.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(result), fragment=""))


def request_context(raw):
    """Explicit request inputs only; destination always comes from scoped target."""
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict) or set(value) - {'method', 'headers', 'cookies', 'json', 'data'}:
        raise ValueError('request_json supports method, headers, cookies, json or data only')
    method = str(value.get('method', 'GET')).upper()
    if method not in ('GET', 'POST', 'PUT', 'PATCH'):
        raise ValueError('Unsupported request method')
    if 'json' in value and 'data' in value:
        raise ValueError('Provide json or data, not both')
    for key in ('headers', 'cookies', 'json', 'data'):
        if key in value and (not isinstance(value[key], dict) or any(
                not isinstance(k, str) or isinstance(v, (dict, list)) for k, v in value[key].items())):
            raise ValueError(key + ' must be a flat object')
    if method == 'GET' and ('json' in value or 'data' in value):
        raise ValueError('GET bodies not supported')
    headers = value.get('headers', {})
    if any(k.lower() in ('host', 'content-length', 'transfer-encoding') for k in headers):
        raise ValueError('Host and framing headers are derived from the scoped request')
    value['method'] = method
    return value
