"""Bounded auth differentials; public responses alone are not auth findings."""
import asyncio
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

AUTH_TESTS = [
    ("no_auth", {}),
    ("basic_auth", {"Authorization": "Basic YWRtaW46YWRtaW4="}),
    ("bearer_fake", {"Authorization": "Bearer fake_token_123"}),
    ("bearer_none", {"Authorization": "Bearer none"}),
    ("api_key_header", {"X-API-Key": "admin"}),
    ("internal_header", {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Internal": "true"}),
    ("admin_header", {"X-Admin": "true", "X-Role": "admin", "X-Auth": "bypass"}),
]

API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/users",
    "/api/admin",
    "/graphql",
    "/rest",
    "/swagger",
    "/api/swagger",
    "/api/docs",
    "/api/health",
    "/api/status",
]


class _AuthProbe:
    """SurfaceProbe cannot be used here: it stops on expected 401/403 controls."""

    def __init__(self, client, seconds=20, max_requests=128, max_bytes=262144):
        self.client = client
        self.deadline = time.monotonic() + seconds
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.requests = 0
        self.errors = []
        self.stopped = False
        self.baseline_status = None

    async def request(self, method, url, **kwargs):
        if self.stopped:
            return None
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= self.max_requests:
            self.fail('budget_exhausted')
            return None
        self.requests += 1

        async def receive():
            # Each observation is stateless: a Set-Cookie from an earlier probe
            # must not contaminate subsequent negative controls.
            self.client.cookies.clear()
            async with self.client.stream(method, url, follow_redirects=False, **kwargs) as response:
                if response.status_code == 429 or response.status_code >= 500:
                    self.fail('rate_limit_or_server_error')
                    return None
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > self.max_bytes:
                        self.fail('body_limit_exceeded')
                        return None
                    body.extend(chunk)
                return httpx.Response(response.status_code, content=bytes(body))
        try:
            return await asyncio.wait_for(receive(), remaining)
        except (httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
            self.fail(type(exc).__name__)
            return None

    def fail(self, reason):
        self.errors.append(reason)
        self.stopped = True

    def summary(self):
        return {'requests_attempted': self.requests, 'coverage_complete': not self.errors,
                'execution_status': 'partial' if self.errors else 'completed',
                'errors': self.errors}


def _safe_target(target):
    # Do not echo credentials, paths, queries, fragments or response content.
    parsed = urlsplit(target)
    host = parsed.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    if parsed.port is not None:
        host += ':' + str(parsed.port)
    return urlunsplit((parsed.scheme, host, '', '', ''))


def _parse_target(target):
    """Validate syntax before creating a client; do not resolve or contact hosts."""
    parsed = urlsplit(target if '://' in target else 'https://' + target)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('invalid_target')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('invalid_target')
    if any(char.isspace() for char in parsed.netloc):
        raise ValueError('invalid_target')
    httpx.URL(urlunsplit(parsed))
    return parsed._replace(fragment='')


def _invalid_target_result():
    return {'target': None, 'candidates': [], 'requests_attempted': 0,
            'coverage_complete': False, 'execution_status': 'partial',
            'error': 'Invalid HTTP(S) target', 'errors': ['invalid_target'],
            'coverage': 'Input validation only; no requests sent.'}


def _same_response(left, right):
    return right is not None and left.status_code == right.status_code and left.content == right.content


async def _negative_baseline(probe, url, statuses=(401, 403)):
    first = await probe.request('GET', url)
    probe.baseline_status = first.status_code if first is not None else None
    if first is None or first.status_code not in statuses:
        return None
    second = await probe.request('GET', url)
    if not _same_response(first, second):
        if second is not None:
            probe.fail('unstable_negative_baseline')
        return None
    return first


def _matched_resource(negative, positive):
    """Narrow structured resource evidence, not a keyword or status heuristic.

    An explicit identical resource identity in a denied envelope and a data
    envelope supports resource access, but not an authenticated role claim.
    Other formats remain candidates for caller-supplied protected controls.
    """
    try:
        denied, allowed = negative.json(), positive.json()
    except ValueError:
        return False
    return (isinstance(denied, dict) and isinstance(allowed, dict)
            and isinstance(denied.get('resource'), str) and bool(denied['resource'])
            and denied['resource'] == allowed.get('resource')
            and denied.get('error') in ('forbidden', 'unauthorized', 'access_denied')
            and not allowed.get('error')
            and isinstance(allowed.get('data'), (dict, list)) and bool(allowed['data']))


async def _assess(probe, target, negative, method, url, headers=None):
    response = await probe.request(method, url, headers=headers or {})
    if response is None or response.status_code != 200 or not response.content or method != 'GET':
        return None
    repeat = await probe.request(method, url, headers=headers or {})
    control = await probe.request('GET', target)
    if not _same_response(response, repeat) or not _same_response(negative, control):
        if not probe.stopped:
            probe.fail('unstable_differential')
        return None
    matched = _matched_resource(negative, response)
    return {'status': response.status_code, 'size': len(response.content),
            'confidence': 'medium' if matched else 'low',
            'resource_access_observed': matched,
            'authenticated_privilege_confirmed': False,
            'coverage': ('Repeated GET differential against stable denied controls; '
                         + ('matching structured resource identity observed; ' if matched else
                            'protected resource identity unverified; ')
                         + 'authenticated roles not verified; response bodies withheld.'),
            'evidence': 'stable denied/data resource match' if matched else 'stable status/body differential only',
            'severity': 'medium' if matched else 'info'}


async def api_auth(target: str) -> dict:
    results, candidates = [], []
    try:
        parsed = _parse_target(target)
    except (ValueError, httpx.InvalidURL):
        return {**_invalid_target_result(), 'tests': [], 'api_endpoints_exposed': 0,
                'critical_findings': 0}
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        probe = _AuthProbe(client)
        for api_path in API_PATHS:
            url = urlunsplit(parsed._replace(path=parsed.path.rstrip('/') + api_path, fragment=''))
            negative = await _negative_baseline(probe, url)
            if probe.stopped:
                break
            if negative is None:
                continue
            for test_name, headers in AUTH_TESTS:
                if not headers:
                    continue
                evidence = await _assess(probe, url, negative, 'GET', url, headers)
                if evidence:
                    row = {'endpoint': api_path, 'test': test_name, **evidence}
                    if evidence['resource_access_observed']:
                        results.append({**row, 'auth_bypass_possible': True})
                        break
                    else:
                        candidates.append(row)
                if probe.stopped:
                    break
    return {'target': _safe_target(urlunsplit(parsed)), 'tests': results, 'candidates': candidates,
            'api_endpoints_exposed': len(results), 'critical_findings': 0,
            'coverage': 'Fixed API paths and existing header probes only; no role/session, query-token or protocol testing. Public endpoints are not vulnerabilities.',
            **probe.summary()}
