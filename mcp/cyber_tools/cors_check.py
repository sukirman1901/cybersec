"""Bounded CORS policy observations, not proof of sensitive-data exposure."""
from __future__ import annotations

import asyncio
import time

import httpx
from .http_guard import GuardedAsyncClient


OBSERVE_SECONDS = 12.0
OBSERVE_REQUESTS = 24
DEEP_SECONDS = 25.0
DEEP_REQUESTS = 64
CORE_ORIGINS = (
    'https://evil.com', 'http://evil.com', 'null',
    'https://evil{host}', 'https://{host}.evil.com',
    '{scheme}://{host}', 'https://sub.{host}.evil.com',
)
DEEP_ORIGINS = CORE_ORIGINS + (
    'https://evil.{host}', 'https://{host}-evil.com',
    'https://{host}evil.com', '{scheme}://evil{host}',
)


def _serialized_origin(url: httpx.URL) -> str:
    host = url.raw_host.decode('ascii')
    if ':' in host:
        host = '[' + host + ']'
    port = ':' + str(url.port) if url.port is not None else ''
    return url.scheme + '://' + host + port


def _format_origins(templates: tuple[str, ...], host: str, scheme: str) -> list[str]:
    """Only emit browser-serializable origins, excluding path/userinfo tricks."""
    origins = []
    for template in templates:
        try:
            origin = template.format(host=host, scheme=scheme)
            if origin != 'null':
                url = httpx.URL(origin)
                if (url.scheme not in ('http', 'https') or not url.host or url.userinfo
                        or url.path != '/' or url.query or url.fragment
                        or _serialized_origin(url) != origin):
                    continue
            if origin not in origins:
                origins.append(origin)
        except (httpx.InvalidURL, ValueError, KeyError, IndexError):
            continue
    return origins


async def cors_check(target: str, preset: str = 'observe-first') -> dict:
    """Observe credentialed GET CORS policy; staging-deep adds safe preflights.

    `vulnerable` retains compatibility and means a policy candidate only.
    Authentication, cookie delivery and sensitive response content are untested.
    """
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    results, errors = [], []
    requests = 0
    stopped = False
    origins = []
    report_target = '[invalid target]'
    own_origin = ''
    deep = preset == 'staging-deep'
    max_requests = DEEP_REQUESTS if deep else OBSERVE_REQUESTS
    seconds = DEEP_SECONDS if deep else OBSERVE_SECONDS
    deadline = time.monotonic() + seconds
    try:
        url = httpx.URL(target)
        if (url.scheme not in ('http', 'https') or not url.host or url.userinfo
                or preset not in ('observe-first', 'staging-deep')):
            raise ValueError('invalid input')
        own_origin = _serialized_origin(url)
        report_target = own_origin + '/'
        target = str(url.copy_with(fragment=None))
        host = url.raw_host.decode('ascii')
        if ':' in host:
            host = '[' + host + ']'
        origins = _format_origins(DEEP_ORIGINS if deep else CORE_ORIGINS, host, url.scheme)
        if own_origin not in origins:
            origins.append(own_origin)
    except (ValueError, httpx.InvalidURL):
        errors.append('invalid_target_or_preset')

    async with GuardedAsyncClient(timeout=4.0 if deep else 3.0,
                                  follow_redirects=False) as client:
        async def observe(method, origin, requested_method='GET'):
            nonlocal requests, stopped
            remaining = deadline - time.monotonic()
            if stopped:
                return
            if remaining <= 0 or requests >= max_requests:
                errors.append('budget_exhausted')
                stopped = True
                return
            requests += 1
            headers = {'Origin': origin}
            if method == 'OPTIONS':
                headers.update({'Access-Control-Request-Method': requested_method,
                                'Access-Control-Request-Headers': 'authorization,content-type'})

            async def receive():
                # No body is needed for policy inspection. Avoid eager reads,
                # decompression, infinite streams and redirect credential egress.
                async with client.stream(method, target, headers=headers,
                                         follow_redirects=False) as response:
                    return response.status_code, response.headers.copy()
            try:
                status, response_headers = await asyncio.wait_for(
                    receive(), timeout=min(remaining, 4.0 if deep else 3.0))
            except (httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
                errors.append(type(exc).__name__)
                results.append({'test_type': 'actual_request' if method == 'GET' else 'preflight',
                                'origin': origin, 'error': type(exc).__name__, 'vulnerable': False})
                stopped = True
                return

            success = 200 <= status < 300
            if not success:
                errors.append(method + '_status:' + str(status))
                # OPTIONS may be unsupported while simple GET is supported.
                if method == 'GET' or status != 405:
                    stopped = True
            acao = response_headers.get_list('access-control-allow-origin')
            acac = response_headers.get_list('access-control-allow-credentials')
            reflected = acao == [origin]
            wildcard = acao == ['*']
            # Fetch's credential check is case sensitive and requires a single
            # exact ACAO field. Wildcard cannot authorize credentials mode include.
            credentials = reflected and acac == ['true']
            candidate = method == 'GET' and success and origin != own_origin and credentials
            observation = {
                'test_type': 'actual_request' if method == 'GET' else 'preflight',
                'method': method, 'origin': origin, 'status_code': status,
                'is_reflected': reflected and origin != 'null',
                'is_wildcard': wildcard, 'is_null': reflected and origin == 'null',
                'credentials_allowed': credentials, 'vulnerable': candidate,
                'severity': 'HIGH' if candidate else '',
                # Do not serialize arbitrary reflected header data or cookies.
                'acao': origin if reflected else '*' if wildcard else '[absent_or_other]',
                'acac': 'true' if acac == ['true'] else '[absent_or_invalid]',
            }
            if method == 'OPTIONS':
                observation['requested_method'] = requested_method
            if candidate:
                observation.update({
                    'classification': 'cors_policy_candidate', 'confidence': 'HIGH',
                    'sensitive_data_leak_verified': False,
                    'coverage': 'Successful unauthenticated GET response headers only; '
                                'authentication, cookie delivery, sensitive content and browser exploitation untested.',
                })
            results.append(observation)

        for origin in origins:
            if stopped:
                break
            await observe('GET', origin)
            await observe('OPTIONS', origin)
        if deep and not stopped and origins:
            for origin in ('https://evil.com', 'null'):
                for requested_method in ('POST', 'PUT', 'DELETE'):
                    # These are OPTIONS requests only, never actual mutations.
                    await observe('OPTIONS', origin, requested_method)

    findings = [item for item in results if item.get('vulnerable')]
    total_tests = sum('status_code' in item for item in results)
    coverage = (
        f'preset={preset}; requests_attempted={requests}; tests_completed={total_tests}; '
        f'request_limit={max_requests}; deadline_seconds={seconds}; response_body_bytes_read=0; '
        'first-hop headers only; redirects not followed; actual mutating methods untested; '
        'sensitive content, authentication and browser credential delivery untested; '
        'non-browser origin strings excluded; negative results do not establish safety'
    )
    return {
        'target': report_target, 'preset': preset, 'total_tests': total_tests,
        'vulnerable_count': len(findings), 'vulnerable': bool(findings),
        'risk': 'high' if findings else 'info',
        'confidence': 'HIGH' if findings else 'LOW' if errors else 'MEDIUM',
        'coverage': coverage, 'coverage_complete': False,
        'execution_status': 'partial' if errors else 'completed',
        'errors': errors, 'requests_attempted': requests,
        'technique': 'Credentialed CORS policy candidates; sensitive-data leakage unverified',
        'evidence': [f"GET permits credentialed CORS for {f['origin']} (policy only)" for f in findings],
        'findings': findings, 'all_results': results,
    }
