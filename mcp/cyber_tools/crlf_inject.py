"""Bounded CRLF query testing with differential response-header evidence."""
import asyncio
import secrets
import time
import urllib.parse

import httpx


MAX_REQUESTS = 49
MAX_SECONDS = 15.0
MAX_PARAMS = 4
ENCODINGS = (('standard_crlf', '%0d%0a'), ('lf_only', '%0a'),
             ('double_encoded', '%250d%250a'))


async def crlf_inject(target: str) -> dict:
    """Test bounded query CRLF header injection; report other techniques as untested."""
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    results = []
    coverage = {
        'coverage_complete': False, 'execution_status': 'partial',
        'requests_attempted': 0, 'errors': [], 'cases_completed': 0,
        'request_limit': MAX_REQUESTS, 'deadline_seconds': MAX_SECONDS,
        'response_body_bytes_read': 0,
        'tested_surface': 'GET query parameters; first-hop response headers only',
        'untested_techniques': ['response_splitting', 'log_forgery', 'path_segments',
                               'request_headers', 'cookies', 'post_body', 'json_body',
                               'other_encodings', 'redirect_destinations'],
        'limitations': ['At most four parameter names and three encodings; first occurrence only.',
                        'No response bodies consumed; no log or response framing evidence.',
                        'Redirect headers are inspected but redirects are never followed.',
                        'Negative results do not establish absence of CRLF injection.'],
    }
    # Keep URL credentials, query values, paths, and fragments out of reports.
    report_target = '[invalid target]'
    try:
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('invalid target')
        parsed.port  # Validate malformed ports before starting HTTP.
        report_target = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, '/', '', ''))
        target = urllib.parse.urlunsplit(parsed._replace(fragment=''))
        parts = parsed.query.split('&') if parsed.query else []
        names = [urllib.parse.unquote_plus(p.partition('=')[0]) for p in parts]
        params = list(dict.fromkeys(names + ['q', 'redirect', 'next', 'url']))[:MAX_PARAMS]
    except ValueError:
        coverage['errors'].append('invalid_target')
        params = []

    deadline = time.monotonic() + MAX_SECONDS

    def probe_url(param, value):
        # Replace just one selected value; preserve all other raw query bytes,
        # ordering, duplicate parameters and blank values.
        query = list(parts)
        if param in names:
            index = names.index(param)
            query[index] = query[index].partition('=')[0] + '=' + value
        else:
            query.append(urllib.parse.quote(param, safe='') + '=' + value)
        return urllib.parse.urlunsplit(parsed._replace(query='&'.join(query), fragment=''))

    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        async def request(url):
            if coverage['errors']:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0 or coverage['requests_attempted'] >= MAX_REQUESTS:
                coverage['errors'].append('budget_exhausted')
                return None
            coverage['requests_attempted'] += 1

            async def receive():
                # Header evidence needs zero body bytes: close without iterating
                # even compressed, infinite or oversized response streams.
                async with client.stream('GET', url, follow_redirects=False,
                                         headers={'Cache-Control': 'no-cache'}) as response:
                    if response.status_code in (401, 403, 429) or response.status_code >= 500:
                        coverage['errors'].append('blocked_or_server_error:' + str(response.status_code))
                        return None
                    return response.status_code, response.headers.copy()

            try:
                return await asyncio.wait_for(receive(), timeout=min(5.0, remaining))
            except (httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
                coverage['errors'].append(type(exc).__name__)
                return None

        baseline = await request(target) if params else None
        for param_index, param in enumerate(params):
            if baseline is None or coverage['errors']:
                break
            for encoding_name, newline in ENCODINGS:
                confirmed = []
                for _ in range(2):
                    # Fresh challenge on repeat defeats cached responses. The
                    # same header/value is present in the non-newline control.
                    header = 'X-Crlf-Probe-' + secrets.token_hex(12)
                    value = secrets.token_hex(16)
                    suffix = header + '%3A%20' + value
                    control = await request(probe_url(param, 'probe-' + suffix))
                    if control is None:
                        break
                    attack = await request(probe_url(param, 'probe' + newline + suffix))
                    if attack is None:
                        break
                    if (header in baseline[1] or header in control[1]
                            or attack[1].get_list(header) != [value]
                            or attack[0] != control[0]):
                        break
                    confirmed.append(attack[0])
                if coverage['errors']:
                    break
                coverage['cases_completed'] += 1
                if len(confirmed) == 2:
                    results.append({
                        'technique': 'header_injection',
                        'param': 'query_parameter_' + str(param_index + 1),
                        'payload': encoding_name, 'status': confirmed[-1],
                        'risk': 'HIGH', 'confidence': 'high',
                        # Fixed, JSON-safe snapshot: no mutable scan counters or
                        # collections shared with the envelope/other findings.
                        'coverage': {
                            'surface': 'GET query; first-hop response headers',
                            'parameter_occurrence': 1, 'encoding': encoding_name,
                            'coverage_complete': False, 'redirects_followed': False,
                            'untested': ', '.join(coverage['untested_techniques']),
                        },
                        'evidence': {'source': 'response_header', 'exact_nonce_match': True,
                                     'baseline_absent': True, 'control_absent': True,
                                     'repeat_confirmed': True, 'independent_markers': 2},
                    })
                    break
    coverage['planned_subset_complete'] = not coverage['errors']
    return {
        'target': report_target, 'results': results, 'vulnerable': bool(results),
        'total_findings': len(results),
        'techniques_found': ['header_injection'] if results else [],
        'risk_summary': {'critical': 0, 'high': len(results), 'medium': 0},
        'coverage': coverage,
    }
