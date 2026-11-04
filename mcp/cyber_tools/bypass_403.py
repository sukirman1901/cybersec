"""Bounded 403 differentials with stable denied and matched resource controls."""
import urllib.parse

import httpx

from .api_auth import (_AuthProbe, _assess, _negative_baseline, _safe_target,
                       _parse_target, _invalid_target_result)


HEADER_BYPASSES = [
    ({'X-Forwarded-For': '127.0.0.1'}, 'X-Forwarded-For localhost'),
    ({'X-Forwarded-For': '1'}, 'X-Forwarded-For 1'),
    ({'X-Forwarded-Host': 'localhost'}, 'X-Forwarded-Host localhost'),
    ({'X-Forwarded-Server': 'localhost'}, 'X-Forwarded-Server localhost'),
    ({'X-Original-URL': '', 'X-Rewrite-URL': ''}, 'X-Original-URL / X-Rewrite-URL'),
    ({'X-Custom-IP-Authorization': '127.0.0.1'}, 'X-Custom-IP-Authorization'),
    ({'X-Real-IP': '127.0.0.1'}, 'X-Real-IP'),
    ({'Client-IP': '127.0.0.1'}, 'Client-IP'),
    ({'X-Client-IP': '127.0.0.1'}, 'X-Client-IP'),
    ({'X-Remote-Addr': '127.0.0.1'}, 'X-Remote-Addr'),
    ({'X-Remote-IP': '127.0.0.1'}, 'X-Remote-IP'),
    ({'X-ProxyUser-IP': '127.0.0.1'}, 'X-ProxyUser-IP'),
    ({'X-Real-User-IP': '127.0.0.1'}, 'X-Real-User-IP'),
    ({'X-Host': 'localhost'}, 'X-Host'),
    ({'X-Forwarded-Proto': 'https'}, 'X-Forwarded-Proto'),
    ({'X-Forwarded-Port': '443'}, 'X-Forwarded-Port'),
    ({'X-HTTP-Host-Override': 'localhost'}, 'X-HTTP-Host-Override'),
    ({'Forwarded': 'for=127.0.0.1;by=127.0.0.1;host=localhost'}, 'Forwarded header'),
    ({'True-Client-IP': '127.0.0.1'}, 'True-Client-IP'),
    ({'CF-Connecting-IP': '127.0.0.1'}, 'CF-Connecting-IP'),
    ({'X-Cluster-Client-IP': '127.0.0.1'}, 'X-Cluster-Client-IP'),
]

PATH_BYPASSES = [
    '/{path}/', '/{path}/.', '/./{path}', '/{path}/..;/', '/;/{path}',
    '/..;/{path}', '/{path}%', '/{path}..;/', '/{path}%20', '/{path}%09',
    '/{path}%00', '/{path}~', '/{path}.json', '/{path}.html', '/{path}.txt',
    '/{path}%', '/{path}..', '/{path}...', '/{path}/..', '/{path}/../',
    '/%2e{path}', '/{path}%2f', '/{path}#', '/{path}?', '/{path};',
    '/{path}%0a', '/{path}%0d%0a', '/{path}\\', '/{path}/%20', '/{path}/',
    '/%2f{path}', '/{path}/*/', '/{path}/./',
]


def _case_variants(path: str) -> list[str]:
    variants = [path, path.upper(), path.lower(), path.capitalize()]
    if len(path) > 1:
        variants.extend((path[0].upper() + path[1:], path[0].lower() + path[1:]))
    return list(dict.fromkeys(variants))


def _encoding_variants(path: str) -> list[str]:
    variants = [urllib.parse.quote(path, safe='/'),
                urllib.parse.quote(urllib.parse.quote(path, safe='/'), safe='/'),
                ''.join(f'%{ord(c):02x}' for c in path),
                ''.join(f'%u{ord(c):04x}' for c in path),
                ''.join(f'%{ord(c):02x}' if c.isalpha() else c for c in path)]
    return list(dict.fromkeys(variants))


# Mutation methods cannot establish equivalent GET access and may change data.
METHOD_BYPASSES = ['HEAD', 'OPTIONS']
PROTOCOL_BYPASSES = []  # Raw protocol evidence had no bounded, matched control.


async def bypass_403(target: str) -> dict:
    """Compare existing probes against stable 403 controls; retain uncertainty."""
    try:
        parsed = _parse_target(target)
    except (ValueError, httpx.InvalidURL):
        return {**_invalid_target_result(), 'baseline_status': None, 'bypasses': [],
                'bypass_found': False, 'total_techniques_tried': 0, 'techniques_found': []}
    target = urllib.parse.urlunsplit(parsed)
    path = parsed.path or '/'
    results, candidates = [], []
    baseline_status = None
    tried = 0
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        probe = _AuthProbe(client)
        negative = await _negative_baseline(probe, target, statuses=(403,))
        baseline_status = probe.baseline_status
        if negative is not None:
            attempts = [('header_bypass', desc, 'GET', target, headers)
                        for headers, desc in HEADER_BYPASSES]
            for template in PATH_BYPASSES:
                variant = template.replace('{path}', path.strip('/'))
                # Templates ending in ?/# were no-ops. Retain the caller query.
                variant = variant.rstrip('?#')
                url = urllib.parse.urlunsplit(parsed._replace(path=variant))
                attempts.append(('path_bypass', 'Path variant', 'GET', url, {}))
            for technique, variants in (('case_bypass', _case_variants(path)),
                                        ('encoding_bypass', _encoding_variants(path))):
                for variant in variants[:5]:
                    # Keep encoded leading slashes within this origin.
                    if not variant.startswith('/'):
                        continue
                    url = urllib.parse.urlunsplit(parsed._replace(path=variant))
                    attempts.append((technique, 'Path variant', 'GET', url, {}))
            attempts.extend(('method_bypass', method, method, target, {}) for method in METHOD_BYPASSES)
            seen = {('GET', str(httpx.URL(target)), ())}
            for technique, description, method, url, headers in attempts:
                key = (method, str(httpx.URL(url)), tuple(sorted(headers.items())))
                if key in seen:
                    continue
                seen.add(key)
                tried += 1
                evidence = await _assess(probe, target, negative, method, url, headers)
                if evidence:
                    row = {'technique': technique, 'description': description, **evidence}
                    if evidence['resource_access_observed']:
                        results.append({**row, 'success': True})
                        break
                    candidates.append({**row, 'success': False})
                if probe.stopped:
                    break
    return {'target': _safe_target(target), 'baseline_status': baseline_status,
            'bypasses': results, 'candidates': candidates, 'bypass_found': bool(results),
            'total_techniques_tried': tried,
            'techniques_found': list(dict.fromkeys(r['technique'] for r in results)),
            'coverage': 'Bounded existing headers/path/case/encoding and HEAD/OPTIONS; mutation methods and raw protocol probes unsupported. Authenticated roles not verified.',
            **probe.summary()}
