"""Historical certificate/PTR name candidates; not verified shared hosting."""

import socket
import httpx
import asyncio
import ipaddress
import re
from .surface_probe import SurfaceProbe


async def reverse_ip(target: str) -> dict:
    result = {'target': '[invalid target]', 'domains': [], 'count': 0, 'sources': {},
              'sources_status': {}, 'coverage_complete': False, 'hosting_verified': False,
              'scope_authorized': False, 'truncated': False, 'assessment': 'incomplete',
              'coverage': 'One CT response (200 rows) plus PTR, at most 100 distinct name candidates; historical IP SAN/PTR association is not current co-hosting proof or authorization'}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        target = url.host.lower().rstrip('.')
        if url.scheme not in ('http', 'https') or url.userinfo or not target:
            raise ValueError('Invalid target')
        try:
            ip = str(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError:
            if not _hostname(target):
                raise ValueError('Unsupported IPv4 target')
            ip = str(ipaddress.IPv4Address(await asyncio.wait_for(asyncio.to_thread(socket.gethostbyname, target), timeout=5)))
        result.update(ip=ip, target=target)
    except (OSError, ValueError, TypeError, httpx.InvalidURL, asyncio.TimeoutError) as exc:
        return {**result, 'error': type(exc).__name__}
    candidates = {}
    errors = []
    try:
        async with httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=False) as client:
            probe = SurfaceProbe(client, max_requests=1)
            resp = await probe.request('GET', 'https://crt.sh/', params={'q':ip, 'output':'json'})
            result['requests_attempted'] = probe.requests
            if resp is None:
                errors.extend(probe.errors)
            elif resp.status_code != 200:
                errors.append('Provider HTTP ' + str(resp.status_code))
            else:
                rows = resp.json()
                if not isinstance(rows, list):
                    raise ValueError('Provider schema')
                result['truncated'] = len(rows) > 200
                for entry in rows[:200]:
                    if not isinstance(entry, dict) or not isinstance(entry.get('name_value'), str):
                        errors.append('Malformed certificate row')
                        continue
                    names = {name.strip().lower().rstrip('.') for name in entry['name_value'].splitlines()}
                    # Search matches are not evidence: require the queried IP in
                    # the same certificate's SAN values, then label historical only.
                    if ip not in names:
                        continue
                    for name in sorted(names):
                        if _hostname(name):
                            candidates.setdefault(name, set()).add('crt.sh')
    except (httpx.HTTPError, ValueError, TypeError, RecursionError) as exc:
        errors.append(type(exc).__name__)
    result['sources_status']['crt.sh'] = 'incomplete' if errors or result['truncated'] else 'response_parsed'
    try:
        rev = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=5)
        if not isinstance(rev, tuple) or len(rev) != 3 or not isinstance(rev[0], str) or not isinstance(rev[2], list) or ip not in rev[2]:
            raise ValueError('PTR identity mismatch')
        name = rev[0].lower().rstrip('.')
        if not _hostname(name):
            raise ValueError('Invalid PTR hostname')
        candidates.setdefault(name, set()).add('rdns')
        result['sources_status']['rdns'] = 'response_parsed'
    except socket.herror as exc:
        if exc.errno == 1:
            result['sources_status']['rdns'] = 'no_record'
        else:
            result['sources_status']['rdns'] = 'incomplete'
            errors.append('PTR lookup failure')
    except (OSError, ValueError, TypeError, asyncio.TimeoutError):
        result['sources_status']['rdns'] = 'incomplete'
        errors.append('PTR lookup failure')
    names = sorted(candidates)[:100]
    result.update(domains=names, count=len(names), truncated=result['truncated'] or len(candidates) > 100,
                  sources={source: sum(source in candidates[name] for name in names) for source in ('crt.sh', 'rdns')},
                  assessment='unverified_name_candidates' if names else 'no_results_in_response')
    result['coverage_complete'] = not errors and not result['truncated']
    result['execution_status'] = 'completed' if result['coverage_complete'] else 'partial'
    if errors:
        result.update(error='One or more sources incomplete', errors=sorted(set(errors)))
        if not names:
            result['assessment'] = 'incomplete'
    return result


def _hostname(name):
    return len(name) <= 253 and bool(re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', name))
