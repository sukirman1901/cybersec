"""Search Certificate Transparency logs for certificates."""

import httpx
import re
from .surface_probe import SurfaceProbe


async def crt_search(domain: str) -> dict:
    result = {'domain': '[invalid domain]', 'certificates': [], 'count': 0,
              'coverage_complete': False, 'assessment': 'incomplete', 'truncated': False,
              'coverage': 'At most 200 certificate rows from one response; DNS names scoped to requested domain; CT corpus completeness/freshness unverified'}
    try:
        url = httpx.URL(domain if '://' in domain else 'https://' + domain)
        domain = url.host.lower().rstrip('.')
        if url.scheme not in ('http', 'https') or url.userinfo or not _hostname(domain):
            raise ValueError('Invalid domain')
        result['domain'] = domain
        async with httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=False) as client:
            probe = SurfaceProbe(client, max_requests=1)
            resp = await probe.request('GET', 'https://crt.sh/', params={'q':'%.' + domain, 'output':'json'})
            result.update(probe.summary())
            if resp is None:
                return result
            if resp.status_code != 200:
                raise ValueError('Provider status')
            rows = resp.json()
        if not isinstance(rows, list):
            raise ValueError('Provider schema')
        seen = set()
        malformed = 0
        for entry in rows[:200]:
            if not isinstance(entry, dict) or not isinstance(entry.get('name_value'), str):
                malformed += 1
                continue
            names = sorted({name.strip().lower().rstrip('.') for name in entry['name_value'].splitlines()
                            if _in_scope(name.strip().lower().rstrip('.'), domain)})
            if not names:
                continue
            cid = entry.get('id')
            cid = cid if type(cid) is int and cid >= 0 else None
            key = (cid, tuple(names))
            if key in seen:
                continue
            seen.add(key)
            def text(field):
                value = entry.get(field, '')
                return value[:256] if isinstance(value, str) and not any(ord(c) < 32 for c in value) else ''
            result['certificates'].append({'id': cid, 'issued': text('entry_timestamp'),
                'issuer': text('issuer_name'), 'name_value': '\n'.join(names),
                'not_before': text('not_before'), 'not_after': text('not_after')})
        result.update(count=len(result['certificates']), truncated=len(rows) > 200,
                      coverage_complete=not malformed and len(rows) <= 200,
                      assessment='provider_records' if result['certificates'] else 'no_results_in_response')
        if malformed:
            result['error'] = 'Malformed certificate rows'
            if not result['certificates']:
                result['assessment'] = 'incomplete'
        result['execution_status'] = 'completed' if result['coverage_complete'] else 'partial'
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, TypeError, RecursionError) as exc:
        result.update(error=type(exc).__name__, coverage_complete=False, assessment='incomplete', execution_status='partial')
    return result


def _hostname(value):
    return len(value) <= 253 and bool(re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', value))


def _in_scope(name, domain):
    name = name[2:] if name.startswith('*.') else name
    return _hostname(name) and (name == domain or name.endswith('.' + domain))
