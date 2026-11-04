import httpx
import ipaddress
import re
from .surface_probe import SurfaceProbe


async def shodan_lookup(query: str, api_key: str = "") -> dict:
    result = {'query': '[redacted]', 'total': 0, 'results': [], 'coverage_complete': False,
              'assessment': 'incomplete', 'truncated': False, 'scope_authorized': False, 'query_scope_verified': False,
              'coverage': 'At most 20 matches from one provider response; query semantics and hostname/IP association not independently verified; results do not extend authorized scope'}
    if not api_key:
        return {**result, 'error': 'Shodan API key not provided'}
    try:
        if not isinstance(query, str) or not query.strip() or len(query) > 2048 or not isinstance(api_key, str):
            raise ValueError('Invalid query/key')
        async with httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=False) as client:
            probe = SurfaceProbe(client, max_requests=1)
            resp = await probe.request('GET', 'https://api.shodan.io/shodan/host/search', params={'key':api_key, 'query':query})
            result.update(probe.summary())
            if resp is None:
                return result
            if resp.status_code != 200:
                raise ValueError('Provider status')
            data = resp.json()
        if not isinstance(data, dict) or not isinstance(data.get('matches'), list) or type(data.get('total')) is not int or data['total'] < 0:
            raise ValueError('Provider schema')
        malformed = 0
        nested_truncated = False
        for match in data['matches'][:20]:
            if not isinstance(match, dict):
                malformed += 1
                continue
            try:
                ip = str(ipaddress.ip_address(match.get('ip_str')))
            except ValueError:
                malformed += 1
                continue
            port = match.get('port')
            if type(port) is not int or not 0 < port <= 65535:
                malformed += 1
                continue
            names = match.get('hostnames', [])
            vulns = match.get('vulns', [])
            if not isinstance(names, list) or not isinstance(vulns, (dict, list)):
                malformed += 1
                continue
            nested_truncated = nested_truncated or len(names) > 100 or len(vulns) > 100
            def text(field):
                value = match.get(field)
                return value.replace(api_key, '[redacted]')[:256] if isinstance(value, str) else None
            hostnames = sorted({name.lower().rstrip('.') for name in names[:100]
                if isinstance(name, str) and api_key not in name and len(name) <= 253
                and re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?', name)})
            cves = sorted({cve for cve in list(vulns)[:100] if isinstance(cve, str) and re.fullmatch(r'CVE-\d{4}-\d{4,}', cve)})
            result['results'].append({'ip':ip, 'port':port, 'org':text('org'), 'hostnames':hostnames,
                'product':text('product'), 'version':text('version'), 'cve':cves})
        total = data['total']
        inconsistent = total < len(data['matches']) or (total > 0 and not data['matches'])
        truncated = nested_truncated or len(data['matches']) > 20 or total > len(data['matches'])
        result.update(total=total, truncated=truncated,
                      coverage_complete=not malformed and not truncated and not inconsistent,
                      assessment='provider_records' if result['results'] else 'no_results_in_response')
        if malformed or inconsistent:
            result['error'] = 'Malformed or inconsistent provider records'
            if not result['results']:
                result['assessment'] = 'incomplete'
        result['execution_status'] = 'completed' if result['coverage_complete'] else 'partial'
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, TypeError, RecursionError) as exc:
        result.update(error=type(exc).__name__, coverage_complete=False, assessment='incomplete', execution_status='partial')
    return result
