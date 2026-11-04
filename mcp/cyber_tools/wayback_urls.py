import httpx
import re
from .surface_probe import SurfaceProbe


async def wayback_urls(domain: str, limit: int = 100) -> dict:
    result = {'domain': '[invalid domain]', 'total': 0, 'urls': [], 'coverage_complete': False,
              'assessment': 'incomplete', 'truncated': False,
              'coverage': 'One CDX response; exact requested hostname only; URL userinfo rejected and query/fragment removed; no archive exhaustion or live URL validation'}
    try:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('Limit must be 1..1000')
        url = httpx.URL(domain if '://' in domain else 'https://' + domain)
        domain = url.host.lower().rstrip('.')
        if url.scheme not in ('http', 'https') or url.userinfo or len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
            raise ValueError('Invalid domain')
        result['domain'] = domain
        fields = ['timestamp', 'original', 'statuscode', 'contenttype']
        async with httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=False) as client:
            probe = SurfaceProbe(client, max_requests=1)
            resp = await probe.request('GET', 'https://web.archive.org/cdx/search/cdx',
                params={'url': domain + '/*', 'output':'json', 'limit':limit, 'fl':','.join(fields)})
            result.update(probe.summary())
            if resp is None:
                return result
            if resp.status_code != 200:
                raise ValueError('Provider status')
            rows = resp.json()
        if rows == []:
            rows = [fields]
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], list) or len(rows[0]) != 4 or not all(isinstance(x, str) for x in rows[0]) or set(rows[0]) != set(fields):
            raise ValueError('CDX columns')
        malformed = 0
        excluded = 0
        for row in rows[1:limit + 1]:
            if not isinstance(row, list) or len(row) != 4 or not all(isinstance(x, str) for x in row):
                malformed += 1
                continue
            item = dict(zip(rows[0], row))
            try:
                original = httpx.URL(item['original'])
            except httpx.InvalidURL:
                malformed += 1
                continue
            if original.scheme not in ('http', 'https') or original.userinfo or original.host.lower().rstrip('.') != domain:
                excluded += 1
                continue
            if not re.fullmatch(r'\d{14}', item['timestamp']) or not re.fullmatch(r'[1-5]\d{2}|-', item['statuscode']) or not re.fullmatch(r'[A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+|-', item['contenttype']):
                malformed += 1
                continue
            result['urls'].append({'timestamp':item['timestamp'],
                'url':str(original.copy_with(query=None, fragment=None)),
                'status':item['statuscode'], 'content_type':item['contenttype']})
        # A full page has no exhaustion proof; no implicit next-page requests.
        result.update(total=len(result['urls']), truncated=len(rows) - 1 >= limit,
                      excluded_rows=excluded, coverage_complete=not malformed and len(rows) - 1 < limit,
                      assessment='provider_records' if result['urls'] else 'no_results_in_response')
        if malformed:
            result['error'] = 'Malformed CDX rows'
            if not result['urls']:
                result['assessment'] = 'incomplete'
        result['execution_status'] = 'completed' if result['coverage_complete'] else 'partial'
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, TypeError, RecursionError) as exc:
        result.update(error=type(exc).__name__, coverage_complete=False, assessment='incomplete', execution_status='partial')
    return result
