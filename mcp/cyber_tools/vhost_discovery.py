import asyncio
from html.parser import HTMLParser
import re

import httpx

TOTAL_TIMEOUT = 20.0
MAX_REQUESTS = 55
MAX_BODY = 65536
MAX_TOTAL_BODY = 1048576
MAX_RESULTS = 20


class _Identity(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hosts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'link' and 'canonical' in (attrs.get('rel') or '').lower().split():
            try:
                url = httpx.URL(attrs.get('href') or '')
                if url.scheme in ('http', 'https') and not url.userinfo:
                    self.hosts.append(url.host)
            except (ValueError, httpx.InvalidURL):
                pass

COMMON_VHOSTS = [
    "admin", "www", "mail", "webmail", "cpanel", "cp", "whm", "support",
    "dev", "api", "stage", "staging", "test", "beta", "alpha",
    "app", "my", "portal", "login", "sso", "auth",
    "blog", "shop", "forum", "wiki", "docs", "help",
    "git", "jenkins", "jira", "confluence", "wiki",
    "monitor", "status", "stats", "analytics",
    "cdn", "static", "assets", "media", "files",
    "backup", "intranet", "internal", "hr", "payroll",
    "vpn", "remote", "cloud", "exchange",
    "wordpress", "wp", "joomla", "drupal",
]

async def vhost_discovery(target: str) -> dict:
    result = {'vhosts_tested': 0, 'discovered': [], 'count': 0, 'requests': 0,
              'complete': False, 'confidence': 'unknown',
              'coverage': 'Existing Host-header candidates only; no DNS checks or discovered-host requests.',
              'note': 'Candidates are not confirmed virtual hosts and do not authorize further testing.'}
    try:
        parsed = httpx.URL(target)
        domain = parsed.host
        if (parsed.scheme not in ('http', 'https') or parsed.userinfo
                or not domain or len(domain) > 253
                or not re.fullmatch(r'[a-zA-Z0-9.-]+', domain)):
            raise ValueError
        base = str(parsed.copy_with(path='', query=None, fragment=None))
    except (ValueError, TypeError, httpx.InvalidURL):
        return {**result, 'error': 'Invalid HTTP target'}
    result['target'] = domain
    total_bytes = 0
    ambiguous = False
    baseline = None
    hosts = [domain] + [f'{prefix}.{domain}' for prefix in dict.fromkeys(COMMON_VHOSTS)]
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, trust_env=False) as client:
                for index, host in enumerate(hosts):
                    if result['requests'] >= MAX_REQUESTS or len(result['discovered']) >= MAX_RESULTS or total_bytes >= MAX_TOTAL_BODY:
                        return {**result, 'error': 'Aggregate budget reached'}
                    result['requests'] += 1
                    if index:
                        result['vhosts_tested'] += 1
                    headers = {'Accept-Encoding': 'identity'}
                    if index:
                        headers['Host'] = host
                    async with client.stream('GET', base, headers=headers) as resp:
                        status = resp.status_code
                        if status == 429 or status >= 500:
                            return {**result, 'error': 'Rate limit or server failure'}
                        if resp.headers.get('content-encoding', 'identity').lower() != 'identity':
                            return {**result, 'error': 'Encoded response not inspected'}
                        body = bytearray()
                        async for chunk in resp.aiter_bytes():
                            if len(body) + len(chunk) > MAX_BODY or total_bytes + len(chunk) > MAX_TOTAL_BODY:
                                return {**result, 'error': 'Body budget exceeded'}
                            body.extend(chunk)
                            total_bytes += len(chunk)
                    text = body.decode('utf-8', errors='strict')
                    normalized = text.lower().replace(host.lower(), '[host]')
                    if index == 0:
                        baseline = normalized
                        if status not in (200, 404, 410):
                            return {**result, 'error': 'Baseline inconclusive'}
                        if status == 200 and (not text or re.search(r'not\s+found|\b404\b|no\s+such\s+(?:host|site)|access\s+denied', text, re.I)):
                            ambiguous = True
                        continue
                    if status in (404, 410):
                        continue
                    if status != 200 or not text or normalized == baseline or re.search(r'not\s+found|\b404\b|no\s+such\s+(?:host|site)|access\s+denied', text, re.I):
                        ambiguous = True
                        continue
                    identity = _Identity()
                    identity.feed(text)
                    if identity.hosts != [host]:
                        ambiguous = True
                        continue
                    result['discovered'].append({'vhost': host, 'status': status, 'size': len(body),
                                                 'title': '[withheld]', 'different_from_baseline': True,
                                                 'confidence': 'medium', 'classification': 'candidate',
                                                 'authorized': False,
                                                 'evidence': 'Distinct response with matching canonical host'})
                    result['count'] = len(result['discovered'])
    except (httpx.HTTPError, TimeoutError, UnicodeError, ValueError):
        return {**result, 'error': 'Request failed, malformed response, or time budget exceeded'}
    result['complete'] = not ambiguous
    result['confidence'] = 'medium' if result['count'] else 'unknown'
    return result
