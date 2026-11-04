"""Bounded provider name candidates and selected DNS guesses, never scope grants."""
import asyncio
import ipaddress
import re
import socket
import time
import uuid
from typing import Dict

import httpx
from .surface_probe import SurfaceProbe

_COMMON = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'dns', 'mx', 'exchange', 'vpn', 'remote', 'admin', 'portal', 'api', 'dev',
    'development', 'staging', 'test', 'testing', 'beta', 'alpha', 'demo', 'sandbox',
    'app', 'apps', 'mobile', 'm', 'blog', 'news', 'shop', 'store', 'secure', 'cdn',
    'static', 'assets', 'img', 'images', 'media', 'docs', 'doc', 'help', 'support',
    'status', 'login', 'signin', 'sso', 'auth', 'dashboard', 'panel', 'cpanel',
    'webmin', 'git', 'gitlab', 'svn', 'jenkins', 'ci', 'cd', 'build', 'db',
    'database', 'mysql', 'postgres', 'mongo', 'redis', 'cloud', 'aws', 'azure',
    'gcp', 'intranet', 'internal', 'private', 'corp', 'office', 'old', 'new',
    'legacy', 'backup',
]


def _hostname(name):
    return isinstance(name, str) and len(name) <= 253 and bool(re.fullmatch(
        r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', name))


async def enumerate_subdomains(target: str) -> Dict:
    """One response per provider, 24 DNS guesses plus two wildcard controls."""
    result = {'domain':'[invalid domain]', 'subdomains':[], 'count':0, 'sources':{},
              'sources_status':{}, 'scope_authorized':False, 'coverage_complete':False,
              'truncated':False, 'wildcard_dns':False, 'dns_candidates_deferred':len(_COMMON),
              'coverage':'Provider/DNS name candidates only; 200 rows per provider and 200 total names; first 24 of 80 DNS guesses; historical data and discoveries do not authorize targets'}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        domain = url.host.lower().rstrip('.')
        if url.scheme not in ('http', 'https') or url.userinfo or not _hostname(domain):
            raise ValueError('Invalid domain')
    except (httpx.InvalidURL, ValueError, TypeError):
        return {**result, 'error':'Invalid HTTP domain'}
    result['domain'] = domain
    deadline = time.monotonic() + 15
    names, errors = {}, []
    def add(name, source):
        if not isinstance(name, str):
            errors.append('Malformed provider name')
            return
        name = name.lower().strip().rstrip('.')
        if _hostname(name) and (name == domain or name.endswith('.' + domain)):
            if len(names) < 200 or name in names:
                names.setdefault(name, set()).add(source)
            else:
                result['truncated'] = True

    providers = [('crt.sh','https://crt.sh/', {'q':'%.' + domain, 'output':'json'}),
                 ('hackertarget','https://api.hackertarget.com/hostsearch/', {'q':domain}),
                 ('threatcrowd','https://www.threatcrowd.org/searchApi/v2/domain/report/', {'domain':domain})]
    async with httpx.AsyncClient(timeout=3.0, trust_env=False, follow_redirects=False) as client:
        probe = SurfaceProbe(client, seconds=15, max_requests=3)
        for source, endpoint, params in providers:
            if probe.stopped:
                result['sources_status'][source] = 'not_attempted'
                continue
            before = len(errors)
            response = await probe.request('GET', endpoint, params=params)
            if response is None:
                errors.extend(probe.errors)
            else:
                try:
                    if response.status_code != 200:
                        raise ValueError('Provider HTTP status')
                    if source == 'crt.sh':
                        rows = response.json()
                        if not isinstance(rows, list):
                            raise ValueError('CT schema')
                        if len(rows) > 200:
                            result['truncated'] = True
                        for row in rows[:200]:
                            if not isinstance(row, dict) or not isinstance(row.get('name_value'), str):
                                errors.append('Malformed CT row')
                                continue
                            for name in row['name_value'].splitlines()[:200]:
                                add(name, source)
                            if len(row['name_value'].splitlines()) > 200:
                                result['truncated'] = True
                    elif source == 'hackertarget':
                        rows = response.text.splitlines()
                        if len(rows) > 200:
                            result['truncated'] = True
                        for row in rows[:200]:
                            if not row.strip():
                                continue
                            fields = row.split(',')
                            if len(fields) != 2:
                                errors.append('Malformed hostsearch response')
                                continue
                            ipaddress.ip_address(fields[1].strip())
                            add(fields[0], source)
                    else:
                        data = response.json()
                        if not isinstance(data, dict) or str(data.get('response_code')) != '1' or not isinstance(data.get('subdomains'), list):
                            raise ValueError('Threatcrowd schema/status')
                        rows = data['subdomains']
                        if len(rows) > 200:
                            result['truncated'] = True
                        for name in rows[:200]:
                            add(name, source)
                except (ValueError, TypeError, RecursionError):
                    errors.append('Malformed provider response')
            result['sources_status'][source] = 'incomplete' if len(errors) > before else 'response_parsed'

    checked, dns_requests = 0, 0
    async def resolve(name):
        nonlocal dns_requests
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        dns_requests += 1
        try:
            value = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyname, name), timeout=min(2, remaining))
            return str(ipaddress.IPv4Address(value))
        except socket.gaierror as exc:
            if exc.errno in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', socket.EAI_NONAME)):
                return None
            raise
    if not probe.stopped:
        try:
            controls = [await resolve('missing-' + uuid.uuid4().hex + '.' + domain) for _ in range(2)]
            result['wildcard_dns'] = any(controls)
            if not result['wildcard_dns']:
                for prefix in _COMMON[:24]:
                    value = await resolve(prefix + '.' + domain)
                    checked += 1
                    if value:
                        add(prefix + '.' + domain, 'dns_bruteforce')
            result['sources_status']['dns_bruteforce'] = 'wildcard_inconclusive' if any(controls) else 'selected_guesses_checked'
        except (OSError, ValueError, asyncio.TimeoutError):
            errors.append('DNS lookup incomplete')
            result['sources_status']['dns_bruteforce'] = 'incomplete'
    else:
        result['sources_status']['dns_bruteforce'] = 'not_attempted'
    result.update(subdomains=sorted(names), count=len(names), requests_attempted=probe.requests,
                  dns_requests=dns_requests, dns_candidates_deferred=len(_COMMON)-checked,
                  sources={source:sum(source in found for found in names.values()) for source in ('crt.sh','hackertarget','threatcrowd','dns_bruteforce')},
                  selected_sources_complete=not errors and not result['truncated'] and not result['wildcard_dns'],
                  assessment='unverified_name_candidates' if names else ('incomplete' if errors else 'no_candidates_in_selected_checks'),
                  execution_status='partial')
    if errors:
        result.update(error='One or more discovery sources incomplete', errors=sorted(set(errors)))
    return result
