"""Bounded DNS address candidates; neither CT nor DNS proves a CDN origin."""
import asyncio
import ipaddress
import re
import socket
import time

import httpx
from .surface_probe import SurfaceProbe


async def origin_ip_discovery(target: str) -> dict:
    result = {'target':'[invalid target]', 'ip_addresses':[], 'sources':{}, 'count':0,
              'origin_verified':False, 'scope_authorized':False, 'coverage_complete':False,
              'unsupported_detection':['ct_ip_mapping','CDN bypass','origin verification','historical DNS resolution'],
              'coverage':'A records for requested host and six fixed labels only; CT names are historical observations, not IP mappings; DNS addresses may be CDN edges'}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        domain = url.host.lower().rstrip('.')
        if url.scheme not in ('http','https') or url.userinfo or len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?',domain):
            raise ValueError('Invalid domain')
    except (httpx.InvalidURL, ValueError, TypeError):
        return {**result, 'error':'Invalid HTTP domain'}
    result['target'] = domain
    deadline, errors, sources = time.monotonic() + 15, [], {}
    checked = 0
    for host in [domain] + [prefix + '.' + domain for prefix in ('direct','origin','origin-','direct-','backend','lb')]:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            checked += 1
            ip = str(ipaddress.IPv4Address(await asyncio.wait_for(asyncio.to_thread(socket.gethostbyname, host), timeout=min(2, remaining))))
            sources.setdefault(ip, set()).add('dns_a_record' if host == domain else 'origin_subdomains')
        except socket.gaierror as exc:
            if exc.errno not in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', socket.EAI_NONAME)):
                errors.append('DNS lookup failure')
        except (OSError, ValueError, asyncio.TimeoutError):
            errors.append('DNS lookup incomplete')
            break
    names = set()
    async with httpx.AsyncClient(timeout=3.0, trust_env=False, follow_redirects=False) as client:
        probe = SurfaceProbe(client, seconds=max(0, deadline-time.monotonic()), max_requests=1)
        response = await probe.request('GET','https://crt.sh/', params={'q':domain,'output':'json'})
        if response is None:
            errors.extend(probe.errors)
        else:
            try:
                rows = response.json()
                if response.status_code != 200 or not isinstance(rows, list):
                    raise ValueError('Provider schema/status')
                result['truncated'] = len(rows) > 50
                for row in rows[:50]:
                    if not isinstance(row, dict) or not isinstance(row.get('name_value'), str):
                        errors.append('Malformed CT row')
                        continue
                    # crt.sh's search schema does not attest an `ip` field.
                    # Retain only exact-domain certificate observation, no new DNS expansion.
                    if domain in {name.strip().lower().rstrip('.') for name in row['name_value'].splitlines()}:
                        names.add(domain)
            except (ValueError, TypeError, RecursionError):
                errors.append('Malformed CT response')
    result.update(ip_addresses=sorted(sources), count=len(sources),
                  sources={source:[ip for ip in sorted(sources) if source in sources[ip]] for source in ('dns_a_record','origin_subdomains')},
                  certificate_name_observed=bool(names), dns_requests=checked, requests_attempted=probe.requests,
                  selected_checks_complete=not errors and checked==7 and not result.get('truncated',False),
                  assessment='unverified_ip_candidates' if sources else ('incomplete' if errors else 'no_candidates_in_selected_checks'),
                  execution_status='partial')
    if errors:
        result.update(error='One or more sources incomplete', errors=sorted(set(errors)))
    return result
