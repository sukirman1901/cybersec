"""Bounded header product hints; no WAF enforcement or bypass attestation."""

import re
import httpx
from .http_guard import GuardedClient, guarded_urlopen  # legacy transport import compatibility

WAF_SIGNATURES = {
    "Cloudflare": [r"cloudflare", r"__cfduid", r"cf-ray"],
    "ModSecurity": [r"ModSecurity", r"NOYB"],
    "AWS WAF": [r"awselb", r"AWS"],
    "Akamai": [r"akamai", r"akamaid"],
    "Sucuri": [r"Sucuri", r"cloudproxy"],
    "Barracuda": [r"barracuda", r"BarracudaNet"],
    "F5 BIG-IP": [r"BigIP", r"F5"],
    "Imperva": [r"incapsula", r"Imperva"],
}

_SERVER_HINTS = {
    'ModSecurity': r'^modsecurity(?:[/\s]|$)',
    'Sucuri': r'^sucuri(?:[/\s-]|$)|^cloudproxy(?:[/\s]|$)',
    'Barracuda': r'^barracuda(?:net)?(?:[/\s-]|$)',
    'Imperva': r'^(?:imperva|incapsula)(?:[/\s-]|$)',
}
_EDGE_HINTS = {
    'Cloudflare': r'^cloudflare(?:[/\s]|$)',
    'Akamai': r'^akamaighost(?:[/\s]|$)',
    'AWS ELB': r'^awselb(?:[/\s]|$)',
    'F5 BIG-IP': r'^bigip(?:[/\s]|$)',
}


def waf_detect(target: str) -> dict:
    """Single streamed GET; only selected header hints, no response body reads.

    waf_detected means a WAF-product hint, never demonstrated enforcement.
    CDN/load-balancer hints are observations only. Legacy signature vocabulary is
    retained above for callers, but is not searched in arbitrary header/body text.
    """
    result = {'target': '[invalid target]', 'waf_detected': False, 'waf_name': None,
              'signatures_found': [], 'error': None, 'waf_confirmed': False,
              'observations': [], 'assessment': 'no_product_hint', 'confidence': 'LOW',
              'requests_attempted': 0, 'coverage_complete': False,
              'coverage': 'One response header snapshot; no body reads, challenges, enforcement or bypass testing',
              'unsupported_detection': ['body/challenge signatures', 'WAF enforcement', 'hidden WAF', 'bypass testing'],
              'execution_status': 'partial'}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        if url.scheme not in ('http', 'https') or not url.host or url.userinfo:
            raise ValueError('Invalid HTTP target')
        result['target'] = str(url.copy_with(query=None, fragment=None))
        with GuardedClient(timeout=5.0, verify=False, trust_env=False, follow_redirects=False) as client:
            result['requests_attempted'] = 1
            with client.stream('GET', url, headers={'User-Agent': 'Mozilla/5.0'}, follow_redirects=False) as response:
                result['status'] = response.status_code
                # Do not consume an arbitrarily large body just to inspect headers.
                if response.status_code != 200:
                    result['error'] = 'Non-success response; header assessment incomplete'
                    return result
                if sum(len(k) + len(v) for k, v in response.headers.raw) > 16384:
                    result['error'] = 'Header inspection limit exceeded'
                    return result
                server = response.headers.get('server', '').strip()
                hints = [name for name, pattern in _SERVER_HINTS.items() if re.search(pattern, server, re.I)]
                if 'x-sucuri-id' in response.headers or 'x-sucuri-block' in response.headers:
                    hints.append('Sucuri')
                for name, pattern in _EDGE_HINTS.items():
                    if re.search(pattern, server, re.I):
                        result['observations'].append({'product': name, 'evidence': 'Server product token',
                                                        'assessment': 'edge_hint_not_waf_proof',
                                                        'confidence': 'MEDIUM', 'coverage': result['coverage']})
                if hints:
                    result.update(waf_detected=True, waf_name=hints[0],
                                   signatures_found=sorted(set(hints)), assessment='product_hint_only', confidence='MEDIUM')
                result['coverage_complete'] = True  # selected header snapshot only
                result['execution_status'] = 'completed'
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, TypeError) as exc:
        result['error'] = type(exc).__name__  # exception messages may contain URLs/secrets
    return result
