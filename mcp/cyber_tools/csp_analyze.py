"""Header-level CSP observations, not an XSS exploitability verdict."""
import re
import httpx


async def csp_analyze(target: str) -> dict:
    result = {'target': target, 'findings': [], 'count': 0, 'confidence': 'HIGH',
              'coverage': 'One anonymous GET; response headers only, no meta CSP or browser execution',
              'coverage_complete': False, 'assessment': 'inconclusive'}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(target)
    except httpx.HTTPError as exc:
        return {**result, 'error': type(exc).__name__}
    result['status_code'] = resp.status_code
    if not 200 <= resp.status_code < 300:
        return {**result, 'error': 'Non-success response; application header policy not assessed'}
    policies = resp.headers.get_list('content-security-policy')
    # Multiple enforced policies intersect. Do not turn a weak individual policy
    # into a claim about the effective policy without evaluating that intersection.
    if len(policies) > 1 or (policies and ',' in policies[0]):
        return {**result, 'policy_count': len(policies),
                'error': 'Multiple CSP policies; effective intersection not evaluated'}
    csp = policies[0] if policies else ''
    findings = result['findings']
    if csp:
        directives = {}
        for raw in csp.split(';'):
            parts = raw.split()
            if parts:
                directives.setdefault(parts[0].lower(), ' '.join(parts[1:]))
        issues = []
        for directive, value in directives.items():
            tokens = value.split()
            if directive not in {'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
                                 'style-src', 'style-src-elem', 'style-src-attr', 'img-src',
                                 'font-src', 'connect-src', 'frame-src', 'worker-src',
                                 'object-src', 'media-src', 'child-src', 'manifest-src'}:
                continue
            nonce_or_hash = any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'", t)
                                for t in tokens)
            script_or_style = directive.startswith(('script-src', 'style-src')) or directive == 'default-src'
            if script_or_style and "'unsafe-inline'" in tokens and not nonce_or_hash:
                issues.append({'directive': directive, 'issue': 'Inline source allowance weakens CSP defense in depth',
                               'severity': 'low', 'assessment': 'hardening_observation'})
            if directive in ('script-src', 'default-src') and "'unsafe-eval'" in tokens:
                issues.append({'directive': directive, 'issue': "'unsafe-eval' permits string evaluation",
                               'severity': 'low', 'assessment': 'hardening_observation'})
            if any(t in ('https:', 'http:') for t in tokens):
                issues.append({'directive': directive, 'issue': 'Broad scheme source allows arbitrary hosts',
                               'severity': 'low', 'assessment': 'hardening_observation'})
            if '*' in tokens:
                issues.append({'directive': directive, 'issue': 'Wildcard source allows arbitrary hosts',
                               'severity': 'low', 'assessment': 'hardening_observation'})
        findings.append({'csp_present': True, 'directives_count': len(directives),
                         'directives': directives, 'issues': issues, 'severity': 'info'})
    else:
        findings.append({'csp_present': False, 'severity': 'low',
                         'note': 'No enforced CSP header observed; meta CSP and XSS exploitability not assessed'})
    for header in ('X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Strict-Transport-Security'):
        value = resp.headers.get(header, '')
        protected_by_csp = header == 'X-Frame-Options' and csp and 'frame-ancestors' in directives
        findings.append({'header': header, 'value': value or 'missing',
                         'severity': 'info' if value or protected_by_csp else 'low'})
    for finding in findings:
        finding.update(confidence='HIGH', coverage=result['coverage'], assessment='observed')
    result.update(count=len(findings), coverage_complete=True, assessment='observed')
    return result
