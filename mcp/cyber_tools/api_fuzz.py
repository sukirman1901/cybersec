"""Bounded API/document discovery; endpoint visibility is not a vulnerability."""
import re
import secrets
import httpx
from .surface_probe import SurfaceProbe

PATHS = ['/api', '/api/v1', '/api/v2', '/swagger', '/swagger.json', '/openapi.json',
         '/docs', '/redoc', '/graphql', '/graphiql', '/health', '/readyz', '/ping',
         '/status', '/metrics', '/prometheus', '/.well-known',
         '/.well-known/security.txt', '/robots.txt', '/sitemap.xml']


async def api_fuzz(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    base = target.rstrip('/')
    found = []
    coverage = '20 public paths plus soft-404 control; signature-backed observations, no auth or exploit testing'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=len(PATHS)+1)
        control = await probe.request('GET', base + '/.__cybersec_missing_' + secrets.token_hex(8))
        for path in PATHS:
            if control is None or probe.stopped:
                break
            response = await probe.request('GET', base + path)
            if response is None:
                break
            if response.status_code != 200 or response.content == control.content:
                continue
            text = response.text
            kind = None
            try:
                data = response.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and isinstance(data.get('paths'), dict) and isinstance(data.get('info'), dict) and (
                    isinstance(data.get('openapi'), str) and data['openapi'].startswith('3.') or data.get('swagger') == '2.0'):
                kind = 'api_schema'
            elif path in ('/swagger', '/docs', '/redoc') and re.search(r'<(?:script|redoc)\b[^>]*(?:swagger-ui|redoc)', text, re.I):
                kind = 'api_documentation_ui'
            elif path in ('/metrics', '/prometheus') and re.search(r'(?m)^# TYPE [A-Za-z_:][A-Za-z0-9_:]* (?:counter|gauge|histogram|summary|untyped)\s*$', text):
                kind = 'prometheus_metrics'
            elif path == '/.well-known/security.txt' and re.search(r'(?m)^Contact:\s*(?:mailto:|https://)', text):
                kind = 'security_contact'
            elif path == '/robots.txt' and re.search(r'(?im)^User-agent:\s*\S+', text):
                kind = 'robots_policy'
            elif path == '/sitemap.xml' and re.search(r'<(?:urlset|sitemapindex)\b[^>]*xmlns=[\"\']http://www.sitemaps.org/schemas/sitemap/0.9', text):
                kind = 'sitemap'
            elif path in ('/api', '/api/v1', '/api/v2', '/health', '/readyz', '/status') and isinstance(data, (dict, list)) and data:
                if not isinstance(data, dict) or not ({'error','errors','message'} & data.keys()):
                    kind = 'json_endpoint_candidate'
            if kind:
                found.append({'path':path, 'status':response.status_code, 'content_type':response.headers.get('content-type',''),
                              'size':len(response.content), 'kind':kind, 'assessment':'observed_not_vulnerability',
                              'confidence':'MEDIUM' if kind.endswith('candidate') else 'HIGH', 'coverage':coverage})
    return {'target':target, 'found':found, 'count':len(found), 'coverage':coverage, **probe.summary()}
