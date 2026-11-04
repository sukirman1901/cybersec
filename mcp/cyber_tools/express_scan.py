"""Content-backed Express surface observations, without status-only findings."""
import re
import httpx
from .framework_surface import inspect_paths

EXPRESS_PATHS = ['/debug', '/_debug', '/console', '/dev', '/.env', '/routes',
                 '/api/routes', '/api-docs', '/swagger.json', '/sitemap.xml',
                 '/robots.txt', '/package.json', '/.git/HEAD']
PATHS = ['/%s', '/..%2f', '/admin%00', '/node_modules/', '/static/', '/public/', '/assets/'] + EXPRESS_PATHS


def _classify(path, response):
    text = response.text
    html = bool(re.search(r'<(?:html|body|!doctype\s+html)\b', text, re.I))
    if not html and path == '/.env' and re.search(r'(?m)^(?:NODE_ENV|DATABASE_URL|DB_PASSWORD)=\S+', text) and len(re.findall(r'(?m)^[A-Z_][A-Z0-9_]*=\S+', text)) >= 2:
        return 'environment_configuration', 'medium', False
    if path == '/.git/HEAD' and re.fullmatch(r'ref: refs/heads/[\w./-]+\s*', text):
        return 'git_head_exposure', 'medium', False
    if path == '/package.json':
        try:
            data = response.json()
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get('name'), str) and isinstance(data.get('dependencies'), dict):
            return 'package_manifest', 'info', 'express' in data['dependencies']
    if path in ('/%s', '/..%2f', '/admin%00') and re.search(r'(?m)^(?:TypeError|ReferenceError|Error):[^\n]+', text) and re.search(r'(?m)^\s+at [^\n]*[/:][^\n]*:\d+:\d+\)?\s*$', text):
        return 'javascript_stack_disclosure', 'medium', False
    if path in ('/node_modules/', '/static/', '/public/', '/assets/') and re.search(r'<(?:title|h1)>\s*Index of /[^<]*</(?:title|h1)>', text, re.I) and re.search(r'<a\s[^>]*href=[\"\']\.\./[\"\']', text, re.I):
        return 'directory_listing', 'medium', False
    return None


async def express_scan(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    coverage = '20 GET paths plus root/control; env/git/package/stack/listing signatures; no console execution or API authorization; 5xx responses remain incomplete'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        result = await inspect_paths(client, target.rstrip('/'), PATHS, _classify,
            lambda r: r.headers.get('x-powered-by','').strip().lower() == 'express', coverage)
    return {'target':target, 'framework':'Express.js', **result}
