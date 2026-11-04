"""Django source exposure checks; public admin pages are observations."""
import re
import httpx
from .framework_surface import inspect_paths

PATHS = ['/admin/', '/api/', '/api/v1/', '/api/v2/', '/api/auth/', '/.env',
         '/settings.py', '/manage.py', '/requirements.txt', '/static/admin/js/core.js',
         '/__debug__/', '/debug/', '/robots.txt', '/sitemap.xml']


def _classify(path, response):
    text = response.text
    if path == '/admin/' and re.search(r'<title>[^<]*Django site admin</title>', text, re.I) and re.search(r'name=[\"\']csrfmiddlewaretoken[\"\']', text):
        return 'django_admin_login', 'info', True
    if re.search(r'<(?:html|body|!doctype\s+html)\b', text, re.I):
        return None
    if path == '/settings.py' and all(re.search(r'(?m)^' + name + r'\s*=', text) for name in ('SECRET_KEY','DATABASES','INSTALLED_APPS')):
        return 'django_settings_source', 'medium', True
    if path == '/manage.py' and re.search(r'from django.core.management import execute_from_command_line', text) and 'DJANGO_SETTINGS_MODULE' in text:
        return 'django_management_source', 'medium', True
    if path == '/.env' and re.search(r'(?m)^(?:DJANGO_SETTINGS_MODULE|DJANGO_SECRET_KEY|SECRET_KEY)=\S+', text) and len(re.findall(r'(?m)^[A-Z_][A-Z0-9_]*=\S+', text)) >= 2:
        return 'environment_configuration', 'medium', False
    if path == '/requirements.txt' and re.search(r'(?im)^django\s*(?:==|>=|~=)\s*\d+(?:\.\d+)+', text):
        return 'django_dependency_manifest', 'info', True
    return None


async def django_scan(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    coverage = '14 paths plus root/control; Django source/admin signatures; no debug execution, API authorization or cookie audit'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        result = await inspect_paths(client, target.rstrip('/'), PATHS, _classify,
            lambda r: bool(re.search(r'\bdjango\b', r.headers.get('x-powered-by',''), re.I)), coverage)
    return {'target':target, 'django_detected':result['framework_detected'],
            'checks_not_performed':['debug_execution', 'api_authorization', 'cookie_audit'], **result}
