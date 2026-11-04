"""Bounded, read-only Rails surface checks with content-backed observations."""
import re
import secrets
import httpx
from .surface_probe import SurfaceProbe

RAILS_PATHS = [
    '/assets/', '/rails/info', '/rails/info/routes', '/rails/info/properties',
    '/rails/mailers', '/rails/db', '/sidekiq', '/delayed_job', '/admin',
    '/admin/login', '/administrator', '/config/database.yml',
    '/config/secrets.yml', '/config/credentials.yml.enc', '/.env', '/Gemfile',
    '/Gemfile.lock', '/db/schema.rb', '/db/structure.sql', '/log/development.log',
    '/log/production.log', '/tmp/', '/public/uploads/', '/rails/console',
]


def _signature(path, text):
    """Return evidence labels, never source content or configuration values."""
    html = bool(re.search(r'<(?:html|body|!doctype\s+html)\b', text, re.I))
    if not html:
        if path == '/config/database.yml' and re.search(r'(?m)^\w+:\s*$', text) and re.search(r'(?m)^\s+adapter:\s*\w+', text) and re.search(r'(?m)^\s+database:\s*\S+', text):
            return 'database_configuration', 'MEDIUM'
        if path == '/config/secrets.yml' and re.search(r'(?m)^\w+:\s*$', text) and re.search(r'(?m)^\s+secret_key_base:\s*\S+', text):
            return 'secret_configuration', 'MEDIUM'
        if path == '/.env' and len(re.findall(r'(?m)^[A-Z_][A-Z0-9_]*=\S+', text)) >= 2 and re.search(r'(?m)^(?:RAILS_ENV|DATABASE_URL|SECRET_KEY_BASE)=', text):
            return 'environment_configuration', 'MEDIUM'
        if path == '/Gemfile' and re.search(r'(?m)^source\s+[\"\']https://rubygems.org', text) and re.search(r'(?m)^gem\s+[\"\']rails[\"\']', text):
            return 'rails_dependency_manifest', 'INFO'
        if path == '/Gemfile.lock' and re.search(r'(?m)^GEM\s*$', text) and re.search(r'(?m)^\s+rails \([\d.]+\)', text):
            return 'rails_dependency_lockfile', 'INFO'
        if path == '/db/schema.rb' and re.search(r'ActiveRecord::Schema(?:\[[\d.]+\])?\.define\(', text) and re.search(r'\bcreate_table\s+[\"\']', text):
            return 'database_schema_source', 'MEDIUM'
        if path == '/db/structure.sql' and re.search(r'(?m)^CREATE TABLE ', text) and re.search(r'(?m)^-- PostgreSQL database dump', text):
            return 'database_schema_sql', 'MEDIUM'
    if path == '/rails/info/routes' and re.search(r'<th[^>]*>\s*Prefix\s*</th>', text, re.I) and re.search(r'<th[^>]*>\s*Controller#Action\s*</th>', text, re.I):
        return 'rails_route_table', 'MEDIUM'
    return None


async def rails_scan(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    base = target.rstrip('/')
    findings, observations = [], []
    coverage = 'Read-only signature checks; no mass-assignment, console execution or credential validity testing'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=len(RAILS_PATHS)+2)
        root = await probe.request('GET', base)
        detected = bool(root is not None and re.search(r'\brails\b', root.headers.get('x-powered-by', ''), re.I))
        if detected:
            observations.append({'type':'rails_disclosure', 'risk':'INFO', 'evidence':'Rails identifier in X-Powered-By'})
        control = await probe.request('GET', base + '/.__cybersec_missing_' + secrets.token_hex(8))
        for path in RAILS_PATHS:
            if control is None or probe.stopped:
                break
            response = await probe.request('GET', base + path)
            if response is None:
                break
            if response.status_code != 200 or response.content == control.content:
                continue
            signature = _signature(path, response.text)
            if signature:
                kind, risk = signature
                findings.append({'type':kind, 'path':path, 'status':200, 'risk':risk,
                                 'confidence':'HIGH', 'evidence':kind, 'coverage':coverage,
                                 'assessment':'observed_source_or_route_exposure; sensitivity unverified'})
    return {'target':target, 'findings':findings, 'observations':observations,
            'vulnerable':any(f['risk'] != 'INFO' for f in findings),
            'framework':'Ruby on Rails', 'framework_detected':detected,
            'checks_not_performed':['mass_assignment', 'console_execution', 'encrypted_credentials_validation',
                                    'log_analysis', 'admin_access_validation'],
            'coverage':coverage, **probe.summary()}
