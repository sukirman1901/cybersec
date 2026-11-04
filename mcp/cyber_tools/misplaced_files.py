"""Scan for misplaced sensitive files — signatures, certs, configs, backups."""

import json
import re
import uuid

import httpx
from .surface_probe import SurfaceProbe

SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.prod",
    "/.env.local",
    "/private_key.pem",
    "/private.pem",
    "/key.pem",
    "/cert.pem",
    "/certificate.p12",
    "/certificate.der",
    "/mobileprovision",
    "/embedded.mobileprovision",
    "/.htaccess",
    "/.htpasswd",
    "/config.json",
    "/config.php",
    "/configuration.php",
    "/database.yml",
    "/database.php",
    "/dump.sql",
    "/backup.sql",
    "/db.sql",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/WEB-INF/web.xml",
    "/WEB-INF/applicationContext.xml",
    "/.DS_Store",
    "/Thumbs.db",
    "/package.json",
    "/yarn.lock",
    "/requirements.txt",
    "/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/.well-known/security.txt",
    "/security.txt",
]


_SUPPORTED = {
    '/.git/HEAD', '/.env', '/.env.prod', '/.env.local',
    '/private_key.pem', '/private.pem', '/key.pem', '/.htpasswd',
    '/config.json', '/config.php', '/configuration.php', '/database.yml',
    '/database.php', '/dump.sql', '/backup.sql', '/db.sql', '/.DS_Store',
}


def _signature(path, response):
    """Recognize selected file structures; never export the matched contents."""
    text = response.text.strip()
    if re.search(r'<(?:!doctype\s+html|html|body|pre|code)\b', text, re.I):
        return None
    if path == '/.git/HEAD' and re.fullmatch(r'ref: refs/[A-Za-z0-9_./-]+|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', text):
        return 'Git HEAD reference'
    if path.startswith('/.env'):
        assignments = re.findall(r'(?m)^(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*[^\r\n]+$', text)
        if len(assignments) >= 2 and any(re.search(r'(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY)', key) for key in assignments):
            return 'Environment assignments with credential-like keys (values unvalidated)'
    if path.endswith('.pem') and re.fullmatch(r'-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----\s+[A-Za-z0-9+/=\s]{32,}\s+-----END \1-----', text):
        return 'PEM private-key envelope (cryptographic validity untested)'
    if path == '/.htpasswd' and re.search(r'(?m)^[A-Za-z0-9_.@-]+:\$(?:apr1\$[^:\s]+|2[aby]\$\d{2}\$[./A-Za-z0-9]{53})$', text):
        return 'Password-file hash record'
    if path.endswith('.php') and text.startswith('<?php') and re.search(r'\$[\w]*(?:password|passwd|secret)[\w]*\s*=\s*[\'"][^\r\n]+[\'"]\s*;', text, re.I):
        return 'PHP configuration assignment (credential validity untested)'
    if path == '/config.json':
        try:
            value = json.loads(text)
        except (ValueError, RecursionError):
            return None
        # Bounded, iterative traversal; no raw keys or values leave this parser.
        pending = [value] if isinstance(value, dict) else []
        for _ in range(1000):
            if not pending:
                break
            item = pending.pop()
            for key, val in item.items():
                if re.fullmatch(r'(?:password|passwd|secret|api_key|private_key|access_token)', key, re.I) and isinstance(val, str) and val.strip():
                    return 'JSON configuration with credential-like keys (values unvalidated)'
                if isinstance(val, dict):
                    pending.append(val)
    if path == '/database.yml' and re.search(r'(?m)^\w+:\s*$', text) and re.search(r'(?m)^\s+(?:adapter|database):\s*\S+', text) and re.search(r'(?m)^\s+password:\s*\S+', text):
        return 'Database YAML structure with password field (value unvalidated)'
    if path.endswith('.sql') and re.search(r'(?im)^\s*CREATE TABLE\s+[`"\w]', text) and re.search(r'(?im)^\s*(?:INSERT INTO\s+|--\s*(?:MySQL|PostgreSQL|SQLite).*dump)', text):
        return 'SQL table/dump structure'
    if path == '/.DS_Store' and response.content.startswith(b'\x00\x00\x00\x01Bud1'):
        return 'DS_Store header (contents not parsed)'
    return None


async def misplaced_files(target: str) -> dict:
    results = []
    checked = 0
    paths = [path for path in SENSITIVE_PATHS if path in _SUPPORTED]
    unsupported = [path for path in SENSITIVE_PATHS if path not in _SUPPORTED]
    coverage = 'Selected file-structure recognition only; credentials/keys not validated; public documents and unsupported binary/config formats not assessed'
    try:
        url = httpx.URL(target)
        if url.scheme not in ('http', 'https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        base = str(url.copy_with(query=None, fragment=None)).rstrip('/')
    except (httpx.InvalidURL, ValueError):
        return {'target': '[invalid target]', 'paths_checked': 0, 'exposed_files': 0,
                'findings': [], 'risk': 'INCONCLUSIVE', 'coverage_complete': False,
                'requests_attempted': 0, 'error': 'Invalid HTTP target'}
    async with httpx.AsyncClient(timeout=5.0, verify=False, trust_env=False) as client:
        probe = SurfaceProbe(client, max_requests=len(paths) + 1)
        control = await probe.request('GET', base + '/.missing-' + uuid.uuid4().hex)
        if control is not None:
            for path in paths:
                response = await probe.request('GET', base + path)
                if response is None:
                    break
                checked += 1
                if response.status_code != 200 or response.content == control.content:
                    continue
                signature = _signature(path, response)
                if signature:
                    results.append({'path': path, 'status': 200, 'size': len(response.content),
                                    'evidence': signature, 'confidence': 'MEDIUM', 'severity': 'medium',
                                    'assessment': 'recognized_file_structure', 'coverage': coverage})
    summary = probe.summary()
    return {'target': base, 'paths_checked': checked, 'exposed_files': len(results),
            'findings': results, 'risk': 'REVIEW' if results else 'NO_EVIDENCE',
            'coverage': coverage, 'unsupported_paths': unsupported,
            'supported_paths_complete': summary['coverage_complete'],
            **summary, 'coverage_complete': False}
