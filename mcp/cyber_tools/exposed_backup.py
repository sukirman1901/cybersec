import httpx
import re
import secrets
from .surface_probe import SurfaceProbe

EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".swp", ".swo",
    "~", ".save", ".save.1", ".local", ".private", ".default",
    ".sql", ".dump", ".csv", ".tar", ".zip", ".gz", ".7z", ".rar",
]

BASE_FILES = [
    "index.php", "index.html", "index.js", "config.php", "config.json",
    "config.yaml", "config.local.php", "database.php", "db.php",
    ".env", ".env.local", ".env.production", ".env.development",
    "wp-config.php", "wp-config", "settings.php", "settings",
    "app.php", "app.conf", "nginx.conf", ".htaccess",
    "composer.json", "package.json", "yarn.lock", "package-lock.json",
    "dump.sql", "backup.sql", "export.sql",
]


async def exposed_backup(target: str) -> dict:
    findings = []
    if not target.startswith(('http://','https://')):
        target = 'https://' + target
    base = target.rstrip('/')
    priority = ['.env', 'config.php', 'wp-config.php', 'database.php', 'dump.sql', 'config.json']
    files = priority + [f for f in BASE_FILES if f not in priority]
    preferred = ['/' + f + ext for ext in ('.bak', '.backup', '.old', '~') for f in priority]
    candidates = list(dict.fromkeys(preferred + ['/' + f + ext for ext in EXTENSIONS for f in files]))
    selected = candidates[:24]
    checked = 0
    coverage = '24 prioritized backup paths plus soft-404 control; recognized env/PHP/SQL/config/archive signatures only; remaining paths deferred'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=25)
        control = await probe.request('GET', base + '/.__cybersec_missing_' + secrets.token_hex(8))
        for path in selected:
            if control is None or probe.stopped:
                break
            response = await probe.request('GET', base + path)
            checked += 1
            if response is None:
                break
            if response.status_code != 200 or response.content == control.content:
                continue
            body, text = response.content, response.text
            signature = None
            if re.search(r'<(?:!doctype\s+html|html|body)\b', text, re.I):
                continue
            if re.search(r'(?m)^(?:APP_ENV|APP_KEY|DB_HOST|DB_PASSWORD|DATABASE_URL)\s*=\s*\S+', text) and len(re.findall(r'(?m)^[A-Z_][A-Z0-9_]*\s*=', text)) >= 2:
                signature = 'Environment assignment structure'
            elif '<?php' in text and re.search(r'(?:define\s*\(|\$[A-Za-z_][A-Za-z0-9_]*\s*=)', text):
                signature = 'Unexecuted PHP configuration source'
            elif re.search(r'(?im)^CREATE TABLE\s', text) and re.search(r'(?im)^(?:INSERT INTO|-- (?:MySQL|PostgreSQL))\s', text):
                signature = 'SQL dump structure'
            elif body.startswith((b'PK\x03\x04', b'\x1f\x8b\x08', b'7z\xbc\xaf\x27\x1c', b'Rar!\x1a\x07')):
                signature = 'Archive signature; contents not inspected'
            elif 'config.json' in path:
                try:
                    data = response.json()
                except ValueError:
                    data = None
                if isinstance(data, dict) and {'database','connectionStrings','db','credentials'} & data.keys():
                    signature = 'Configuration object structure; values omitted'
            if signature:
                findings.append({'path':path, 'target':base+path, 'status':200, 'size':len(body),
                                 'severity':'medium', 'confidence':'HIGH', 'evidence':signature,
                                 'assessment':'observed_file_exposure; sensitivity unverified', 'coverage':coverage})
    deferred = len(candidates)-checked
    if deferred:
        probe.errors.append('candidate_coverage_deferred')
    return {'target':target, 'findings':findings, 'backup_exposed':bool(findings), 'count':len(findings),
            'candidates_total':len(candidates), 'candidates_checked':checked, 'candidates_deferred':deferred,
            'coverage':coverage, **probe.summary()}
