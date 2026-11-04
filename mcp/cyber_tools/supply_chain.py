import httpx
import re
import json
import asyncio
from urllib.parse import urlsplit

KNOWN_VULN_PACKAGES = {
    "lodash": {"max": "4.17.20", "cve": "CVE-2021-23337"},
    "axios": {"max": "0.21.1", "cve": "CVE-2021-3749"},
    "express": {"max": "4.17.1", "cve": "CVE-2022-24999"},
    "guzzlehttp/guzzle": {"max": "6.5.5", "cve": "CVE-2022-29248"},
    "laravel/framework": {"max": "8.83.0", "cve": "CVE-2022-31279"},
    "symfony/http-kernel": {"max": "5.4.12", "cve": "CVE-2022-24894"},
    "django": {"max": "3.2.14", "cve": "CVE-2022-36359"},
    "requests": {"max": "2.28.1", "cve": "CVE-2023-32681"},
    "jinja2": {"max": "3.1.2", "cve": "CVE-2024-22195"},
    "flask": {"max": "2.3.2", "cve": "CVE-2023-30861"},
}

MANIFEST_PATHS = [
    ("package.json", "node_modules|dependencies", r'"(.*?)":\s*"\^?(\d+\.\d+\.\d+)"'),
    ("composer.json", "require|packages", r'"(.*?)":\s*"\^?(\d+\.\d+\.\d+)"'),
    ("requirements.txt", "", r'^([a-zA-Z_][a-zA-Z0-9_-]*)[=~><]+(\d+\.\d+\.?\d*)'),
    ("go.mod", "require", r'(\S+)\s+v(\d+\.\d+\.\d+)'),
    ("Gemfile", "gem", r"gem ['\"](\S+)['\"],\s*['\"]~?>\s*(\d+\.\d+\.?\d*)"),
    ("build.gradle", "implementation", r"implementation\s+['\"](.*?):(.*?):(\d+\.\d+\.?\d*)"),
]


MAX_BODY = 1024 * 1024
ECOSYSTEMS = {
    'package.json': {'lodash', 'axios', 'express'},
    'composer.json': {'guzzlehttp/guzzle', 'laravel/framework', 'symfony/http-kernel'},
    'requirements.txt': {'django', 'requests', 'jinja2', 'flask'},
}


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})', value):
        return None
    return tuple(map(int, value.split('.')))


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON member')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('Nonstandard JSON constant')


def _dependencies(path, content):
    """Return declarations and unresolved count; never resolve ranges or URLs."""
    deps = []
    unresolved = 0
    if path in {'package.json', 'composer.json'}:
        data = json.loads(content, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
        if not isinstance(data, dict):
            raise ValueError('Manifest must be an object')
        if 'name' in data and not isinstance(data['name'], str):
            raise ValueError('Manifest name must be a string')
        sections = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies') if path == 'package.json' else ('require', 'require-dev')
        # Reject arbitrary JSON/login responses that lack manifest structure.
        if not any(key in data for key in (*sections, 'name')):
            raise ValueError('No recognized manifest structure')
        for section in sections:
            values = data.get(section, {})
            if not isinstance(values, dict) or not all(isinstance(v, str) for v in values.values()):
                raise ValueError('Malformed dependencies')
            deps.extend(values.items())
    else:
        # Narrow grammars deliberately avoid evaluating manifests or package managers.
        patterns = {
            'requirements.txt': r'([A-Za-z0-9_.-]+)==([0-9]+\.[0-9]+\.[0-9]+)',
            'go.mod': r'([A-Za-z0-9_./-]+)\s+v([0-9]+\.[0-9]+\.[0-9]+)',
            'Gemfile': r'gem\s+[\'"]([A-Za-z0-9_-]+)[\'"],\s*[\'"]([0-9]+\.[0-9]+\.[0-9]+)[\'"]',
            'build.gradle': r'implementation\s+[\'"]([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+):([0-9]+\.[0-9]+\.[0-9]+)[\'"]',
        }
        for line in content.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            if '<html' in line.lower() or '<!doctype' in line.lower():
                raise ValueError('HTML is not a manifest')
            if path == 'go.mod' and (line in {'require (', ')'} or line.startswith(('module ', 'go '))):
                continue
            match = re.fullmatch(patterns[path], line.removeprefix('require ') if path == 'go.mod' else line)
            if match:
                deps.append(match.groups())
            else:
                unresolved += 1
        if not deps:
            raise ValueError('No supported dependency declarations')
    if len(deps) > 200:
        unresolved += len(deps) - 200
        deps = deps[:200]
    exact = []
    for name, version in deps:
        if _version(version) is None:
            unresolved += 1
        else:
            exact.append((name, version))
    return exact, unresolved


async def supply_chain(target: str) -> dict:
    try:
        if not isinstance(target, str) or len(target) > 4096:
            raise ValueError('Invalid target')
        parsed = urlsplit(target)
        if parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError('Invalid target')
        parsed.port
    except ValueError:
        return {'error': 'Expected HTTP(S) base URL without credentials, query or fragment', 'coverage_complete': False, 'execution_status': 'not_started'}
    findings, requests, errors = [], [], []
    base = target.rstrip('/')
    async with httpx.AsyncClient(timeout=10.0, verify=True, follow_redirects=False) as client:
        for path, _, _ in MANIFEST_PATHS:
            record = {'manifest': path}
            requests.append(record)
            try:
                async with asyncio.timeout(15), client.stream('GET', f'{base}/{path}') as response:
                    record['status'] = response.status_code
                    if response.status_code == 404:
                        record['assessment'] = 'not_found'
                        continue
                    if response.status_code != 200:
                        errors.append(f'{path}: blocked, redirected or unsuccessful response')
                        record['assessment'] = 'inconclusive'
                        continue
                    body = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        if len(body) + len(chunk) > MAX_BODY:
                            raise ValueError('Response limit exceeded')
                        body.extend(chunk)
                    deps, unresolved = _dependencies(path, body.decode('utf-8'))
                    record.update({'assessment': 'parsed_manifest', 'bytes_read': len(body), 'unresolved': unresolved})
                    if unresolved:
                        errors.append(f'{path}: unresolved declarations or dependency limit')
                    if path not in ECOSYSTEMS:
                        errors.append(f'{path}: no ecosystem-specific advisory data')
                    for name, version in deps:
                        # Never confuse equally named packages across ecosystems.
                        name = re.sub(r'[-_.]+', '-', name).lower() if path == 'requirements.txt' else name
                        hint = KNOWN_VULN_PACKAGES.get(name) if name in ECOSYSTEMS.get(path, set()) else None
                        if hint is not None and (not isinstance(hint, dict) or _version(hint.get('max')) is None):
                            errors.append(f'{path}: invalid bundled advisory threshold')
                            continue
                        if hint and _version(version) <= _version(hint['max']):
                            findings.append({'manifest': path, 'package': name, 'version': version,
                                             'max_safe': None, 'max_affected': hint['max'], 'cve': hint.get('cve'),
                                             'severity': 'medium', 'assessment': 'candidate', 'confidence': 'low',
                                             'coverage': 'Exact declared version below bundled historical threshold; advisory branch ranges, installed version, current applicability and exploitation unverified. max_safe is unavailable.'})
                    findings.append({'manifest': path, 'status': 200, 'packages_found': len(deps),
                                     'severity': 'info', 'assessment': 'observation',
                                     'coverage': 'Parsed supported declaration syntax; not proof of installed packages or vulnerability'})
            except (httpx.HTTPError, ValueError, RecursionError, asyncio.TimeoutError):
                errors.append(f'{path}: request failed, oversized response or malformed/unsupported manifest')
                record['assessment'] = 'inconclusive'
    complete = not errors
    return {'target': target, 'findings': findings, 'count': len(findings), 'requests': requests, 'errors': errors,
            'coverage_complete': complete, 'execution_status': 'completed' if complete else 'partial',
            'coverage': 'Six manifest paths; TLS verified; redirects not followed; 15s total/path, 1 MiB decoded response/path, 200 declarations/path. Bundled advisory hints are historical candidates, not current vulnerability validation.'}
