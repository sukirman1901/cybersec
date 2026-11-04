import httpx
import re
from urllib.parse import urlsplit

CHECKS = [
    ("/var/run/docker.sock", "docker socket exposed", "critical"),
    ("/.dockerenv", "docker environment", "info"),
    ("/proc/1/cgroup", "docker", "info"),
    ("/proc/1/environ", "environment variables leaked", "high"),
    ("/proc/self/mounts", "overlay|docker", "info"),
]


async def docker_scan(target: str) -> dict:
    findings = []
    observations = []
    try:
        parsed = urlsplit(target)
        parsed.port
        valid = len(target) <= 2048 and parsed.scheme in ('http', 'https') and parsed.hostname and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    except ValueError:
        valid = False
    if not valid:
        return {'findings': [], 'count': 0, 'error': 'Invalid HTTP target', 'coverage_complete': False}
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                async with client.stream('GET', url) as resp:
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk[:65537 - len(body)])
                        if len(body) > 65536:
                            break
                text = body.decode('utf-8', errors='replace')
                matched = False
                if resp.status_code == 200 and len(body) <= 65536:
                    if path == '/proc/1/cgroup':
                        matched = bool(re.search(r'(?m)^\d+:[^\n]*:/[^\n]*(?:docker|kubepods|containerd)', text))
                    elif path == '/proc/self/mounts':
                        matched = bool(re.search(r'(?m)^\S+ /\S* (?:overlay|ext4) \S*', text)) and 'docker' in text
                    elif path == '/proc/1/environ':
                        matched = '\x00' in text and bool(re.search(r'(?:^|\x00)[A-Za-z_][A-Za-z0-9_]*=', text))
                observations.append({'path': path, 'status': resp.status_code, 'outcome': 'matched' if matched else 'not_found' if resp.status_code == 404 else 'inconclusive'})
                if matched:
                    findings.append({
                        "path": path,
                        "status": resp.status_code,
                        "severity": severity,
                        "indicator": indicator,
                        "confidence": "MEDIUM",
                        "coverage": "HTTP file-content pattern only; container identity and exploitability unverified",
                    })
            except httpx.HTTPError:
                observations.append({'path': path, 'outcome': 'request_failed'})
    return {"target": target, "findings": findings, "count": len(findings), 'observations': observations,
            'coverage_complete': all(o['outcome'] in ('matched', 'not_found') for o in observations),
            'coverage': 'HTTP file indicators only; no local socket or exploit validation'}
