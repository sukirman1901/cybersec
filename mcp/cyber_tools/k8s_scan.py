import httpx
import json
from urllib.parse import urlsplit

ENDPOINTS = [
    ("/api/v1", "kubernetes API", "high"),
    ("/api/v1/namespaces/default/pods", "pods exposed", "critical"),
    ("/api/v1/secrets", "secrets exposed", "critical"),
    ("/openapi/v2", "openapi spec", "medium"),
    ("/healthz", "health", "info"),
    ("/livez", "liveness", "info"),
    ("/readyz", "readiness", "info"),
    ("/api/v1/nodes", "nodes exposed", "critical"),
    ("/.well-known/openid-configuration", "OIDC", "medium"),
    ("/apis/rbac.authorization.k8s.io/v1", "RBAC API", "high"),
]


async def k8s_scan(target: str) -> dict:
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
        for path, indicator, severity in ENDPOINTS:
            url = f"{base}{path}"
            try:
                async with client.stream('GET', url, headers={"Authorization": "Bearer invalid"}) as resp:
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk[:65537 - len(body)])
                        if len(body) > 65536:
                            break
                matched = False
                if resp.status_code == 200 and len(body) <= 65536:
                    try:
                        data = json.loads(body)
                    except (ValueError, UnicodeError, RecursionError):
                        data = None
                    kinds = {'/api/v1': 'APIResourceList', '/apis/rbac.authorization.k8s.io/v1': 'APIResourceList',
                             '/api/v1/namespaces/default/pods': 'PodList', '/api/v1/secrets': 'SecretList', '/api/v1/nodes': 'NodeList'}
                    if path in kinds and isinstance(data, dict):
                        key = 'resources' if kinds[path] == 'APIResourceList' else 'items'
                        matched = data.get('kind') == kinds[path] and isinstance(data.get(key), list)
                        if key == 'resources' or (matched and not data[key]):
                            severity = 'info'
                            indicator = 'API discovery' if key == 'resources' else 'empty resource list'
                    elif path == '/openapi/v2' and isinstance(data, dict):
                        matched = data.get('swagger') == '2.0' and isinstance(data.get('paths'), dict)
                        severity = 'info'
                    elif path in ('/healthz', '/livez', '/readyz'):
                        matched = body.strip() == b'ok'
                    elif path == '/.well-known/openid-configuration' and isinstance(data, dict):
                        matched = isinstance(data.get('issuer'), str) and isinstance(data.get('jwks_uri'), str)
                        severity = 'info'
                observations.append({'endpoint': path, 'status': resp.status_code, 'outcome': 'matched' if matched else 'not_found' if resp.status_code == 404 else 'inconclusive'})
                if matched:
                    findings.append({
                        "endpoint": path,
                        "status": resp.status_code,
                        "severity": severity,
                        "confidence": "MEDIUM",
                        "coverage": "HTTP response structure candidate for this endpoint only; broader permissions and exploitation untested",
                        "note": f"{indicator} response matched with invalid bearer token; no broader permissions inferred",
                    })
            except httpx.HTTPError:
                observations.append({'endpoint': path, 'outcome': 'request_failed'})
    return {"target": target, "findings": findings, "count": len(findings), 'observations': observations,
            'coverage_complete': all(o['outcome'] in ('matched', 'not_found') for o in observations),
            'coverage': 'Listed HTTP endpoints only; discovery does not establish full API access'}
