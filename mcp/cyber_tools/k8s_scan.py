import httpx

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
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path, indicator, severity in ENDPOINTS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url, headers={"Authorization": "Bearer invalid"})
                if resp.status_code != 404:
                    findings.append({
                        "endpoint": path,
                        "status": resp.status_code,
                        "severity": severity,
                        "note": f"{indicator}" + (" — accessible without valid auth!" if resp.status_code == 200 else ""),
                    })
            except httpx.HTTPError:
                continue
        try:
            resp = await client.get(base + "/api/v1", headers={"Authorization": "Bearer invalid"})
            if resp.status_code == 200:
                pods = resp.json().get("resources", [])
                findings.append({"endpoint": "/api/v1", "status": 200, "severity": "critical", "note": f"Full API access. Resources: {len(pods)}"})
        except Exception:
            pass
    return {"target": target, "findings": findings, "count": len(findings)}
