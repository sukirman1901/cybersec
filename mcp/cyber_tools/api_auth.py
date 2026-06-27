import httpx

AUTH_TESTS = [
    ("no_auth", {}),
    ("basic_auth", {"Authorization": "Basic YWRtaW46YWRtaW4="}),
    ("bearer_fake", {"Authorization": "Bearer fake_token_123"}),
    ("bearer_none", {"Authorization": "Bearer none"}),
    ("api_key_header", {"X-API-Key": "admin"}),
    ("api_key_param", {}),
    ("token_in_url", {}),
    ("internal_header", {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Internal": "true"}),
    ("admin_header", {"X-Admin": "true", "X-Role": "admin", "X-Auth": "bypass"}),
]

API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/users",
    "/api/admin",
    "/graphql",
    "/rest",
    "/swagger",
    "/api/swagger",
    "/api/docs",
    "/api/health",
    "/api/status",
]


async def api_auth(target: str) -> dict:
    results = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_orig = await client.get(base)
        orig_status = resp_orig.status_code
        for api_path in API_PATHS:
            url = f"{base}{api_path}"
            for test_name, headers in AUTH_TESTS:
                try:
                    resp = await client.get(url, headers=headers)
                    if test_name == "no_auth" and resp.status_code == 200 and resp.status_code != orig_status:
                        results.append({
                            "endpoint": api_path,
                            "test": test_name,
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "unauthenticated_access": True,
                            "severity": "critical",
                        })
                        break
                    elif resp.status_code == 200 and test_name != "no_auth":
                        results.append({
                            "endpoint": api_path,
                            "test": test_name,
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "auth_bypass_possible": True,
                            "severity": "high",
                        })
                        break
                except httpx.HTTPError:
                    continue
    return {"target": target, "tests": results, "api_endpoints_exposed": len(results), "critical_findings": len([r for r in results if r.get("unauthenticated_access")])}
