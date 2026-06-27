import httpx
import re

OAUTH_ENDPOINTS = [
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/revoke",
    "/oauth/authorization",
    "/oauth2/authorize",
    "/oauth2/token",
    "/api/oauth/authorize",
    "/api/oauth/token",
    "/auth/realms",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


async def oauth_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in OAUTH_ENDPOINTS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code != 404:
                    finding = {"endpoint": path, "status": resp.status_code}
                    if resp.status_code == 200:
                        text_lower = resp.text.lower()
                        if "authorization_endpoint" in text_lower:
                            finding["type"] = "OIDC Discovery"
                            finding["severity"] = "info"
                        elif "access_token" in text_lower or "refresh_token" in text_lower:
                            finding["type"] = "Token endpoint"
                            finding["severity"] = "high"
                        else:
                            finding["type"] = "OAuth Endpoint"
                            finding["severity"] = "medium"
                    elif resp.status_code in (302, 301):
                        finding["type"] = "Redirect OAuth"
                        finding["severity"] = "info"
                    else:
                        finding["type"] = "OAuth exists"
                        finding["severity"] = "low"
                    findings.append(finding)
            except httpx.HTTPError:
                continue
        try:
            resp = await client.get(base)
            redirect_uri_params = re.findall(r'redirect_uri=([^&\s"\']+)', resp.text)
            if redirect_uri_params:
                for ru in redirect_uri_params[:5]:
                    findings.append({"finding": f"redirect_uri in page: {__import__('urllib').parse.unquote(ru)}", "severity": "high", "note": "Check if redirect_uri validation is weak"})
            client_ids = re.findall(r'client_id=([^&\s"\']+)', resp.text)
            for cid in client_ids[:3]:
                findings.append({"finding": f"client_id exposed: {cid}", "severity": "medium"})
        except httpx.HTTPError:
            pass
    return {"target": target, "findings": findings, "count": len(findings)}
