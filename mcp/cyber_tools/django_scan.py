import httpx
import re

CHECKS = [
    ("/admin/", "admin|django", "high"),
    ("/api/", "api", "medium"),
    ("/api/v1/", "api", "medium"),
    ("/api/v2/", "api", "medium"),
    ("/api/auth/", "auth|login|token", "medium"),
    ("/.env", "SECRET_KEY|DB_NAME|DB_PASSWORD|DJANGO", "critical"),
    ("/settings.py", "SECRET_KEY|DATABASES|ALLOWED_HOSTS", "critical"),
    ("/manage.py", "manage.py|django", "medium"),
    ("/requirements.txt", "django|requirements", "info"),
    ("/static/admin/js/core.js", "django|cookie|csrf", "medium"),
    ("/__debug__/", "debug", "critical"),
    ("/debug/", "debug", "critical"),
    ("/robots.txt", "Disallow|sitemap", "info"),
    ("/sitemap.xml", "urlset", "info"),
]

HEADER_SIGS = ["x-frame-options", "x-content-type-options", "csrf", "sessionid"]


async def django_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        is_django = False
        for h in resp_root.headers:
            if any(sig in h.lower() for sig in HEADER_SIGS):
                is_django = True
        if "csrf" in resp_root.text.lower() or "django" in resp_root.text.lower():
            is_django = True
        if "sessionid" in resp_root.headers.get("set-cookie", ""):
            is_django = True
        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 or resp.status_code == 301:
                    exposed = False
                    if resp.status_code == 200:
                        exposed = True
                    elif path == "/admin/" and resp.status_code == 301:
                        exposed = True
                    if exposed:
                        findings.append({"path": path, "status": resp.status_code, "severity": severity})
            except httpx.HTTPError:
                continue
        if "debug=" in resp_root.text.lower() or "debug: true" in resp_root.text.lower():
            findings.append({"path": "/", "severity": "critical", "note": "Debug mode detected in response"})
        set_cookie = resp_root.headers.get("set-cookie", "")
        if "sessionid" in set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append({"finding": "Session cookie without HttpOnly flag", "severity": "medium"})
            if "secure" not in set_cookie.lower():
                findings.append({"finding": "Session cookie without Secure flag", "severity": "medium"})
            if "samesite" not in set_cookie.lower():
                findings.append({"finding": "Session cookie without SameSite flag", "severity": "low"})
    return {"target": target, "django_detected": is_django, "findings": findings, "count": len(findings)}
