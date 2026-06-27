"""Scan for misplaced sensitive files — signatures, certs, configs, backups."""

import httpx

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


async def misplaced_files(target: str) -> dict:
    results = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in SENSITIVE_PATHS:
            try:
                url = target.rstrip("/") + path
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 5:
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "snippet": resp.text[:150],
                    })
            except Exception:
                pass

    return {
        "target": target,
        "paths_checked": len(SENSITIVE_PATHS),
        "exposed_files": len(results),
        "findings": results,
        "risk": "HIGH" if results else "PASS",
    }
