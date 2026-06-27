"""Scan Express.js app — header disclosure, error handling, directory listing, exposed paths."""

import httpx

EXPRESS_PATHS = [
    "/debug",
    "/_debug",
    "/console",
    "/dev",
    "/.env",
    "/routes",
    "/api/routes",
    "/api-docs",
    "/swagger.json",
    "/sitemap.xml",
    "/robots.txt",
    "/package.json",
    "/.git/HEAD",
]

EXPRESS_HEADERS_RISKY = {
    "x-powered-by": "Express framework disclosure",
    "x-aspnet-version": "ASP.NET version disclosure (unlikely in Express)",
}


async def express_scan(target: str) -> dict:
    """Scan an Express.js application for common security misconfigurations."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    findings = []
    base = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.get(base)
        headers = dict(resp.headers)

        # Check Express-specific headers
        for hdr, desc in EXPRESS_HEADERS_RISKY.items():
            if hdr in headers:
                findings.append({
                    "type": "header_disclosure",
                    "header": hdr,
                    "value": headers[hdr],
                    "description": desc,
                    "risk": "MEDIUM",
                })

        # Check for Express session cookie
        for cookie_name, cookie_value in resp.cookies.items():
            if "connect.sid" in cookie_name.lower():
                findings.append({
                    "type": "express_session",
                    "cookie": cookie_name,
                    "note": "Express session cookie (connect.sid) detected",
                    "risk": "INFO",
                })

        # Check error handling
        error_paths = ["/%s", "/..%2f", "/admin%00"]
        for ep in error_paths:
            try:
                err_resp = await client.get(base + ep)
                err_text = err_resp.text.lower()
                if any(
                    ptn in err_text
                    for ptn in [
                        "express",
                        "stack trace",
                        "at ",
                        "error:",
                        "referenceerror",
                        "typeerror",
                    ]
                ):
                    findings.append({
                        "type": "error_disclosure",
                        "path": ep,
                        "risk": "HIGH",
                        "note": "Error page may disclose framework internals",
                    })
                    break
            except Exception:
                continue

        # Check for express.static misconfig (directory listing)
        for sp in ["/node_modules/", "/static/", "/public/", "/assets/"]:
            try:
                sr = await client.get(base + sp)
                body_lower = sr.text.lower()
                if sr.status_code == 200 and any(
                    p in body_lower
                    for p in ["index of", "directory listing", "parent directory"]
                ):
                    findings.append({
                        "type": "directory_listing",
                        "path": sp,
                        "risk": "HIGH",
                    })
            except Exception:
                continue

        # Check common paths
        for p in EXPRESS_PATHS:
            try:
                pr = await client.get(base + p)
                if pr.status_code == 200 and pr.text.strip():
                    findings.append({
                        "type": "exposed_path",
                        "path": p,
                        "status": pr.status_code,
                        "risk": "MEDIUM",
                    })
            except Exception:
                continue

    return {
        "target": target,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "framework": "Express.js",
    }
