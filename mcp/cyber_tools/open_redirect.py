"""Test for open redirect vulnerabilities."""

import httpx


async def open_redirect(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    payloads = ["//evil.com", "https://evil.com", "/\\evil.com"]
    params = ["url", "next", "redirect", "return", "dest", "goto", "redirect_uri"]
    results = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
        for param in params[:5]:
            for payload in payloads:
                try:
                    resp = await client.get(f"{target}?{param}={payload}")
                    loc = resp.headers.get("location", "")
                    if loc and "evil.com" in loc:
                        results.append({"parameter": param, "payload": payload, "redirects_to": loc})
                        break
                except httpx.HTTPError:
                    continue

    return {"target": target, "found": results, "count": len(results), "vulnerable": len(results) > 0}
