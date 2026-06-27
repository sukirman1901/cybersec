"""Test for Server-Side Request Forgery."""

import httpx


async def ssrf_detect(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    params = ["url", "uri", "file", "dest", "redirect", "src", "load", "fetch"]
    callbacks = ["burpcollaborator.net", "oastify.com"]

    results = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        base = target.split("?")[0]
        for p in params:
            for cb in callbacks:
                try:
                    resp = await client.get(f"{base}?{p}=https://{cb}/test")
                    if resp.elapsed.total_seconds() > 5:
                        results.append({"parameter": p, "payload": f"https://{cb}/test", "timing": resp.elapsed.total_seconds(), "note": "Slow response"})
                except httpx.TimeoutException:
                    results.append({"parameter": p, "payload": f"https://{cb}/test", "timing": "timeout", "note": "Timeout"})
                except httpx.HTTPError:
                    continue

    return {"target": target, "found": results, "count": len(results), "vulnerable": len(results) > 0}
