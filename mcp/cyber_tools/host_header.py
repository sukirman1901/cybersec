import httpx
import re

INJECTIONS = [
    "evil.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.1.1",
    "internal.localhost",
]


async def host_header(target: str) -> dict:
    results = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_orig = await client.get(base)
        orig_status = resp_orig.status_code
        orig_size = len(resp_orig.text)
        for injection in INJECTIONS:
            try:
                resp = await client.get(base, headers={"Host": injection})
                diff_status = resp.status_code != orig_status
                diff_size = abs(len(resp.text) - orig_size) > 50
                password_reset_indicators = ["reset", "password", "link sent", "email sent", "verify"]
                cache_indicators = ["x-cache", "age", "cf-cache"]
                host_reflected = injection in resp.text
                results.append({
                    "host": injection,
                    "status": resp.status_code,
                    "diff_status": diff_status,
                    "diff_size": diff_size,
                    "host_reflected": host_reflected,
                    "password_reset_pages": any(ind in resp.text.lower()[:500] for ind in password_reset_indicators),
                    "suspicious": diff_status or diff_size or host_reflected,
                })
            except httpx.HTTPError as e:
                results.append({"host": injection, "error": str(e)})
        cache_resp = await client.get(base)
        cache_headers = {}
        for k, v in cache_resp.headers.items():
            if "cache" in k.lower():
                cache_headers[k] = v
    return {"target": target, "tests": results, "host_header_vulnerable": any(r.get("suspicious") for r in results), "cache_headers": cache_headers}
