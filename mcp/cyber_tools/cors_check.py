"""Test for CORS misconfiguration."""

import httpx
from urllib.parse import urlparse


async def cors_check(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    host = urlparse(target).hostname
    origins = ["https://evil.com", "null", f"https://evil{host}", f"https://{host}.evil.com"]
    results = []

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for origin in origins:
            try:
                resp = await client.options(target, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                results.append({
                    "origin": origin,
                    "access_control_allow_origin": acao,
                    "vulnerable": acao == "*" or acao == origin or (acao and acac.lower() == "true"),
                })
            except httpx.HTTPError as e:
                results.append({"origin": origin, "error": str(e)})

    return {"target": target, "tests": results, "vulnerable": any(r.get("vulnerable") for r in results)}
