"""Test for Server-Side Template Injection."""

import httpx


async def ssti_detect(target: str, param: str = "") -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    payloads = [("{{7*7}}", ["49"]), ("${7*7}", ["49"]), ("<%= 7*7 %>", ["49"])]
    test_params = [param] if param else ["name", "msg", "user", "input", "q"]

    results = []
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        base = target.split("?")[0]
        for p in test_params:
            for payload, expected in payloads:
                try:
                    resp = await client.get(f"{base}?{p}={payload.replace('{','%7B').replace('}','%7D')}")
                    found = [e for e in expected if e in resp.text]
                    if found:
                        results.append({
                            "parameter": p, "payload": payload, "matched": found,
                            "engine_hint": "Jinja2/Twig" if "{{" in payload and "49" in str(found) else "ERB" if "<%=" in payload else "Freemarker",
                        })
                        break
                except httpx.HTTPError:
                    continue

    return {"target": target, "found": results, "count": len(results), "vulnerable": len(results) > 0}
