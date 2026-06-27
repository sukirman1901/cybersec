import httpx
import re

ENDPOINTS = [
    "/InvokeTransformer",
    "/InvokerTransformer",
    "/CommonsCollections1",
    "/CommonsCollections2",
    "/ysoserial",
    "/deserialization",
    "/rmi",
    "/jmx",
    "/jndi",
]

SIGNATURES = [
    ("java serialized", r'\xac\xed\x00\x05'),
    ("weblogic", r'weblogic'),
    ("jboss", r'jboss'),
    ("java rmi", r'JRMI'),
    ("jndi lookup", r'jndi:rmi|jndi:ldap'),
]


async def java_deserialize(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for sig_name, sig_pattern in SIGNATURES:
            try:
                resp = await client.get(base)
                if re.search(sig_pattern, resp.text, re.I):
                    findings.append({
                        "type": sig_name,
                        "detected_in": "response body",
                        "severity": "high",
                    })
            except httpx.HTTPError:
                continue
        for endpoint in ENDPOINTS:
            url = f"{base}{endpoint}"
            try:
                resp = await client.get(url)
                if resp.status_code != 404:
                    findings.append({
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "severity": "high" if resp.status_code == 200 else "medium",
                    })
            except httpx.HTTPError:
                continue
    return {"target": target, "findings": findings, "count": len(findings)}
