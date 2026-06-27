"""Search Certificate Transparency logs for certificates."""

import httpx


async def crt_search(domain: str) -> dict:
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code != 200:
                return {"domain": domain, "error": f"HTTP {resp.status_code}"}

            certs = []
            seen = set()
            for entry in resp.json()[:200]:
                cid = entry.get("id", "")
                if cid in seen:
                    continue
                seen.add(cid)
                certs.append({
                    "id": cid, "issued": entry.get("entry_timestamp", ""),
                    "issuer": entry.get("issuer_name", ""),
                    "name_value": entry.get("name_value", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                })
            return {"domain": domain, "certificates": certs, "count": len(certs)}
    except Exception as e:
        return {"domain": domain, "error": str(e)}
