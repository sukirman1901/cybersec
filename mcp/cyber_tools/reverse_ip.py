"""Find domains hosted on the same IP address via crt.sh and reverse DNS."""

import socket
import httpx


async def reverse_ip(target: str) -> dict:
    if target.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        target = urlparse(target).hostname or target
    target = target.split(":")[0]

    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        return {"target": target, "error": str(e)}

    domains = []
    sources = {}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://crt.sh/?q={ip}&output=json")
            if resp.status_code == 200:
                for entry in resp.json():
                    for d in entry.get("name_value", "").split("\n"):
                        d = d.strip().lower()
                        if d and "*" not in d and d not in domains:
                            domains.append(d)
                            sources["crt.sh"] = sources.get("crt.sh", 0) + 1
    except Exception:
        pass

    try:
        rev = socket.gethostbyaddr(ip)
        if rev[0] and rev[0] not in domains:
            domains.append(rev[0])
            sources["rdns"] = sources.get("rdns", 0) + 1
    except Exception:
        pass

    return {"ip": ip, "target": target, "domains": domains[:100], "count": len(domains[:100]), "sources": sources}
