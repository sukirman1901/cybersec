"""Discover origin IP behind CDN via historical DNS and records."""

import socket
import httpx
from urllib.parse import urlparse


async def origin_ip_discovery(target: str) -> dict:
    if target.startswith(("http://", "https://")):
        target = urlparse(target).hostname or target

    ips = []
    sources = {}

    try:
        ip = socket.gethostbyname(target)
        ips.append(ip)
        sources["dns_a_record"] = [ip]
    except Exception:
        pass

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://crt.sh/?q={target}&output=json")
            if resp.status_code == 200:
                for entry in resp.json()[:50]:
                    ip = entry.get("ip", "")
                    if ip and ip not in ips:
                        ips.append(ip)
                        sources.setdefault("crt.sh", []).append(ip)
    except Exception:
        pass

    for prefix in ["direct", "origin", "origin-", "direct-", "backend", "lb"]:
        try:
            ip = socket.gethostbyname(f"{prefix}.{target}")
            if ip not in ips:
                ips.append(ip)
                sources.setdefault("origin_subdomains", []).append(ip)
        except socket.gaierror:
            pass

    return {"target": target, "ip_addresses": ips, "sources": sources, "count": len(ips)}
