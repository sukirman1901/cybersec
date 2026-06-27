"""
Passive subdomain enumeration via crt.sh, DNS brute-force, Hackertarget, and Threatcrowd.
Pure Python, no external binaries.
"""

import asyncio
import socket
from typing import Dict, List, Set


async def enumerate_subdomains(target: str) -> Dict:
    """Enumerate subdomains using multiple free data sources."""
    import httpx

    if target.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        target = urlparse(target).hostname or target

    subdomains: Set[str] = set()
    sources: Dict[str, int] = {}

    # 1. Certificate Transparency Logs (crt.sh)
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"https://crt.sh/?q=%.{target}&output=json", follow_redirects=True
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(target) and "*" not in sub and sub not in subdomains:
                            subdomains.add(sub)
                            sources["crt.sh"] = sources.get("crt.sh", 0) + 1
    except Exception:
        pass

    # 2. DNS Brute Force
    common = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
        "ns1", "ns2", "dns", "mx", "exchange", "vpn", "remote",
        "admin", "portal", "api", "dev", "development", "staging",
        "test", "testing", "beta", "alpha", "demo", "sandbox",
        "app", "apps", "mobile", "m", "blog", "news", "shop", "store",
        "secure", "cdn", "static", "assets", "img", "images", "media",
        "docs", "doc", "help", "support", "status", "login", "signin",
        "sso", "auth", "dashboard", "panel", "cpanel", "webmin",
        "git", "gitlab", "svn", "jenkins", "ci", "cd", "build",
        "db", "database", "mysql", "postgres", "mongo", "redis",
        "cloud", "aws", "azure", "gcp", "intranet", "internal",
        "private", "corp", "office", "old", "new", "legacy", "backup",
    ]
    for sub in common:
        try:
            socket.gethostbyname(f"{sub}.{target}")
            sd = f"{sub}.{target}"
            if sd not in subdomains:
                subdomains.add(sd)
                sources["dns_bruteforce"] = sources.get("dns_bruteforce", 0) + 1
        except socket.gaierror:
            pass

    # 3. Hackertarget API
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(f"https://api.hackertarget.com/hostsearch/?q={target}")
            if response.status_code == 200 and "error" not in response.text.lower():
                for line in response.text.split("\n"):
                    if "," in line:
                        sd = line.split(",")[0].strip().lower()
                        if sd.endswith(target) and sd not in subdomains:
                            subdomains.add(sd)
                            sources["hackertarget"] = sources.get("hackertarget", 0) + 1
    except Exception:
        pass

    # 4. Threatcrowd API
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}"
            )
            if response.status_code == 200:
                data = response.json()
                for sd in data.get("subdomains", []):
                    sd = sd.strip().lower()
                    if sd.endswith(target) and sd not in subdomains:
                        subdomains.add(sd)
                        sources["threatcrowd"] = sources.get("threatcrowd", 0) + 1
    except Exception:
        pass

    sorted_subs = sorted(subdomains)
    return {
        "subdomains": sorted_subs,
        "count": len(sorted_subs),
        "sources": sources,
        "domain": target,
    }
