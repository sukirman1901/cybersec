"""WHOIS lookup for domain registration information."""

import asyncio
import re
import shutil
import subprocess
from typing import Optional
from urllib.parse import urlparse

# TLD-specific WHOIS servers (fallback when IANA referral fails)
_TLD_WHOIS = {
    "go.id": "whois.idnic.net",
    "co.id": "whois.idnic.net",
    "or.id": "whois.idnic.net",
    "ac.id": "whois.idnic.net",
    "sch.id": "whois.idnic.net",
    "web.id": "whois.idnic.net",
    "id": "whois.idnic.net",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
}


def _normalize_domain(target: str) -> str:
    if target.startswith(("http://", "https://")):
        target = urlparse(target).hostname or target
    return target.split(":")[0].strip().lower().rstrip(".")


def _tld_servers(domain: str) -> list[str]:
    parts = domain.split(".")
    servers: list[str] = []
    for i in range(len(parts) - 1):
        tld = ".".join(parts[i:])
        if tld in _TLD_WHOIS:
            servers.append(_TLD_WHOIS[tld])
    return servers


def _whois_cli(domain: str) -> Optional[dict]:
    if not shutil.which("whois"):
        return None
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=25,
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        if not text.strip():
            return None
        parsed = {}
        for line in text.splitlines():
            if ":" in line and not line.strip().startswith("%"):
                k, v = line.split(":", 1)
                k = k.strip().lower().replace(" ", "_")
                v = v.strip()
                if k and v and k not in ("%", "#"):
                    parsed[k] = v
        return {"target": domain, "server": "whois-cli", "raw": text[:5000], "parsed": parsed}
    except Exception:
        return None


async def _whois_socket(domain: str, server: str) -> str:
    r, w = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout=12)
    w.write((domain + "\r\n").encode())
    await w.drain()
    data = b""
    while True:
        try:
            chunk = await asyncio.wait_for(r.read(4096), timeout=5)
            if not chunk:
                break
            data += chunk
        except asyncio.TimeoutError:
            break
    w.close()
    return data.decode(errors="replace")


async def whois_lookup(target: str) -> dict:
    domain = _normalize_domain(target)

    cli_result = _whois_cli(domain)
    if cli_result and cli_result.get("parsed"):
        return cli_result

    # Try TLD-specific servers
    for server in _tld_servers(domain):
        try:
            text = await _whois_socket(domain, server)
            if text.strip():
                parsed = {}
                for line in text.split("\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k = k.strip().lower().replace(" ", "_")
                        v = v.strip()
                        if k and v and k not in ("%", "#", ";"):
                            parsed[k] = v
                return {"target": domain, "server": server, "raw": text[:5000], "parsed": parsed}
        except Exception:
            continue

    # IANA referral fallback
    try:
        ref = await _whois_socket(domain, "whois.iana.org")
        whois_server = None
        for line in ref.split("\n"):
            m = re.search(r"whois:\s*(\S+)", line, re.I)
            if m:
                whois_server = m.group(1).strip()
                break
        if not whois_server:
            return {
                "target": domain,
                "error": "No WHOIS server found",
                "hint": "Install whois CLI: brew install whois",
            }
        text = await _whois_socket(domain, whois_server)
        parsed = {}
        for line in text.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower().replace(" ", "_")
                v = v.strip()
                if k and v:
                    parsed[k] = v
        return {"target": domain, "server": whois_server, "raw": text[:5000], "parsed": parsed}
    except Exception as e:
        return {"target": domain, "error": str(e), "hint": "brew install whois"}
