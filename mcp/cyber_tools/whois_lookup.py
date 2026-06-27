"""WHOIS lookup for domain registration information."""

import re
import asyncio


async def whois_lookup(target: str) -> dict:
    if target.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        target = urlparse(target).hostname or target
    target = target.split(":")[0]

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("whois.iana.org", 43), timeout=10)
        w.write((target + "\r\n").encode())
        await w.drain()

        ref = b""
        while True:
            line = await asyncio.wait_for(r.readline(), timeout=5)
            if not line:
                break
            ref += line
            if b"whois." in line:
                break
        w.close()

        whois_server = None
        for line in ref.decode(errors="replace").split("\n"):
            m = re.search(r"whois:\s*(\S+)", line)
            if m:
                whois_server = m.group(1)
                break

        if not whois_server:
            return {"target": target, "error": "No WHOIS server found"}

        r2, w2 = await asyncio.wait_for(asyncio.open_connection(whois_server, 43), timeout=10)
        w2.write((target + "\r\n").encode())
        await w2.drain()

        data = b""
        while True:
            try:
                chunk = await asyncio.wait_for(r2.read(4096), timeout=5)
                if not chunk:
                    break
                data += chunk
            except asyncio.TimeoutError:
                break
        w2.close()

        text = data.decode(errors="replace")
        parsed = {}
        for line in text.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower().replace(" ", "_")
                v = v.strip()
                if k and v and k not in ("%", "#", ";", ">>>", "<<"):
                    parsed[k] = v

        return {"target": target, "server": whois_server, "raw": text[:3000], "parsed": parsed}
    except Exception as e:
        return {"target": target, "error": str(e)}
