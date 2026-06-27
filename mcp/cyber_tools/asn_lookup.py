"""ASN lookup for an IP address via Team Cymru."""

import socket
import asyncio


async def asn_lookup(ip: str) -> dict:
    try:
        socket.inet_aton(ip)
    except OSError:
        try:
            ip = socket.gethostbyname(ip.split(":")[0])
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("whois.cymru.com", 43), timeout=10)
        w.write(f"begin\nverbose\n{ip}\nend\n".encode())
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

        for line in data.decode(errors="replace").split("\n"):
            line = line.strip()
            if "|" in line and not line.startswith("Bulk"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 5:
                    return {"ip": ip, "asn": parts[0], "cidr": parts[2], "country": parts[3], "registry": parts[4]}
        return {"ip": ip}
    except Exception as e:
        return {"ip": ip, "error": str(e)}
