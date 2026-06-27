"""Audit SSH server banner and algorithm support."""

import re
import asyncio


async def ssh_audit(target: str, port: int = 22) -> dict:
    host = target.split(":")[0]
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
        banner = (await asyncio.wait_for(r.readline(), timeout=10)).decode(errors="replace").strip()
        w.close()

        ssh_ver = None
        if "SSH-" in banner:
            parts = banner.split("-")
            ssh_ver = parts[1] if len(parts) > 1 else None

        weak = []
        if "CBC" in banner:
            weak.append("CBC mode ciphers supported")
        if "SSH-1" in banner or "1.5" in banner:
            weak.append("SSH protocol version 1 (insecure)")

        return {"target": host, "port": port, "banner": banner, "ssh_version": ssh_ver, "weak_algorithms": weak}
    except Exception as e:
        return {"target": host, "port": port, "error": str(e)}
