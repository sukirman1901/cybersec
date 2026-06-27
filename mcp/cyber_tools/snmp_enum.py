"""Check SNMP service availability on port 161."""

import asyncio


async def snmp_enum(target: str, community: str = "public") -> dict:
    host = target.split(":")[0]
    communities = [community] if community else ["public", "private", "community"]

    for comm in communities:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, 161), timeout=5)
            w.close()
            return {"target": target, "snmp_available": True, "community": comm, "port": 161}
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            continue

    return {"target": target, "snmp_available": False}
