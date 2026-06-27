"""Check SMB service availability on port 445."""

import asyncio


async def smb_enum(target: str) -> dict:
    host = target.split(":")[0]
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, 445), timeout=10)
        w.write(bytes.fromhex("0000004500fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
        await w.drain()
        resp = await asyncio.wait_for(r.read(1024), timeout=10)
        w.close()
        return {"target": target, "smb_available": len(resp) > 0, "port": 445}
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return {"target": target, "smb_available": False, "error": str(e)}
