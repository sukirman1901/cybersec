import asyncio


async def redis_enum(target: str) -> dict:
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 6379
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        w.write(b"PING\r\n")
        await w.drain()
        resp = await asyncio.wait_for(r.read(4096), timeout=5)
        if b"+PONG" in resp:
            w.write(b"INFO\r\n")
            await w.drain()
            info = await asyncio.wait_for(r.read(65536), timeout=5)
            info_text = info.decode(errors="replace")
            keyspace = ""
            for line in info_text.split("\r\n"):
                if line.startswith("db"):
                    keyspace += line + ", "
            w.write(b"CONFIG GET requirepass\r\n")
            await w.drain()
            auth_resp = await asyncio.wait_for(r.read(4096), timeout=3)
            no_auth = b"$-1" in auth_resp or b"*-1" in auth_resp
            w.write(b"DBSIZE\r\n")
            await w.drain()
            dbsize_resp = await asyncio.wait_for(r.read(4096), timeout=3)
            total_keys = 0
            if b":" in dbsize_resp:
                try:
                    total_keys = int(dbsize_resp.split(b":")[1].split(b"\r\n")[0])
                except (ValueError, IndexError):
                    pass
            w.close()
            return {
                "target": f"{host}:{port}",
                "accessible": True,
                "no_auth": no_auth,
                "keys_total": total_keys,
                "keyspace": keyspace.strip(", "),
                "version": [l.split(":")[1] for l in info_text.split("\r\n") if l.startswith("redis_version")][0] if any(l.startswith("redis_version") for l in info_text.split("\r\n")) else "unknown",
            }
        else:
            return {"target": f"{host}:{port}", "accessible": False, "error": "Not a Redis server"}
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return {"target": f"{host}:{port}", "accessible": False, "error": str(e)}
