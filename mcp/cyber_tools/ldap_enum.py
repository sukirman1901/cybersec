import asyncio


async def ldap_enum(target: str, username: str = "", password: str = "") -> dict:
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 389

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
        ldap_bind = bytes.fromhex(
            "300c02010160070201030400a000"
        )
        w.write(ldap_bind)
        await w.drain()
        resp = await asyncio.wait_for(r.read(4096), timeout=10)
        w.close()

        info = {
            "target": f"{host}:{port}",
            "ldap_available": len(resp) > 0,
            "anonymous_bind": len(resp) > 10,
            "response_hex": resp.hex()[:200],
            "note": "LDAP server responded. Use ldapsearch for full enumeration."
        }

        try:
            text = resp.decode("utf-8", errors="replace")
            if text:
                info["response_text"] = text[:200]
        except Exception:
            pass

        return info
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return {"target": f"{host}:{port}", "ldap_available": False, "error": str(e)}
