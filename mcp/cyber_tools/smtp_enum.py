"""Enumerate SMTP users via VRFY, EXPN commands."""

import asyncio


async def smtp_enum(target: str, users: str = "") -> dict:
    host = target.split(":")[0]
    test_users = (users.split(",") if users else
                  ["root", "admin", "info", "support", "sales", "postmaster", "noreply", "test"])

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, 25), timeout=10)
        async def cmd(c):
            w.write((c + "\r\n").encode())
            await w.drain()
            return (await asyncio.wait_for(r.readline(), timeout=5)).decode(errors="replace").strip()

        banner = (await asyncio.wait_for(r.readline(), timeout=5)).decode(errors="replace").strip()
        await cmd("EHLO scanner")

        results = []
        for user in test_users:
            for prefix in ["VRFY", "EXPN"]:
                resp = await cmd(f"{prefix} {user}")
                if resp[:3] in ("250", "251", "252"):
                    results.append({"user": user, "command": prefix, "response": resp, "exists": True})

        await cmd("QUIT")
        w.close()
        return {"target": target, "banner": banner, "found_users": list({r["user"] for r in results}), "results": results, "count": len(results)}
    except Exception as e:
        return {"target": target, "error": str(e)}
