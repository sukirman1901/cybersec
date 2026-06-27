"""Deep service fingerprinting via banner grabbing."""

import re
import asyncio


async def service_fingerprint(target: str, port: int = 80) -> dict:
    host = target.split(":")[0]
    result = {"target": host, "port": port, "banner": None, "service": "unknown", "details": {}}

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)

        if port == 80 or port == 443:
            w.write(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        elif port == 22:
            pass
        elif port in (21, 110, 143):
            pass
        else:
            w.write(b"\r\n")

        await w.drain()
        banner = b""
        try:
            while True:
                chunk = await asyncio.wait_for(r.read(4096), timeout=5)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 4096:
                    break
        except asyncio.TimeoutError:
            pass
        w.close()

        text = banner.decode(errors="replace").strip()
        result["banner"] = text[:500]
        result["size"] = len(banner)

        if "SSH-" in text:
            result["service"] = "ssh"
            m = re.search(r"SSH-([\d.]+)", text)
            if m:
                result["details"]["version"] = m.group(1)
        elif "HTTP/" in text:
            result["service"] = "http"
            m = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
            if m:
                result["details"]["server"] = m.group(1).strip()
        elif "220" in text and "FTP" in text.upper():
            result["service"] = "ftp"
        elif "220" in text and "SMTP" in text.upper():
            result["service"] = "smtp"
        elif "+OK" in text:
            result["service"] = "pop3"
        elif "* OK" in text:
            result["service"] = "imap"

    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result
