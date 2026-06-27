import httpx
import re
import json
import urllib.parse

async def websocket_test(target: str) -> dict:
    findings = []
    base = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Check for WebSocket endpoint in page
        try:
            resp = await client.get(base)
            ws_urls = re.findall(r'(wss?://[^"\'\s]+)', resp.text)
            if not ws_urls:
                # Try common WS endpoints
                ws_urls = [
                    base.replace("https://", "wss://").replace("http://", "ws://") + "/ws",
                    base.replace("https://", "wss://").replace("http://", "ws://") + "/websocket",
                    base.replace("https://", "wss://").replace("http://", "ws://") + "/socket.io/",
                ]
                findings.append({"test": "ws_endpoint_check", "note": "No WS URLs in page, trying common paths", "risk": "INFO"})
        except Exception:
            return {"target": target, "error": "Could not fetch page", "findings": []}

        for ws_url in ws_urls:
            # Check if endpoint accepts connections (via HTTP upgrade)
            try:
                # HTTP upgrade request simulation
                parsed = urllib.parse.urlparse(ws_url)
                http_url = f"{'https' if ws_url.startswith('wss') else 'http'}://{parsed.netloc}{parsed.path or '/'}"
                upgrade_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                }
                hr = await client.get(http_url, headers=upgrade_headers)
                if hr.status_code == 101 or "upgrade" in hr.headers.get("connection", "").lower():
                    findings.append({"test": "ws_endpoint_accessible", "endpoint": ws_url, "risk": "INFO"})

                    # Check origin validation
                    fake_origin = {"Origin": "https://evil.com"}
                    hr2 = await client.get(http_url, headers={**upgrade_headers, **fake_origin})
                    if hr2.status_code == 101:
                        findings.append({"test": "ws_no_origin_check", "endpoint": ws_url, "note": "WebSocket accepts connections from any origin (CSWSH risk)", "risk": "CRITICAL"})
                    else:
                        findings.append({"test": "ws_origin_check", "endpoint": ws_url, "note": "Origin validation appears active", "risk": "INFO"})
                else:
                    findings.append({"test": "ws_endpoint_not_accessible", "endpoint": ws_url, "status": hr.status_code, "risk": "INFO"})
            except Exception:
                pass

        # Check Socket.io endpoints
        for path in ["/socket.io/", "/socket.io/?EIO=4"]:
            try:
                sr = await client.get(base + path)
                if sr.status_code == 200:
                    findings.append({"test": "socket_io_detected", "path": path, "risk": "MEDIUM", "note": "Socket.IO detected — check for misconfigurations"})
            except Exception:
                pass

    return {"target": target, "findings": findings, "vulnerable": any(f.get("risk") in ["CRITICAL", "HIGH"] for f in findings)}
