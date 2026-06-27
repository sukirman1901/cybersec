import httpx
import ssl
import socket


async def ssl_pinning_check(target: str, port: int = 443) -> dict:
    findings = []
    host = target.split(":")[0]
    cert_info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_info = {
                    "subject": dict(cert.get("subject", [])),
                    "issuer": dict(cert.get("issuer", [])),
                    "version": cert.get("version", ""),
                    "serialNumber": cert.get("serialNumber", "")[:20],
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "subjectAltName": [s[1] for s in cert.get("subjectAltName", [])[:10]],
                }
                findings.append({"finding": "Certificate retrieved", "subject": str(cert_info.get("subject", {}).get("commonName", ""))[:80], "issuer": str(list(cert_info.get("issuer", {}).values())[0])[:80] if cert_info.get("issuer") else "", "expiry": cert_info.get("notAfter", ""), "severity": "info"})
    except ssl.SSLCertVerificationError as e:
        findings.append({"finding": "SSL verification failed", "error": str(e)[:100], "severity": "high", "note": "May indicate SSL pinning or invalid cert"})
    except Exception as e:
        findings.append({"finding": "Connection error", "error": str(e)[:100], "severity": "medium"})
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(f"https://{host}:{port}")
            hsts = resp.headers.get("strict-transport-security", "")
            findings.append({"finding": "HSTS header", "present": bool(hsts), "value": hsts[:100], "severity": "info"})
        except httpx.HTTPError:
            pass
    try:
        ctx_no_verify = ssl.create_default_context()
        ctx_no_verify.check_hostname = False
        ctx_no_verify.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx_no_verify.wrap_socket(sock, server_hostname=host) as ssock:
                findings.append({"finding": "SSL without verification works", "note": "Server accepts connections without cert verification — expected for IP-based access", "severity": "info"})
    except Exception as e:
        findings.append({"finding": "SSL non-verify failed", "error": str(e)[:100], "severity": "medium"})
    return {"target": f"{host}:{port}", "certificate": cert_info, "findings": findings, "count": len(findings)}
