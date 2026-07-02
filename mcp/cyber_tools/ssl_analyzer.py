"""SSL/TLS analysis using Python ssl module."""

import re
import ssl
import socket
from urllib.parse import urlparse

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "aNULL",
    "LOW", "SSLv2", "SSLv3",
]


def _normalize_host(target: str, port: int = 443) -> tuple[str, int]:
    """Strip scheme, path, and explicit port from target."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname or target
        if parsed.port:
            port = parsed.port
        return host, port

    # bare host:port or host/path
    if "/" in target:
        target = target.split("/", 1)[0]
    m = re.match(r"^([^:]+):(\d+)$", target)
    if m:
        return m.group(1), int(m.group(2))
    return target, port


def ssl_analyze(host: str, port: int = 443) -> dict:
    """Analyze SSL/TLS configuration."""
    host, port = _normalize_host(host, port)
    result = {
        "host": host,
        "port": port,
        "certificate": {},
        "protocols": {},
        "weak_ciphers": [],
        "issues": [],
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result["certificate"] = {
                        "subject": dict(cert.get("subject", [])[0]) if cert.get("subject") else {},
                        "issuer": dict(cert.get("issuer", [])[0]) if cert.get("issuer") else {},
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "serial": hex(cert.get("serialNumber", 0)),
                    }
                cipher = ssock.cipher()
                result["current_cipher"] = cipher[0] if cipher else "unknown"
                result["tls_version"] = ssock.version()
                for wc in WEAK_CIPHERS:
                    if wc in (cipher[0] if cipher else ""):
                        result["weak_ciphers"].append(cipher[0])
                        result["issues"].append(f"Weak cipher in use: {cipher[0]}")
    except Exception as e:
        result["error"] = str(e)
    return result
