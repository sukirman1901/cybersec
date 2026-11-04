"""SSL/TLS analysis using Python ssl module."""

import re
import ssl
import socket
import ipaddress
import time
from urllib.parse import urlparse

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "aNULL",
    "LOW", "SSLv2", "SSLv3",
]


def _normalize_host(target: str, port: int = 443) -> tuple[str, int]:
    """Validate without DNS; strip URL secrets and support bracketed IPv6."""
    if not isinstance(target, str) or not target or any(c.isspace() for c in target):
        raise ValueError('invalid_target')
    try:
        ipaddress.ip_address(target)
        host = target
    except ValueError:
        parsed = urlparse(target if '://' in target else '//' + target)
        if parsed.scheme and parsed.scheme not in ('http', 'https'):
            raise ValueError('invalid_scheme')
        host = parsed.hostname
        if parsed.port is not None:
            port = parsed.port
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or not host:
        raise ValueError('invalid_target')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                    for label in host.rstrip('.').split('.')):
            raise ValueError('invalid_host')
    return host, port


def ssl_analyze(host: str, port: int = 443) -> dict:
    """Analyze SSL/TLS configuration."""
    result = {
        "host": None,
        "port": None,
        "certificate": {},
        "protocols": {},
        "weak_ciphers": [],
        "issues": [],
        "certificate_validated": False,
        "hostname_validated": False,
        "coverage_complete": False,
        "execution_status": "partial",
        "coverage": "One TLS connection helper call with 5s socket timeout; OS DNS/address retries are not a hard total deadline. Verified handshake and negotiated cipher/version only; supported protocols not enumerated",
    }
    try:
        host, port = _normalize_host(host, port)
        result.update(host=host, port=port)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert or not isinstance(cert.get('serialNumber'), str):
                    raise ValueError('missing_certificate')
                before = ssl.cert_time_to_seconds(cert['notBefore'])
                after = ssl.cert_time_to_seconds(cert['notAfter'])
                now = time.time()
                result["certificate"] = {
                    "subject": dict(pair for rdn in cert.get('subject', ()) for pair in rdn),
                    "issuer": dict(pair for rdn in cert.get('issuer', ()) for pair in rdn),
                    "notBefore": cert['notBefore'], "notAfter": cert['notAfter'],
                    "serial": cert['serialNumber'], "expired": after <= now,
                    "not_yet_valid": before > now,
                }
                if before > now or after <= now or before >= after:
                    raise ValueError('invalid_validity')
                result.update(certificate_validated=True, hostname_validated=True)
                cipher = ssock.cipher()
                result["current_cipher"] = cipher[0] if cipher else "unknown"
                result["tls_version"] = ssock.version()
                if cipher and re.search(r'(?:^|[-_])(?:RC4|DES|3DES|MD5|EXPORT|NULL|aNULL)(?:[-_]|$)', cipher[0]):
                    result['weak_ciphers'].append(cipher[0])
                    result['issues'].append('Weak negotiated cipher observed')
                result.update(coverage_complete=True, execution_status='completed')
    except ssl.SSLCertVerificationError as exc:
        result['error'] = 'TLS certificate verification failed'
        result['error_type'] = {10: 'certificate_expired', 62: 'hostname_mismatch', 64: 'hostname_mismatch'}.get(
            getattr(exc, 'verify_code', None), 'certificate_untrusted_or_invalid')
    except (OSError, ValueError, KeyError, TypeError):
        result['error'] = 'TLS observation failed or certificate/input was invalid'
        result['error_type'] = 'tls_observation_incomplete'
    return result
