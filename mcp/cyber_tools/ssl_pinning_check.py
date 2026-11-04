"""Server TLS/HSTS observations cannot establish client-side certificate pinning."""
import asyncio
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit
import httpx

TLS_AWAIT_TIMEOUT = 15.0


def _host(target, port):
    if not isinstance(target, str) or not target or len(target) > 4096 or type(port) is not int or not 1 <= port <= 65535 or any(c.isspace() for c in target):
        raise ValueError('Invalid target or port')
    try:
        host = str(ipaddress.ip_address(target))
        return host, port
    except ValueError:
        pass
    parsed = urlsplit(target if '://' in target else '//' + target)
    if parsed.scheme not in {'', 'http', 'https'} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError('Invalid host URL')
    if parsed.port is not None:
        if port != 443 and port != parsed.port:
            raise ValueError('Conflicting ports')
        port = parsed.port
    if not 1 <= port <= 65535:
        raise ValueError('Invalid URL port')
    host = parsed.hostname
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode('idna').decode('ascii')
        labels = host.split('.')
        if len(host) > 253 or any(not 1 <= len(label) <= 63 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
            raise ValueError('Invalid hostname')
    return host, port


def _certificate(cert):
    if not isinstance(cert, dict) or not cert:
        raise ValueError('Missing certificate metadata')
    result = {}
    for field in ('subject', 'issuer'):
        names = {}
        value = cert.get(field, ())
        if not isinstance(value, (list, tuple)) or len(value) > 100:
            raise ValueError('Malformed certificate names')
        for rdn in value:
            if not isinstance(rdn, (list, tuple)) or len(rdn) > 20:
                raise ValueError('Malformed certificate RDN')
            for pair in rdn:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2 or not all(isinstance(p, str) for p in pair):
                    raise ValueError('Malformed certificate attribute')
                if pair[0] in {'commonName', 'countryName', 'organizationName', 'organizationalUnitName', 'stateOrProvinceName', 'localityName'}:
                    names[pair[0]] = '[REDACTED]'
        result[field] = names
    result['version'] = cert.get('version') if type(cert.get('version')) is int else None
    result['serialNumber'] = '[REDACTED]'
    for field in ('notBefore', 'notAfter'):
        value = cert.get(field)
        if value is None:
            result[field] = None
        elif not isinstance(value, str) or len(value) > 40:
            raise ValueError('Malformed certificate date')
        else:
            result[field] = ssl.cert_time_to_seconds(value)
    names = cert.get('subjectAltName', ())
    if not isinstance(names, (list, tuple)) or len(names) > 1000:
        raise ValueError('Malformed SAN data')
    result['subjectAltName'] = ['[REDACTED]'] * min(len(names), 10)
    result['subjectAltName_count'] = len(names)
    result['truncated'] = len(names) > 10
    return result


def _observe_tls(host, port):
    """Run blocking resolution/handshake off-loop; contexts close when work exits."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=host) as secured:
            return _certificate(secured.getpeercert())


async def ssl_pinning_check(target: str, port: int = 443) -> dict:
    try:
        host, port = _host(target, port)
    except (ValueError, UnicodeError):
        return {'error': 'Expected valid host/HTTP(S) URL and port without credentials/query/fragment',
                'pinning_status': 'not_assessed', 'coverage_complete': False, 'execution_status': 'not_started'}
    findings, errors, certificate = [], [], {}
    try:
        certificate = await asyncio.wait_for(asyncio.to_thread(_observe_tls, host, port), timeout=TLS_AWAIT_TIMEOUT)
        findings.append({'finding': 'Certificate retrieved', 'severity': 'info', 'assessment': 'observation',
                         'confidence': 'high', 'coverage': 'Default trust-store TLS verification succeeded; client pinning not tested'})
        if certificate['truncated']:
            errors.append('Certificate SAN display truncated')
    except ssl.SSLCertVerificationError:
        findings.append({'finding': 'SSL verification failed', 'severity': 'info', 'assessment': 'observation',
                         'confidence': 'high', 'coverage': 'Observed failure of the local default TLS verifier only; cause and client pinning not established',
                         'note': 'Trust/hostname verification failed; this is not evidence of client-side pinning'})
        errors.append('Certificate verification unsuccessful')
    except asyncio.TimeoutError:
        errors.append('TLS observation deadline exceeded; worker may still be running')
    except (OSError, ValueError, TypeError):
        errors.append('TLS connection or certificate metadata unavailable/malformed')
    authority = f'[{host}]' if ':' in host else host
    try:
        async with asyncio.timeout(15), httpx.AsyncClient(timeout=10.0, verify=True, follow_redirects=False) as client:
            async with client.stream('GET', f'https://{authority}:{port}/') as response:
                hsts = response.headers.get('strict-transport-security', '')
                valid = isinstance(hsts, str) and len(hsts) <= 4096
                age = re.search(r'(?:^|;)\s*max-age\s*=\s*"?([0-9]{1,12})"?\s*(?:;|$)', hsts, re.I) if valid else None
                findings.append({'finding': 'HSTS header', 'present': bool(hsts), 'valid_max_age': bool(age),
                                 'value': 'max-age=' + age[1] if age else '', 'status': response.status_code,
                                 'severity': 'info', 'assessment': 'observation', 'confidence': 'high', 'coverage': 'Response header only; HSTS is not certificate pinning'})
                if (hsts and not age) or response.status_code >= 400:
                    errors.append('HSTS malformed or HTTP response blocked/unsuccessful')
    except (httpx.HTTPError, asyncio.TimeoutError):
        errors.append('HSTS request failed')
    return {'target': f'{authority}:{port}', 'certificate': certificate, 'findings': findings, 'count': len(findings),
            'pinning_status': 'not_assessed', 'coverage_complete': False, 'execution_status': 'partial',
            'tls_observations_complete': not errors, 'errors': errors,
            'coverage': 'Server TLS and root-path HSTS only; client app/device behavior and pinning cannot be inferred. No unverified TLS retry, bypass or exploitation. Blocking TLS runs in a worker with a 15s await deadline and 10s socket timeout; the OS resolver/worker thread may outlive timeout or cancellation and cannot be forcibly killed. Socket contexts close when worker work exits. 15s HSTS deadline; body not read; identity values redacted.'}
