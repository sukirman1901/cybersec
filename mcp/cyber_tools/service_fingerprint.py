"""Bounded service banner observations, not vulnerability validation."""
import re
import asyncio
import ssl

from .ssl_analyzer import _normalize_host


async def _close_writer(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=.25)
        except (OSError, asyncio.TimeoutError):
            pass


def _banner_identity(text):
    """Return protocol evidence only; arbitrary banners/headers may hold secrets."""
    patterns = [('ssh', r'^SSH-(\d+\.\d+)-'), ('http', r'^HTTP/(\d+\.\d+) [1-5]\d{2}\b'),
                ('ftp', r'^220[^\r\n]*\bFTP\b'), ('smtp', r'^220[^\r\n]*\b(?:SMTP|ESMTP)\b'),
                ('pop3', r'^\+OK\b'), ('imap', r'^\* OK\b')]
    for service, pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return service, {'protocol_version': match.group(1)} if service in ('ssh', 'http') else {}
    return 'unknown', {}


async def service_fingerprint(target: str, port: int = 80) -> dict:
    result = {'target': None, 'port': None, 'banner': None, 'service': 'unknown', 'details': {},
              'coverage_complete': False, 'execution_status': 'partial',
              'coverage': 'One bounded banner sample; identity hints only, authentication and vulnerabilities not tested'}
    writer = None
    try:
        host, port = _normalize_host(target, port)
        result.update(target=host, port=port)
        async with asyncio.timeout(10):
            tls = port in (443, 8443) or target.startswith('https://')
            options = {'ssl': ssl.create_default_context(), 'server_hostname': host} if tls else {}
            reader, writer = await asyncio.open_connection(host, port, **options)
            if port in (80, 443, 8443) or target.startswith(('http://', 'https://')):
                writer.write(f'GET / HTTP/1.0\r\nHost: {host}\r\n\r\n'.encode())
                await writer.drain()
            elif port not in (22, 21, 110, 143):
                writer.write(b'\r\n')
                await writer.drain()
            banner = await reader.read(4096)
            if not banner:
                raise ValueError('empty_banner')
            service, details = _banner_identity(banner.decode(errors='replace'))
            result.update(service=service, details=details, size=len(banner), banner='[raw banner withheld]')
            if service == 'unknown':
                raise ValueError('unrecognized_banner')
            result.update(coverage_complete=True, execution_status='completed', confidence='LOW')
    except (OSError, ValueError, asyncio.TimeoutError):
        result.update(error='Service observation incomplete', confidence='LOW')
    finally:
        await _close_writer(writer)
    return result
