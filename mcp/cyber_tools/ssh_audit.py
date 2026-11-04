"""Bounded SSH identification; key exchange algorithms are not enumerated."""
import re
import asyncio

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer


async def ssh_audit(target: str, port: int = 22) -> dict:
    result = {'target': None, 'port': None, 'banner': None, 'ssh_version': None,
              'weak_algorithms': [], 'coverage_complete': False, 'execution_status': 'partial',
              'confidence': 'LOW', 'coverage': 'One SSH identification sample; algorithms not enumerated, software vulnerabilities not verified'}
    writer = None
    try:
        host, port = _normalize_host(target, port)
        result.update(target=host, port=port)
        async with asyncio.timeout(10):
            reader, writer = await asyncio.open_connection(host, port)
            # Identification is <=255 bytes including CRLF. Never readline an
            # unbounded malicious greeting or return arbitrary server comments.
            data = b''
            while len(data) < 256 and b'\n' not in data:
                chunk = await reader.read(256 - len(data))
                if not chunk:
                    break
                data += chunk
            line = data.split(b'\n', 1)[0].rstrip(b'\r')
            if len(line) > 253 or b'\n' not in data:
                raise ValueError('incomplete_identification')
            match = re.fullmatch(rb'SSH-(1\.5|1\.99|2\.0)-[^\s\x00-\x1f]+(?: [^\x00-\x1f]*)?', line)
            if not match:
                raise ValueError('invalid_identification')
            version = match.group(1).decode()
            result.update(ssh_version=version, banner=f'SSH-{version}-[software/comments withheld]',
                          coverage_complete=True, execution_status='completed')
            result['legacy_protocol_advertised'] = version == '1.5'
    except (OSError, ValueError, asyncio.TimeoutError):
        result['error'] = 'SSH identification incomplete'
    finally:
        await _close_writer(writer)
    return result
