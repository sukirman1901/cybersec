"""Bounded SMB2 negotiate observation; no session or share access testing."""
import asyncio
import struct

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer


async def smb_enum(target: str) -> dict:
    result = {'target': None, 'port': None, 'smb_available': None, 'connection_state': 'not_started',
              'coverage_complete': False, 'execution_status': 'partial', 'confidence': 'LOW',
              'coverage': 'One SMB2 negotiate response; authentication, shares and privileges not tested'}
    writer = None
    try:
        host, port = _normalize_host(target, 445)
        result.update(target=host, port=port, connection_state='unknown')
        async with asyncio.timeout(10):
            reader, writer = await asyncio.open_connection(host, port)
            result['connection_state'] = 'open'
            header = bytearray(64)
            header[:4] = b'\xfeSMB'
            struct.pack_into('<H', header, 4, 64)
            struct.pack_into('<H', header, 14, 1)
            body = bytearray(36)
            struct.pack_into('<HHH', body, 0, 36, 1, 1)
            packet = bytes(header + body) + b'\x02\x02'
            writer.write(len(packet).to_bytes(4, 'big') + packet)
            await writer.drain()
            data = b''
            expected = None
            while expected is None or len(data) < expected:
                chunk = await reader.read(4096 - len(data))
                if not chunk or len(data) + len(chunk) > 4096:
                    raise ValueError('response_limit_or_eof')
                data += chunk
                if len(data) >= 4:
                    expected = int.from_bytes(data[:4], 'big') + 4
                    if data[0] != 0 or not 68 <= expected <= 4096:
                        raise ValueError('invalid_frame')
            response = data[4:]
            if len(data) != expected or response[:4] != b'\xfeSMB' or struct.unpack_from('<H', response, 4)[0] != 64:
                raise ValueError('invalid_header')
            if struct.unpack_from('<H', response, 12)[0] != 0 or not struct.unpack_from('<I', response, 16)[0] & 1 or struct.unpack_from('<Q', response, 24)[0] != 0:
                raise ValueError('unmatched_negotiate')
            status = struct.unpack_from('<I', response, 8)[0]
            if status == 0:
                if len(response) < 128 or struct.unpack_from('<H', response, 64)[0] != 65:
                    raise ValueError('truncated_negotiate')
                offset, length = struct.unpack_from('<HH', response, 120)
                if length and (offset < 128 or offset + length > len(response)):
                    raise ValueError('invalid_security_buffer')
            elif len(response) < 72 or struct.unpack_from('<H', response, 64)[0] != 9:
                raise ValueError('truncated_error')
            result.update(smb_available=True, status_code=status, coverage_complete=True, execution_status='completed')
    except ConnectionRefusedError:
        result.update(connection_state='refused', error='TCP connection refused; SMB not assessed')
    except (OSError, asyncio.TimeoutError, ValueError):
        result['error'] = 'SMB observation incomplete or input/response invalid'
    finally:
        await _close_writer(writer)
    return result
