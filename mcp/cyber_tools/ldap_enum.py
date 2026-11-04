"""One bounded anonymous LDAP bind; success does not imply directory access."""
import asyncio

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer


def _tlv(data, offset=0):
    if len(data) < offset + 2:
        raise ValueError('truncated_ber')
    tag, size = data[offset], data[offset + 1]
    start = offset + 2
    if size & 128:
        count = size & 127
        if count not in (1, 2) or len(data) < start + count:
            raise ValueError('unsupported_length')
        size = int.from_bytes(data[start:start + count], 'big')
        start += count
    end = start + size
    if end > len(data):
        raise ValueError('truncated_ber')
    return tag, data[start:end], end


async def ldap_enum(target: str, username: str = '', password: str = '') -> dict:
    result = {'target': None, 'ldap_available': None, 'anonymous_bind': None,
              'privileged_access_confirmed': False, 'connection_state': 'not_started',
              'coverage_complete': False, 'execution_status': 'partial', 'confidence': 'LOW',
              'coverage': 'Anonymous LDAPv3 bind result only; authenticated binds, directory reads and privileges not tested'}
    writer = None
    try:
        host, port = _normalize_host(target, 389)
        result['target'] = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        if username or password:
            result['error'] = 'Credentialed binds unsupported; no credentials sent'
            return result
        result['connection_state'] = 'unknown'
        async with asyncio.timeout(10):
            reader, writer = await asyncio.open_connection(host, port)
            result['connection_state'] = 'open'
            writer.write(bytes.fromhex('300c020101600702010304008000'))
            await writer.drain()
            data = b''
            expected = None
            while expected is None or len(data) < expected:
                chunk = await reader.read(4096 - len(data))
                if not chunk or len(data) + len(chunk) > 4096:
                    raise ValueError('response_limit_or_eof')
                data += chunk
                if data[0] != 0x30:
                    raise ValueError('invalid_ldap')
                if len(data) >= 2:
                    size = data[1]
                    if size < 128:
                        expected = 2 + size
                    else:
                        count = size & 127
                        if count not in (1, 2):
                            raise ValueError('unsupported_length')
                        if len(data) >= 2 + count:
                            expected = 2 + count + int.from_bytes(data[2:2 + count], 'big')
                    if expected is not None and expected > 4096:
                        raise ValueError('response_limit')
            _, message, end = _tlv(data)
            tag, message_id, position = _tlv(message)
            if end != len(data) or tag != 2 or message_id != b'\x01':
                raise ValueError('unmatched_message')
            tag, body, _ = _tlv(message, position)
            if tag != 0x61:
                raise ValueError('not_bind_response')
            tag, code, position = _tlv(body)
            if tag != 0x0a or len(code) != 1:
                raise ValueError('invalid_result')
            for _ in range(2):
                tag, _, position = _tlv(body, position)
                if tag != 4:
                    raise ValueError('invalid_result')
            result.update(ldap_available=True, anonymous_bind=code[0] == 0, result_code=code[0],
                          coverage_complete=True, execution_status='completed')
    except ConnectionRefusedError:
        result.update(connection_state='refused', error='TCP connection refused; LDAP not assessed')
    except (OSError, asyncio.TimeoutError, ValueError):
        result['error'] = 'LDAP observation incomplete or input/response invalid'
    finally:
        await _close_writer(writer)
    return result
