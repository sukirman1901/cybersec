"""Bounded RESP observations without credential/configuration extraction."""
import asyncio
import re

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer


class _Replies:
    def __init__(self, reader):
        self.reader, self.buffer, self.received = reader, b'', 0

    async def fill(self):
        chunk = await self.reader.read(min(4096, 65536 - self.received))
        if not chunk or self.received + len(chunk) > 65536:
            raise ValueError('response_budget_or_eof')
        self.received += len(chunk)
        self.buffer += chunk

    async def response(self):
        while b'\r\n' not in self.buffer:
            if len(self.buffer) > 512:
                raise ValueError('line_limit')
            await self.fill()
        line, self.buffer = self.buffer.split(b'\r\n', 1)
        if len(line) > 512 or not line or line[:1] not in (b'+', b'-', b':', b'$'):
            raise ValueError('invalid_resp')
        kind, value = line[:1], line[1:]
        if kind == b':':
            if not re.fullmatch(rb'\d{1,20}', value):
                raise ValueError('invalid_integer')
            return kind, int(value)
        if kind == b'$':
            if not re.fullmatch(rb'\d{1,5}', value) or int(value) > 65000:
                raise ValueError('bulk_limit')
            length = int(value)
            while len(self.buffer) < length + 2:
                await self.fill()
            if self.buffer[length:length + 2] != b'\r\n':
                raise ValueError('invalid_bulk')
            value, self.buffer = self.buffer[:length], self.buffer[length + 2:]
        return kind, value


async def redis_enum(target: str) -> dict:
    result = {'target': None, 'accessible': None, 'redis_available': None, 'no_auth': None,
              'keys_total': None, 'keyspace': '', 'version': 'unknown', 'commands_attempted': 0,
              'unauthenticated_commands': [], 'privileged_access_confirmed': False,
              'connection_state': 'not_started', 'coverage_complete': False, 'execution_status': 'partial',
              'confidence': 'LOW', 'coverage': 'Only observed commands PING/INFO/DBSIZE; no_auth refers to these observations, not global policy or privileged access. CONFIG and secrets not collected.'}
    writer = None
    try:
        host, port = _normalize_host(target, 6379)
        result['target'] = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        result['connection_state'] = 'unknown'
        async with asyncio.timeout(15):
            reader, writer = await asyncio.open_connection(host, port)
            result['connection_state'] = 'open'
            replies = _Replies(reader)
            async def command(value):
                result['commands_attempted'] += 1
                writer.write(value + b'\r\n')
                await writer.drain()
                return await replies.response()
            kind, data = await command(b'PING')
            if kind == b'-' and data.split(b' ', 1)[0] in (b'NOAUTH', b'NOPERM'):
                result.update(redis_available=True, accessible=True, no_auth=False)
            elif kind == b'+' and data == b'PONG':
                result.update(redis_available=True, accessible=True)
                result['unauthenticated_commands'].append('PING')
                kind, data = await command(b'INFO')
                if kind == b'-' and data.split(b' ', 1)[0] in (b'NOAUTH', b'NOPERM'):
                    result['no_auth'] = False
                elif kind == b'$':
                    version = re.search(rb'(?:^|\r\n)redis_version:(\d+\.\d+\.\d+(?:[.-][A-Za-z0-9]+)?)\r\n', data)
                    if not version:
                        raise ValueError('invalid_info')
                    result.update(version=version.group(1).decode(), no_auth=True)
                    result['unauthenticated_commands'].append('INFO')
                    kind, data = await command(b'DBSIZE')
                    if kind == b':':
                        result['keys_total'] = data
                        result['unauthenticated_commands'].append('DBSIZE')
                    elif not (kind == b'-' and data.split(b' ', 1)[0] in (b'NOAUTH', b'NOPERM')):
                        raise ValueError('invalid_dbsize')
                else:
                    raise ValueError('invalid_info')
            else:
                raise ValueError('invalid_ping')
            result.update(coverage_complete=True, execution_status='completed')
    except ConnectionRefusedError:
        result.update(connection_state='refused', accessible=False, error='TCP connection refused; Redis not assessed')
    except (OSError, asyncio.TimeoutError, ValueError):
        result['error'] = 'Redis observation incomplete or input/response invalid'
    finally:
        await _close_writer(writer)
    return result
