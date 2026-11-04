"""Bounded existing VRFY/EXPN observations; SMTP replies are not identity proof."""
import asyncio
import re

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer


async def smtp_enum(target: str, users: str = '') -> dict:
    result = {'target': None, 'port': None, 'banner': None, 'found_users': [], 'results': [], 'count': 0,
              'connection_state': 'not_started', 'coverage_complete': False, 'execution_status': 'partial',
              'commands_attempted': 0, 'confidence': 'LOW',
              'coverage': 'Bounded VRFY/EXPN replies; positive user claims are server-reported, not independently verified. No mail submission or login.'}
    writer = None
    try:
        host, port = _normalize_host(target, 25)
        test_users = users.split(',') if users else ['root', 'admin', 'info', 'support', 'sales', 'postmaster', 'noreply', 'test']
        if len(test_users) > 16 or any(not re.fullmatch(r'[A-Za-z0-9_.+@-]{1,128}', user) for user in test_users):
            raise ValueError('invalid_users')
        test_users = list(dict.fromkeys(test_users))
        result.update(target=host, port=port, connection_state='unknown')
        async with asyncio.timeout(15):
            reader, writer = await asyncio.open_connection(host, port, limit=1024)
            result['connection_state'] = 'open'
            received = 0
            async def reply():
                nonlocal received
                code = None
                for _ in range(16):
                    line = await reader.readline()
                    received += len(line)
                    if len(line) > 512 or received > 32768 or not line.endswith(b'\r\n'):
                        raise ValueError('reply_limit_or_eof')
                    match = re.fullmatch(rb'([2-5]\d\d)([ -])[^\r\n]*\r\n', line)
                    if not match or (code is not None and code != int(match[1])):
                        raise ValueError('invalid_reply')
                    code = int(match[1])
                    if match[2] == b' ':
                        return code
                raise ValueError('line_limit')
            async def command(value):
                result['commands_attempted'] += 1
                writer.write((value + '\r\n').encode())
                await writer.drain()
                return await reply()
            if await reply() != 220:
                raise ValueError('invalid_greeting')
            result['banner'] = '220 [server text withheld]'
            if await command('EHLO scanner') != 250:
                raise ValueError('ehlo_not_accepted')
            for user in test_users:
                for prefix in ('VRFY', 'EXPN'):
                    status = await command(f'{prefix} {user}')
                    reported = prefix == 'VRFY' and status == 250
                    row = {'user': user, 'command': prefix, 'status': status,
                           'exists': True if reported else None,
                           'candidate': status in (250, 251, 252), 'evidence_type': 'smtp_reply',
                           'independently_verified': False, 'confidence': 'LOW',
                           'coverage': 'SMTP reply only; catch-all behavior and user identity not independently verified'}
                    result['results'].append(row)
                    if reported:
                        result['found_users'].append(user)
                    if status == 421:
                        raise ValueError('server_unavailable')
            if await command('QUIT') != 221:
                raise ValueError('quit_incomplete')
            result.update(coverage_complete=True, execution_status='completed')
    except ConnectionRefusedError:
        result.update(connection_state='refused', error='TCP connection refused; SMTP not assessed')
    except (OSError, asyncio.TimeoutError, ValueError):
        result['error'] = 'SMTP observation incomplete or input/response invalid'
    finally:
        await _close_writer(writer)
    result['found_users'] = sorted(set(result['found_users']))
    result['count'] = len(result['found_users'])
    return result
