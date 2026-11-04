"""Offline fixtures for remaining protocol adapters; never open real sockets."""
import asyncio
import importlib
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
NAMES = ('redis_enum', 'smb_enum', 'ldap_enum', 'smtp_enum', 'snmp_enum')


def ldap_reply(code=0, diagnostic=b''):
    body = b'\x0a\x01' + bytes([code]) + b'\x04\x00\x04' + bytes([len(diagnostic)]) + diagnostic
    message = b'\x02\x01\x01\x61' + bytes([len(body)]) + body
    return b'\x30' + bytes([len(message)]) + message


def smb_reply():
    header = bytearray(64)
    header[:4] = b'\xfeSMB'
    struct.pack_into('<H', header, 4, 64)
    struct.pack_into('<I', header, 16, 1)
    body = bytearray(65)
    struct.pack_into('<HHH', body, 0, 65, 1, 0x0202)
    payload = header + body
    return len(payload).to_bytes(4, 'big') + payload


class RemainingProtocolAccuracy(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, name, chunks=(), lines=(), error=None, target='fixture.test', **kwargs):
        module = importlib.import_module('cyber_tools.' + name)
        reader = AsyncMock()
        reader.read.side_effect = list(chunks) + [b'']
        reader.readline.side_effect = list(lines) + [b'']
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        with patch.object(module.asyncio, 'open_connection', side_effect=error, return_value=(reader, writer)) as connect:
            result = await getattr(module, name)(target, **kwargs)
        return result, writer, connect, reader

    async def test_redis_positive_read_access_is_scoped_without_config_secret(self):
        info = b'redis_version:7.2.1\r\nrequirepass:private-token\r\n'
        result, writer, _, _ = await self.invoke('redis_enum', chunks=[b'+PONG\r\n', b'$' + str(len(info)).encode() + b'\r\n' + info + b'\r\n', b':12\r\n'])
        self.assertTrue(result['accessible'])
        self.assertTrue(result['no_auth'])
        self.assertEqual(result['keys_total'], 12)
        self.assertEqual(result['version'], '7.2.1')
        self.assertIn('observed commands', result['coverage'])
        self.assertNotIn('private-token', json.dumps(result))
        self.assertFalse(any(b'CONFIG' in call.args[0] for call in writer.write.call_args_list))

    async def test_redis_noauth_error_identifies_protocol_not_nonredis(self):
        result, writer, _, _ = await self.invoke('redis_enum', chunks=[b'-NOAUTH Authentication required.\r\n'])
        self.assertTrue(result['redis_available'])
        self.assertFalse(result['no_auth'])
        self.assertTrue(result['coverage_complete'])
        writer.close.assert_called_once()

    async def test_redis_embedded_pong_is_not_protocol_evidence(self):
        result, writer, _, _ = await self.invoke('redis_enum', chunks=[b'HTTP/1.1 200 OK\r\n\r\n+PONG private-token'])
        self.assertFalse(result['coverage_complete'])
        self.assertIsNone(result['redis_available'])
        self.assertNotIn('private-token', json.dumps(result))
        writer.close.assert_called_once()

    async def test_ldap_result_code_not_length_controls_bind_result(self):
        for code in (0, 49, 50):
            result, writer, _, _ = await self.invoke('ldap_enum', chunks=[ldap_reply(code, b'private-token')])
            self.assertTrue(result['ldap_available'])
            self.assertEqual(result['anonymous_bind'], code == 0)
            self.assertEqual(result['result_code'], code)
            self.assertNotIn('private-token', json.dumps(result))
            self.assertNotIn('response_hex', result)
            self.assertIn(b'\x80\x00', writer.write.call_args.args[0])
            self.assertFalse(result['privileged_access_confirmed'])

    async def test_ldap_unmatched_or_malformed_bytes_are_unknown(self):
        for response in (b'HTTP/1.0 200 OK\r\n', ldap_reply().replace(b'\x02\x01\x01', b'\x02\x01\x02', 1)):
            result, _, _, _ = await self.invoke('ldap_enum', chunks=[response])
            self.assertFalse(result['coverage_complete'])
            self.assertIsNone(result['anonymous_bind'])

    async def test_ldap_supplied_credentials_are_not_silently_ignored(self):
        result, _, connect, _ = await self.invoke('ldap_enum', username='admin', password='private-token')
        connect.assert_not_awaited()
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('private-token', json.dumps(result))

    async def test_smb_protocol_header_required_and_positive_retained(self):
        for data, positive in ((b'HTTP/1.1 200 OK\r\n', False), (smb_reply(), True)):
            result, writer, _, _ = await self.invoke('smb_enum', chunks=[data])
            self.assertEqual(result['smb_available'], True if positive else None)
            self.assertEqual(result['coverage_complete'], positive)
            writer.close.assert_called_once()

    async def test_smb_request_frame_length_matches_payload(self):
        _, writer, _, _ = await self.invoke('smb_enum', chunks=[smb_reply()])
        sent = writer.write.call_args.args[0]
        self.assertEqual(int.from_bytes(sent[:4], 'big'), len(sent) - 4)
        self.assertEqual(sent[4:8], b'\xfeSMB')

    async def test_smtp_multiline_consumed_and_252_not_user_proof(self):
        lines = [b'220 fixture ESMTP\r\n', b'250-fixture\r\n', b'250 HELP\r\n',
                 b'252 Cannot VRFY user private-token\r\n', b'550 No expansion\r\n', b'221 bye\r\n']
        result, _, _, _ = await self.invoke('smtp_enum', lines=lines, users='fixture')
        self.assertEqual(result['found_users'], [])
        self.assertEqual(result['results'][0]['status'], 252)
        self.assertIsNone(result['results'][0]['exists'])
        self.assertNotIn('private-token', json.dumps(result))
        self.assertTrue(result['coverage_complete'])

    async def test_smtp_positive_is_reported_not_independently_confirmed(self):
        result, _, _, _ = await self.invoke('smtp_enum', lines=[b'220 ready\r\n', b'250 hello\r\n', b'250 private-token mailbox\r\n', b'550 denied\r\n', b'221 bye\r\n'], users='fixture')
        self.assertEqual(result['found_users'], ['fixture'])
        self.assertEqual(result['results'][0]['evidence_type'], 'smtp_reply')
        self.assertFalse(result['results'][0]['independently_verified'])
        self.assertNotIn('private-token', json.dumps(result))

    async def test_smtp_user_injection_and_budget_rejected_before_connect(self):
        for users in ('admin\r\nMAIL FROM:x', ','.join('u' + str(i) for i in range(17))):
            result, _, connect, _ = await self.invoke('smtp_enum', users=users)
            connect.assert_not_awaited()
            self.assertFalse(result['coverage_complete'])

    async def test_snmp_tcp_reachability_is_not_snmp_or_community_proof(self):
        result, writer, connect, _ = await self.invoke('snmp_enum', community='private-token')
        self.assertTrue(result['tcp_open'])
        self.assertIsNone(result['snmp_available'])
        self.assertFalse(result['community_validated'])
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('private-token', json.dumps(result))
        self.assertEqual(connect.await_count, 1)
        writer.write.assert_not_called()

    async def test_timeout_and_refused_have_distinct_states(self):
        for name in NAMES:
            for error, state in ((asyncio.TimeoutError('private-token'), 'unknown'), (ConnectionRefusedError('private-token'), 'refused')):
                result, _, _, _ = await self.invoke(name, error=error)
                self.assertEqual(result['connection_state'], state)
                self.assertFalse(result['coverage_complete'])
                self.assertNotIn('private-token', json.dumps(result))

    async def test_invalid_target_never_connects(self):
        for name in NAMES:
            for target in ('https://[broken', 'fixture.test:99999', 'host\nprivate-token'):
                result, _, connect, _ = await self.invoke(name, target=target)
                connect.assert_not_awaited()
                self.assertFalse(result['coverage_complete'])
                self.assertNotIn('private-token', json.dumps(result))

    async def test_smb_truncated_body_and_wrong_message_id_are_incomplete(self):
        truncated = bytearray(smb_reply()[:68])
        truncated[:4] = (64).to_bytes(4, 'big')
        unmatched = bytearray(smb_reply())
        unmatched[28] = 1
        for response in (bytes(truncated), bytes(unmatched)):
            result, _, _, _ = await self.invoke('smb_enum', chunks=[response])
            self.assertFalse(result['coverage_complete'])

    async def test_fragmented_frames_preserve_positive_evidence(self):
        for name, response, field in (('smb_enum', smb_reply(), 'smb_available'),
                                      ('ldap_enum', ldap_reply(), 'anonymous_bind')):
            result, _, _, _ = await self.invoke(name, chunks=[response[:1], response[1:3], response[3:]], target='[::1]:1234')
            self.assertTrue(result[field])
            self.assertTrue(result['coverage_complete'])
        result, _, _, _ = await self.invoke('redis_enum', chunks=[b'-NO', b'AUTH required\r', b'\n'])
        self.assertTrue(result['redis_available'])
        self.assertFalse(result['no_auth'])

    async def test_declared_response_caps_stop_reads_and_close(self):
        for name, chunks in (('ldap_enum', [b'\x30\x82\xff\xff']),
                              ('smb_enum', [b'\x00\xff\xff\xff']),
                              ('redis_enum', [b'+PONG\r\n', b'$999999999\r\n'])):
            result, writer, _, reader = await self.invoke(name, chunks=chunks)
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(reader.read.await_count, len(chunks))
            writer.close.assert_called_once()

    async def test_smtp_multiline_cap_and_code_mismatch_are_incomplete(self):
        for lines in ([b'220 ready\r\n'] + [b'250-more\r\n'] * 17,
                      [b'220 ready\r\n', b'250-more\r\n', b'550 mismatch\r\n']):
            result, writer, _, reader = await self.invoke('smtp_enum', lines=lines, users='fixture')
            self.assertFalse(result['coverage_complete'])
            self.assertLessEqual(reader.readline.await_count, 17)
            writer.close.assert_called_once()

    async def test_all_adapters_have_total_deadline_and_cleanup(self):
        real_timeout = asyncio.timeout
        for name in NAMES:
            module = importlib.import_module('cyber_tools.' + name)
            reader, writer = AsyncMock(), Mock()
            reader.readline.return_value = b'220 ready\r\n'
            writer.wait_closed = AsyncMock()
            writer.drain = AsyncMock()
            async def blocked(*args, **kwargs):
                await asyncio.sleep(1)
            writer.drain.side_effect = blocked
            with patch.object(module.asyncio, 'timeout', side_effect=lambda _: real_timeout(.005)), \
                 patch.object(module.asyncio, 'open_connection', return_value=(reader, writer)) as connect:
                result = await getattr(module, name)('fixture.test')
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(connect.await_count, 1)
            writer.close.assert_called_once()

    async def test_noauth_does_not_mean_info_permission(self):
        result, writer, _, _ = await self.invoke('redis_enum', chunks=[b'+PONG\r\n', b'-NOPERM command denied\r\n'])
        self.assertFalse(result['no_auth'])
        self.assertEqual(result['unauthenticated_commands'], ['PING'])
        self.assertFalse(result['privileged_access_confirmed'])

    async def test_smtp_expansion_and_forwarding_are_not_verified_users(self):
        result, _, _, _ = await self.invoke('smtp_enum', users='fixture', lines=[
            b'220 ready\r\n', b'250 hello\r\n', b'251 forwarded private-token\r\n',
            b'250 list-member private-token\r\n', b'221 bye\r\n'])
        self.assertEqual(result['found_users'], [])
        self.assertTrue(all(row['exists'] is None for row in result['results']))
        self.assertNotIn('private-token', json.dumps(result))

    async def test_smb_error_response_is_protocol_evidence_not_access(self):
        payload = bytearray(smb_reply()[4:68]) + bytearray(8)
        struct.pack_into('<I', payload, 8, 0xc0000022)
        struct.pack_into('<H', payload, 64, 9)
        response = len(payload).to_bytes(4, 'big') + payload
        result, _, _, _ = await self.invoke('smb_enum', chunks=[response])
        self.assertTrue(result['smb_available'])
        self.assertEqual(result['status_code'], 0xc0000022)
        self.assertIn('privileges not tested', result['coverage'])


if __name__ == '__main__':
    unittest.main()
