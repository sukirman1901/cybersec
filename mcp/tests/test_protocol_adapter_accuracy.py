"""Protocol adapter evidence using only mocked sockets, streams and TLS."""
import asyncio
import importlib
import json
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ports = importlib.import_module('cyber_tools.port_scanner')
fingerprint = importlib.import_module('cyber_tools.service_fingerprint')
ssh = importlib.import_module('cyber_tools.ssh_audit')
tls = importlib.import_module('cyber_tools.ssl_analyzer')


def streams(data=b''):
    reader = AsyncMock()
    reader.read.return_value = data
    reader.readline.return_value = data
    writer = Mock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


class ProtocolAsyncAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_port_timeout_is_unknown_not_closed(self):
        with patch.object(ports.socket, 'gethostbyname', return_value='192.0.2.1'), \
             patch.object(ports.asyncio, 'open_connection', side_effect=asyncio.TimeoutError('private-token')):
            result = await ports.port_scanner('fixture.test', ports='22', timeout=.01)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['unknown_ports'], [22])
        self.assertNotIn('private-token', json.dumps(result))

    async def test_port_refused_is_completed_closed_observation(self):
        with patch.object(ports.socket, 'gethostbyname', return_value='192.0.2.1'), \
             patch.object(ports.asyncio, 'open_connection', side_effect=ConnectionRefusedError()):
            result = await ports.port_scanner('fixture.test', ports='22')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['closed_ports'], [22])

    async def test_invalid_port_inputs_make_no_dns_or_connections(self):
        with patch.object(ports.socket, 'gethostbyname') as dns, patch.object(ports.asyncio, 'open_connection', new_callable=AsyncMock) as connect:
            for port_spec in ('abc', '0', '65536', '4-2', '1-65535', '22,,80'):
                result = await ports.port_scanner('fixture.test', ports=port_spec)
                self.assertFalse(result['coverage_complete'])
                self.assertIn('error', result)
            for options in ({'concurrency': 0}, {'timeout': float('nan')}, {'timeout': -1}):
                result = await ports.port_scanner('fixture.test', ports='22', **options)
                self.assertFalse(result['coverage_complete'])
            dns.assert_not_called()
            connect.assert_not_awaited()

    async def test_open_port_preserved_without_vulnerability_claim(self):
        reader, writer = streams(b'-ERR redis private-token\r\n')
        with patch.object(ports.socket, 'gethostbyname', return_value='192.0.2.1'), \
             patch.object(ports.asyncio, 'open_connection', return_value=(reader, writer)):
            result = await ports.port_scanner('fixture.test', ports='6379,6379')
        self.assertEqual(result['open_ports'], [6379])
        self.assertEqual(result['ports_scanned'], 1)
        self.assertEqual(result['high_risk_services'], [])
        self.assertEqual(result['services'][0]['vuln_hints'], [])
        self.assertNotIn('private-token', json.dumps(result))

    async def test_service_positive_bounded_single_read_redacts_banner(self):
        reader, writer = streams(b'HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nSet-Cookie: private-token\r\n\r\n')
        with patch.object(fingerprint.asyncio, 'open_connection', return_value=(reader, writer)):
            result = await fingerprint.service_fingerprint('https://fixture.test', 443)
        self.assertEqual(result['service'], 'http')
        self.assertEqual(reader.read.await_count, 1)
        self.assertNotIn('private-token', json.dumps(result))
        self.assertTrue(result['coverage_complete'])

    async def test_https_uses_tls_and_correct_host(self):
        reader, writer = streams(b'HTTP/1.1 200 OK\r\n\r\n')
        with patch.object(fingerprint.asyncio, 'open_connection', return_value=(reader, writer)) as connect:
            await fingerprint.service_fingerprint('https://fixture.test:8443/path', 443)
        self.assertEqual(connect.call_args.args[:2], ('fixture.test', 8443))
        self.assertIsInstance(connect.call_args.kwargs.get('ssl'), ssl.SSLContext)

    async def test_stream_errors_are_incomplete_and_writers_closed(self):
        for module, name in ((fingerprint, 'service_fingerprint'), (ssh, 'ssh_audit')):
            reader, writer = streams()
            reader.read.side_effect = OSError('private-token')
            reader.readline.side_effect = OSError('private-token')
            with patch.object(module.asyncio, 'open_connection', return_value=(reader, writer)):
                result = await getattr(module, name)('fixture.test')
            self.assertFalse(result['coverage_complete'])
            writer.close.assert_called_once()
            self.assertNotIn('private-token', json.dumps(result))

    async def test_ssh_banner_not_algorithm_or_version_vulnerability(self):
        reader, writer = streams(b'SSH-2.0-OpenSSH_9.1.5 CBC private-token\r\n')
        with patch.object(ssh.asyncio, 'open_connection', return_value=(reader, writer)):
            result = await ssh.ssh_audit('[::1]:2222')
        self.assertEqual(result['ssh_version'], '2.0')
        self.assertEqual(result['weak_algorithms'], [])
        self.assertNotIn('private-token', json.dumps(result))
        self.assertIn('not enumerated', result['coverage'])

    async def test_ssh_malformed_and_empty_are_incomplete(self):
        for data in (b'', b'Welcome SSH-2.0 somewhere', b'SSH-2.0-' + b'x' * 512):
            reader, writer = streams(data)
            with patch.object(ssh.asyncio, 'open_connection', return_value=(reader, writer)):
                result = await ssh.ssh_audit('fixture.test')
            self.assertFalse(result['coverage_complete'])

    async def test_invalid_stream_targets_no_connection(self):
        for module, name in ((fingerprint, 'service_fingerprint'), (ssh, 'ssh_audit')):
            with patch.object(module.asyncio, 'open_connection', new_callable=AsyncMock) as connect:
                for target in ('https://[broken', 'host:99999', 'host\r\nprivate-token'):
                    result = await getattr(module, name)(target)
                    self.assertFalse(result['coverage_complete'])
                    self.assertNotIn('private-token', json.dumps(result))
                connect.assert_not_awaited()

    async def test_port_attempt_budget_and_skipped_banners_are_explicit(self):
        reader, writer = streams(b'HTTP/1.0 200 OK\r\n\r\n')
        with patch.object(ports.asyncio, 'open_connection', return_value=(reader, writer)) as connect:
            result = await ports.port_scanner('192.0.2.1', ports='1000-1019')
        self.assertEqual(connect.await_count, 36)
        self.assertEqual(result['requests_attempted'], 36)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['total_open'], 20)

    async def test_total_port_deadline_stops_pending_attempts(self):
        cancelled = []
        async def slow(*args, **kwargs):
            try:
                await asyncio.sleep(1)
            finally:
                cancelled.append(True)
        with patch.object(ports, 'SCAN_SECONDS', .01), patch.object(ports.asyncio, 'open_connection', side_effect=slow):
            result = await ports.port_scanner('192.0.2.1', ports='20-25', concurrency=2)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['unknown_ports'], list(range(20, 26)))
        self.assertEqual(result['requests_attempted'], 2)
        self.assertEqual(len(cancelled), 2)

    async def test_ssh_fragmented_identification_preserves_positive(self):
        reader, writer = streams()
        reader.read.side_effect = [b'SSH-2.0-', b'OpenSSH_9.0\r\n']
        with patch.object(ssh.asyncio, 'open_connection', return_value=(reader, writer)):
            result = await ssh.ssh_audit('fixture.test')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['ssh_version'], '2.0')

    async def test_service_read_and_drain_have_total_deadline(self):
        # Replace the timeout duration only; the real cancellation context runs.
        real_timeout = asyncio.timeout
        reader, writer = streams()
        async def slow():
            await asyncio.sleep(1)
        writer.drain.side_effect = slow
        with patch.object(fingerprint.asyncio, 'timeout', side_effect=lambda _: real_timeout(.01)), \
             patch.object(fingerprint.asyncio, 'open_connection', return_value=(reader, writer)):
            result = await fingerprint.service_fingerprint('fixture.test', 80)
        self.assertFalse(result['coverage_complete'])
        writer.close.assert_called_once()
        reader.read.assert_not_awaited()


class ProtocolTLSAccuracy(unittest.TestCase):
    def invoke(self, cert=None, error=None):
        context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        secure = Mock()
        secure.getpeercert.return_value = cert if cert is not None else {
            'subject': ((('commonName', 'fixture.test'),), (('organizationName', 'Fixture'),)),
            'issuer': ((('commonName', 'Fixture CA'),),), 'serialNumber': '01AB',
            'notBefore': 'Jan  1 00:00:00 2020 GMT', 'notAfter': 'Jan  1 00:00:00 2040 GMT'}
        secure.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        secure.version.return_value = 'TLSv1.3'
        context.wrap_socket.return_value.__enter__ = Mock(return_value=secure)
        context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
        if error:
            context.wrap_socket.side_effect = error
        with patch.object(tls.ssl, 'create_default_context', return_value=context), \
             patch.object(tls.socket, 'create_connection') as connect:
            result = tls.ssl_analyze('https://fixture.test:8443/path?token=private-token')
        return result, context, connect

    def test_verified_certificate_serial_dates_and_hostname(self):
        result, context, connect = self.invoke()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(result['certificate_validated'])
        self.assertTrue(result['hostname_validated'])
        self.assertFalse(result['certificate']['expired'])
        self.assertEqual(result['certificate']['serial'], '01AB')
        self.assertEqual(result['certificate']['subject']['organizationName'], 'Fixture')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(connect.call_args.args[0], ('fixture.test', 8443))

    def test_certificate_verification_error_is_not_secure(self):
        for code in (10, 62, 18):
            error = ssl.SSLCertVerificationError('private-token')
            error.verify_code = code
            result, _, _ = self.invoke(error=error)
            self.assertFalse(result['coverage_complete'])
            self.assertFalse(result['certificate_validated'])
            self.assertNotIn('private-token', json.dumps(result))
            self.assertIn('error', result)

    def test_missing_or_malformed_cert_is_incomplete(self):
        for cert in ({}, {'serialNumber': 'ABC', 'notAfter': 'not-a-date'}):
            result, _, _ = self.invoke(cert=cert)
            self.assertFalse(result['coverage_complete'])

    def test_bad_tls_target_never_connects(self):
        with patch.object(tls.socket, 'create_connection') as connect:
            for target in ('https://[broken', 'fixture.test:99999', 'https:///missing', 'host\nprivate-token'):
                result = tls.ssl_analyze(target)
                self.assertFalse(result['coverage_complete'])
                self.assertNotIn('private-token', json.dumps(result))
            connect.assert_not_called()

    def test_expired_mock_certificate_not_reported_valid(self):
        result, _, _ = self.invoke(cert={'serialNumber': 'AB', 'notBefore': 'Jan  1 00:00:00 2000 GMT',
                                        'notAfter': 'Jan  1 00:00:00 2001 GMT'})
        self.assertFalse(result['certificate_validated'])
        self.assertTrue(result['certificate']['expired'])
        self.assertFalse(result['coverage_complete'])

    def test_legacy_scan_error_is_not_empty_closed_result(self):
        with patch.object(ports.asyncio, 'open_connection', side_effect=asyncio.TimeoutError('private-token')):
            with self.assertRaisesRegex(OSError, 'TCP scan incomplete') as caught:
                ports.scan_ports('192.0.2.1', [22])
        self.assertNotIn('private-token', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
