"""Synthetic archives/media only; all HTTP and TLS connections are mocked."""
import asyncio
import io
import json
import os
from pathlib import Path
import plistlib
import socket
import ssl
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib
import warnings
import threading

import httpx
from cyber_tools.apk_analyze import apk_analyze
from cyber_tools.ipa_analyze import ipa_analyze
from cyber_tools.ios_data_storage import ios_data_storage
from cyber_tools.ios_signing import ios_signing
from cyber_tools.ssl_pinning_check import ssl_pinning_check
from cyber_tools.stego_detect import stego_detect


class Response:
    def __init__(self, content=b'', status=200, headers=None):
        self.content = content
        self.status_code = status
        self.headers = headers or {}
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        pass
    async def aiter_bytes(self, chunk_size=8192):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset:offset + chunk_size]


class Client:
    def __init__(self, response):
        self.response = response
        self.calls = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        pass
    def stream(self, method, target):
        self.calls.append(target)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response
    async def get(self, target):
        return self.stream('GET', target)


class Connection:
    def __init__(self, cert=None):
        self.cert = cert
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def getpeercert(self):
        return self.cert


class MobileArtifactAccuracy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def call(self, tool, *args, **kwargs):
        return asyncio.run(tool(*args, **kwargs))

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return str(path)

    def archive(self, entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                with warnings.catch_warnings():
                    warnings.filterwarnings('ignore', message='Duplicate name:', category=UserWarning)
                    archive.writestr(name, data)
        return stream.getvalue()

    def ipa(self, extra=(), info=None):
        return self.archive([('Payload/Test.app/Info.plist', plistlib.dumps({'CFBundleIdentifier': 'fixture.app'} if info is None else info)), *extra])

    def apk(self, data, status=200):
        client = Client(Response(data, status))
        with patch('cyber_tools.apk_analyze.GuardedAsyncClient', return_value=client):
            result = self.call(apk_analyze, 'https://fixture.invalid/app.apk')
        self.assertLessEqual(len(client.calls), 1)
        return result

    def test_apk_xml_permissions_and_exported_attribute_order(self):
        manifest = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="fixture.app"><uses-permission android:name="android.permission.CAMERA"/><application><activity android:name=".Main" android:exported="true"/></application></manifest>'
        result = self.apk(self.archive([('AndroidManifest.xml', manifest), ('classes.dex', b'synthetic')]))
        self.assertEqual(result.get('permissions_count'), 1)
        self.assertTrue(any(f.get('exported_count') == 1 for f in result['findings']))
        self.assertFalse(any(f.get('severity') == 'high' for f in result['findings']))

    def test_apk_binary_axml_and_missing_manifest_incomplete(self):
        for entries in [[('AndroidManifest.xml', b'\x03\x00\x08\x00' + b'x' * 2000)], [('padding', b'x' * 2000)]]:
            result = self.apk(self.archive(entries))
            self.assertIs(result.get('coverage_complete'), False)
            self.assertTrue(result.get('error') or result.get('errors'))

    def test_apk_xml_comments_not_permissions(self):
        manifest = b'<manifest package="fixture.app"><!-- android.permission.READ_SMS --><application/></manifest>'
        result = self.apk(self.archive([('AndroidManifest.xml', manifest)]))
        self.assertEqual(result.get('permissions_count'), 0)

    def test_apk_http_errors_and_download_bound(self):
        for response in [Response(b'sensitive-response', 403), Response(b'x' * (17 * 1024 * 1024)), httpx.ConnectError('sensitive-error')]:
            with patch('cyber_tools.apk_analyze.GuardedAsyncClient', return_value=Client(response)):
                result = self.call(apk_analyze, 'https://fixture.invalid/app.apk')
            self.assertIs(result.get('coverage_complete'), False)
            self.assertNotIn('sensitive-', json.dumps(result))

    def test_ipa_main_plist_not_framework_and_no_fake_entitlements(self):
        data = self.archive([('Payload/Test.app/Frameworks/F.framework/Info.plist', plistlib.dumps({'fake_entitlement': 'sensitive-value'})),
                             ('Payload/Test.app/Info.plist', plistlib.dumps({'CFBundleIdentifier': 'fixture.app', 'keychain-hint': 'sensitive-value'}))])
        result = self.call(ipa_analyze, self.file('app.ipa', data))
        self.assertTrue(result['plist_found'])
        self.assertEqual(result['entitlements'], {})
        self.assertNotIn('sensitive-value', json.dumps(result))
        self.assertIn('coverage', result)

    def test_storage_values_redacted_and_not_nsuserdefaults_proof(self):
        data = self.ipa([('Payload/Test.app/data.sqlite', b'synthetic')], {'password': 'sensitive-password', 'token': 'sensitive-token'})
        result = self.call(ios_data_storage, self.file('app.ipa', data))
        self.assertEqual(result['sensitive_keys_count'], 2)
        self.assertEqual(result['storage_files_count'], 1)
        self.assertNotIn('sensitive-', json.dumps(result))
        self.assertIn('not', result.get('coverage', '').lower())
        self.assertEqual(result.get('assessment'), 'candidate')

    def test_signing_development_not_adhoc_and_private_values_redacted(self):
        profile = {'TeamName': 'private-team', 'ProvisionedDevices': ['private-device-identifier'],
                   'Entitlements': {'get-task-allow': True, 'keychain-access-groups': ['private-keychain']}}
        data = self.ipa([('Payload/Test.app/embedded.mobileprovision', b'CMS-PREFIX' + plistlib.dumps(profile) + b'TAIL')])
        result = self.call(ios_signing, self.file('app.ipa', data))
        self.assertIs(result.get('is_adhoc'), False)
        self.assertEqual(result.get('profile_type'), 'development')
        self.assertIs(result.get('signature_verified'), False)
        self.assertNotIn('private-', json.dumps(result))

    def test_signing_adhoc_and_malformed_profiles(self):
        profile = {'ProvisionedDevices': ['fixture-device'], 'Entitlements': {'get-task-allow': False}}
        result = self.call(ios_signing, self.file('app.ipa', self.ipa([('Payload/Test.app/embedded.mobileprovision', plistlib.dumps(profile))])))
        self.assertIs(result.get('is_adhoc'), True)
        for content in [b'not a profile', plistlib.dumps([]), plistlib.dumps({'Entitlements': []})]:
            result = self.call(ios_signing, self.file('app.ipa', self.ipa([('Payload/Test.app/embedded.mobileprovision', content)])))
            self.assertIs(result.get('coverage_complete'), False)

    def test_local_zip_missing_invalid_non_object(self):
        for tool in [ipa_analyze, ios_data_storage, ios_signing]:
            for data in [b'not ZIP', self.archive([('other.txt', b'fixture')]), self.ipa(info=[])]:
                with self.subTest(tool=tool.__name__):
                    result = self.call(tool, self.file('bad.ipa', data))
                    self.assertIs(result.get('coverage_complete'), False)

    def test_archive_traversal_symlink_duplicate_and_member_bound(self):
        link = zipfile.ZipInfo('Payload/Test.app/link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = [[('../escape', b'fixture')], [(link, b'/private/fixture')],
                 [('Payload/Test.app/Info.plist', plistlib.dumps({}))], [('large', b'x' * (2 * 1024 * 1024))]]
        for extra in cases:
            data = self.ipa(extra)
            for tool in [ipa_analyze, ios_data_storage, ios_signing]:
                with self.subTest(tool=tool.__name__, extra=str(extra[0][0])):
                    result = self.call(tool, self.file('bad.ipa', data))
                    self.assertIs(result.get('coverage_complete'), False)
            result = self.apk(data)
            self.assertIs(result.get('coverage_complete'), False)
        self.assertFalse((self.root / 'escape').exists())

    def test_archive_directory_and_aggregate_budgets(self):
        cases = [self.ipa([(f'entry-{i}', b'') for i in range(1001)]),
                 self.ipa([(f'entry-{i}', b'x' * (1024 * 1024)) for i in range(33)])]
        for data in cases:
            for tool in [ipa_analyze, ios_data_storage, ios_signing]:
                self.assertIs(self.call(tool, self.file('budget.ipa', data)).get('coverage_complete'), False)
            self.assertIs(self.apk(data).get('coverage_complete'), False)

    def test_archive_multiple_apps_and_binary_plist(self):
        data = self.ipa([('Payload/Other.app/Info.plist', plistlib.dumps({}))])
        for tool in [ipa_analyze, ios_data_storage, ios_signing]:
            self.assertIs(self.call(tool, self.file('ambiguous.ipa', data)).get('coverage_complete'), False)
        data = self.archive([('Payload/Test.app/Info.plist', plistlib.dumps({'CFBundleIdentifier': 'fixture.app'}, fmt=plistlib.FMT_BINARY))])
        self.assertTrue(self.call(ipa_analyze, self.file('binary.ipa', data))['plist_found'])

    def test_no_archive_extraction_or_executables(self):
        path = self.file('app.ipa', self.ipa())
        with patch('zipfile.ZipFile.extractall', side_effect=AssertionError('No extraction')), \
             patch('zipfile.ZipFile.extract', side_effect=AssertionError('No extraction')), \
             patch('subprocess.run', side_effect=AssertionError('No executable')), \
             patch('asyncio.create_subprocess_exec', side_effect=AssertionError('No executable')):
            for tool in [ipa_analyze, ios_data_storage, ios_signing]:
                self.call(tool, path)
            self.apk(self.archive([('AndroidManifest.xml', b'<manifest><application/></manifest>')]))

    def test_inventory_and_storage_display_limits(self):
        data = self.ipa([(f'Payload/Test.app/part-{i}.dylib', b'') for i in range(21)])
        result = self.call(ipa_analyze, self.file('inventory.ipa', data))
        self.assertEqual(len(result['suspicious_files']), 20)
        self.assertTrue(result.get('truncated'))
        self.assertIs(result['coverage_complete'], False)
        data = self.ipa([(f'Payload/Test.app/part-{i}.db', b'') for i in range(21)])
        result = self.call(ios_data_storage, self.file('storage.ipa', data))
        self.assertEqual(len(result['storage_files']['sqlite']), 20)
        self.assertIs(result['coverage_complete'], False)

    def test_signing_device_platform_limits_and_flag_types(self):
        profile = {'ProvisionedDevices': ['private-device'] * 21, 'Entitlements': {'get-task-allow': False}, 'Platform': ['iOS'] * 21}
        data = self.ipa([('Payload/Test.app/embedded.mobileprovision', plistlib.dumps(profile))])
        result = self.call(ios_signing, self.file('profile.ipa', data))
        self.assertLessEqual(len(result['platform']), 20)
        self.assertLessEqual(len(result['provisioned_devices']), 20)
        self.assertIs(result['coverage_complete'], False)
        profile = {'ProvisionedDevices': ['fixture'], 'Entitlements': {'get-task-allow': 'false'}}
        data = self.ipa([('Payload/Test.app/embedded.mobileprovision', plistlib.dumps(profile))])
        self.assertIs(self.call(ios_signing, self.file('profile.ipa', data))['coverage_complete'], False)

    def test_ipa_plist_entity_is_rejected(self):
        xml = b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY value "private-value">]><plist version="1.0"><dict><key>token</key><string>&value;</string></dict></plist>'
        data = self.archive([('Payload/Test.app/Info.plist', xml)])
        for tool in [ipa_analyze, ios_data_storage, ios_signing]:
            result = self.call(tool, self.file('entity.ipa', data))
            self.assertIs(result.get('coverage_complete'), False)
            self.assertNotIn('private-value', json.dumps(result))

    def test_local_input_types_size_and_symlinks(self):
        for tool in [ipa_analyze, ios_data_storage, ios_signing, stego_detect]:
            for path in [None, str(self.root / 'missing')]:
                with self.subTest(tool=tool.__name__, path=path):
                    self.assertIn('error', self.call(tool, path))
            path = self.file('large.bin', b'')
            with open(path, 'wb') as stream:
                stream.truncate(32 * 1024 * 1024 + 1)
            with patch('builtins.open', side_effect=AssertionError('Oversize open')):
                result = self.call(tool, path)
            self.assertIs(result.get('coverage_complete'), False)
            link = self.root / 'link.bin'
            os.symlink(path, link)
            self.assertIs(self.call(tool, str(link)).get('coverage_complete'), False)
            link.unlink()

    def test_local_open_time_swaps_and_read_failures(self):
        import builtins
        real_open = builtins.open
        for tool in [ipa_analyze, ios_data_storage, ios_signing, stego_detect]:
            path = self.file('swap.ipa', self.ipa())
            external = self.file('external.ipa', self.ipa(info={'token': 'private-value'}))
            def swapped(file, *args, **kwargs):
                if file == path:
                    os.unlink(path)
                    os.symlink(external, path)
                return real_open(file, *args, **kwargs)
            with patch('builtins.open', side_effect=swapped):
                result = self.call(tool, path)
            self.assertIs(result.get('coverage_complete'), False)
            os.unlink(path)
            path = self.file('read.bin', b'fixture')
            with patch('builtins.open', side_effect=PermissionError('private-error')):
                result = self.call(tool, path)
            self.assertIs(result.get('coverage_complete'), False)
            self.assertNotIn('private-error', json.dumps(result))

    def tls(self, cert, target='fixture.invalid', error=None):
        connection = Connection(cert)
        context = type('Context', (), {'wrap_socket': lambda self, *args, **kwargs: connection})()
        client = Client(Response(headers={'strict-transport-security': 'max-age=31536000; includeSubDomains'}))
        with patch('cyber_tools.ssl_pinning_check.ssl.create_default_context', return_value=context), \
             patch('cyber_tools.ssl_pinning_check.socket.create_connection', side_effect=error, return_value=connection) as connect, \
             patch('cyber_tools.ssl_pinning_check.httpx.AsyncClient', return_value=client):
            result = self.call(ssl_pinning_check, target)
        return result, connect.call_args_list

    def test_tls_nested_certificate_names_not_error_or_pinning_proof(self):
        cert = {'subject': ((('commonName', 'fixture.invalid'),),), 'issuer': ((('organizationName', 'Fixture CA'),),),
                'version': 3, 'notAfter': 'Nov  5 00:00:00 2030 GMT', 'subjectAltName': (('DNS', 'fixture.invalid'),)}
        result, calls = self.tls(cert)
        self.assertFalse(any(f.get('finding') == 'Connection error' for f in result['findings']))
        self.assertEqual(result.get('pinning_status'), 'not_assessed')
        self.assertEqual(len(calls), 1)

    def test_tls_verification_failure_is_not_pinning(self):
        result, _ = self.tls({}, error=ssl.SSLCertVerificationError('private-error'))
        self.assertEqual(result.get('pinning_status'), 'not_assessed')
        self.assertNotIn('private-error', json.dumps(result))
        self.assertFalse(any('may indicate ssl pinning' in str(f).lower() for f in result['findings']))
        self.assertIs(result.get('coverage_complete'), False)

    def test_tls_url_and_ipv6_host_parsing(self):
        for target, host in [('https://fixture.invalid/path', 'fixture.invalid'), ('[::1]', '::1')]:
            result, calls = self.tls({}, target)
            self.assertEqual(calls[0].args[0][0], host)
            self.assertEqual(result.get('pinning_status'), 'not_assessed')

    def test_tls_invalid_inputs_no_connection(self):
        with patch('socket.create_connection', side_effect=AssertionError('No connection')), patch('httpx.AsyncClient', side_effect=AssertionError('No client')):
            for target, port in [(None, 443), ('fixture.invalid', True), ('fixture.invalid', 70000), ('https://user:secret@fixture.invalid', 443), ('https://fixture.invalid:0', 443)]:
                self.assertIn('error', self.call(ssl_pinning_check, target, port))

    def test_tls_malformed_metadata_and_hsts_error_redaction(self):
        result, _ = self.tls({'subject': 'private-malformed-value'})
        self.assertFalse(result['tls_observations_complete'])
        self.assertNotIn('private-malformed-value', json.dumps(result))
        connection = Connection({'subject': (), 'issuer': (), 'version': 3})
        context = type('Context', (), {'wrap_socket': lambda self, *args, **kwargs: connection})()
        with patch('ssl.create_default_context', return_value=context), patch('socket.create_connection', return_value=connection), patch('httpx.AsyncClient', return_value=Client(httpx.ConnectError('private-error'))):
            result = self.call(ssl_pinning_check, 'fixture.invalid')
        self.assertFalse(result['tls_observations_complete'])
        self.assertNotIn('private-error', json.dumps(result))

    def test_tls_worker_does_not_block_async_heartbeat(self):
        entered, release = threading.Event(), threading.Event()
        observed = []
        connection = Connection({'subject': (), 'issuer': (), 'version': 3})
        context = type('Context', (), {'wrap_socket': lambda self, *args, **kwargs: connection})()
        def blocking_factory(*args, **kwargs):
            entered.set()
            observed.append(release.wait(timeout=0.5))
            return connection
        async def scenario():
            async def heartbeat():
                while not entered.is_set():
                    await asyncio.sleep(0)
                release.set()
            try:
                with patch('ssl.create_default_context', return_value=context), patch('socket.create_connection', side_effect=blocking_factory), patch('httpx.AsyncClient', return_value=Client(Response())):
                    await asyncio.wait_for(asyncio.gather(ssl_pinning_check('fixture.invalid'), heartbeat()), timeout=2)
            finally:
                release.set()
        asyncio.run(scenario())
        self.assertEqual(observed, [True], 'Heartbeat must run while the synthetic TLS factory is blocked')

    def test_tls_bounded_await_reports_worker_lifetime_and_closes_later(self):
        release, closed = threading.Event(), threading.Event()
        class TrackedConnection(Connection):
            def __exit__(self, *args):
                closed.set()
        connection = TrackedConnection({'subject': (), 'issuer': (), 'version': 3})
        context = type('Context', (), {'wrap_socket': lambda self, *args, **kwargs: connection})()
        def blocking_factory(*args, **kwargs):
            release.wait(timeout=0.5)
            return connection
        async def scenario():
            try:
                with patch('cyber_tools.ssl_pinning_check.TLS_AWAIT_TIMEOUT', 0.01, create=True), patch('ssl.create_default_context', return_value=context), patch('socket.create_connection', side_effect=blocking_factory), patch('httpx.AsyncClient', return_value=Client(Response())):
                    result = await ssl_pinning_check('fixture.invalid')
                    self.assertFalse(result['tls_observations_complete'])
                    self.assertTrue(any('deadline' in error.lower() for error in result['errors']))
                    self.assertIn('resolver', result['coverage'].lower())
                    self.assertFalse(closed.is_set())
                    release.set()
                    self.assertTrue(await asyncio.to_thread(closed.wait, 1))
            finally:
                release.set()
        asyncio.run(scenario())

    def test_tls_invalid_hostname_labels_no_connection(self):
        with patch('socket.create_connection', side_effect=AssertionError('No connection')), patch('httpx.AsyncClient', side_effect=AssertionError('No client')):
            for host in ['bad..example', '.example', '-bad.example', 'bad-.example', 'a' * 64 + '.example']:
                with self.subTest(host=host):
                    self.assertIn('error', self.call(ssl_pinning_check, host))

    def test_tls_findings_have_confidence_and_coverage(self):
        for error in [None, ssl.SSLCertVerificationError('synthetic')]:
            result, _ = self.tls({'subject': (), 'issuer': (), 'version': 3}, error=error)
            self.assertTrue(result['findings'])
            for finding in result['findings']:
                self.assertIn(finding.get('confidence'), {'low', 'medium', 'high'})
                self.assertTrue(finding.get('coverage'))

    def png(self, suffix=b''):
        def chunk(kind, body):
            return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body))
        return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\0\0\0\0')) + chunk(b'IEND', b'') + suffix

    def test_stego_real_png_trailing_data_not_fake_iend(self):
        result = self.call(stego_detect, self.file('real.png', self.png(b'AB')))
        self.assertTrue(any(f.get('type') == 'trailing_data' and f.get('size') == 2 for f in result['findings']))
        result = self.call(stego_detect, self.file('fake.png', b'notpng IEND' + b'x' * 20))
        self.assertFalse(any(f.get('type') == 'trailing_data' for f in result['findings']))
        self.assertIs(result.get('coverage_complete'), False)

    def test_stego_secret_values_redacted_and_word_boundaries(self):
        result = self.call(stego_detect, self.file('raw.bin', b'password=private-value\0notpassword=otherprivate\0'))
        self.assertEqual(len([f for f in result['findings'] if f.get('type') == 'embedded_secret']), 1)
        self.assertNotIn('private-value', json.dumps(result))
        self.assertEqual(result['findings'][0].get('assessment'), 'candidate')

    def test_stego_size_and_exif_presence_not_steganography_proof(self):
        result = self.call(stego_detect, self.file('clean.png', self.png()))
        self.assertFalse(result['suspicious'])
        result = self.call(stego_detect, self.file('fake.jpg', b'random\xff\xe1random'))
        self.assertFalse(any(f.get('type') == 'exif_found' for f in result['findings']))
        self.assertIs(result.get('coverage_complete'), False)

    def test_stego_jpeg_exif_positive_and_xmp_negative(self):
        for body, expected in [(b'Exif\0\0fixture', True), (b'http://ns.adobe.com/xap/1.0/\0fixture', False)]:
            data = b'\xff\xd8\xff\xe1' + struct.pack('>H', len(body) + 2) + body + b'\xff\xd9'
            result = self.call(stego_detect, self.file('metadata.jpg', data))
            self.assertEqual(any(f['type'] == 'exif_found' for f in result['findings']), expected)
            self.assertFalse(result['suspicious'])

    def test_stego_bmp_not_png_and_bad_crc(self):
        data = b'BM' + struct.pack('<I', 26) + b'\0' * 8 + b'IEND' + b'x' * 8
        result = self.call(stego_detect, self.file('fixture.bmp', data))
        self.assertFalse(result['suspicious'])
        data = bytearray(self.png())
        data[29] ^= 1
        self.assertIs(self.call(stego_detect, self.file('corrupt.png', data))['coverage_complete'], False)

    def test_stego_string_limits(self):
        result = self.call(stego_detect, self.file('many.bin', b'password=private-value\0' * 101))
        self.assertLessEqual(len(result['findings']), 100)
        self.assertTrue(result['truncated'])
        self.assertIs(result['coverage_complete'], False)


if __name__ == '__main__':
    unittest.main()
