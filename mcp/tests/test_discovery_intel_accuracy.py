"""Offline discovery fixtures. HTTP, DNS, WHOIS and subprocesses are mocked."""
import asyncio
import importlib
import json
import os
import signal
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SECRET = 'synthetic-source-secret'
MODULES = ('subdomain_enum', 'origin_ip_discovery', 'sub_takeover')


async def invoke(name, handler, dns=None):
    module = importlib.import_module('cyber_tools.' + name)
    seen, resolutions = [], []
    def offline(request):
        seen.append(request)
        return handler(request)
    def resolve(host):
        resolutions.append(host)
        if dns:
            return dns(host)
        raise socket.gaierror(socket.EAI_NONAME, 'synthetic absent')
    original = httpx.AsyncClient
    def factory(**kwargs):
        kwargs['transport'] = httpx.MockTransport(offline)
        return original(**kwargs)
    with patch.object(httpx, 'AsyncClient', side_effect=factory), patch('socket.gethostbyname', side_effect=resolve):
        function = module.enumerate_subdomains if name == 'subdomain_enum' else getattr(module, name)
        result = await function('fixture.test')
    return result, seen, resolutions


def provider_empty(request):
    if request.url.host == 'crt.sh':
        return httpx.Response(200, json=[])
    if request.url.host == 'api.hackertarget.com':
        return httpx.Response(200, text='')
    return httpx.Response(200, json={'response_code':'1', 'subdomains':[]})


class DiscoveryIntelAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_scope_boundary_and_mixed_provider_positives(self):
        def handler(request):
            if request.url.host == 'crt.sh':
                return httpx.Response(200, json=[{'name_value':'api.fixture.test\nnotfixture.test\nfixture.test.evil.test\n*.fixture.test'}])
            if request.url.host == 'api.hackertarget.com':
                return httpx.Response(200, text='mail.fixture.test,192.0.2.1\nnotfixture.test,192.0.2.2\n' + SECRET)
            return httpx.Response(200, json={'response_code':'1', 'subdomains':['www.fixture.test','notfixture.test']})
        result, seen, _ = await invoke('subdomain_enum', handler)
        self.assertEqual(set(result['subdomains']), {'api.fixture.test','mail.fixture.test','www.fixture.test'})
        self.assertFalse(result.get('scope_authorized', True))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertLessEqual(len(seen), 3)

    async def test_dns_wildcard_is_not_many_discovered_hosts(self):
        result, _, dns = await invoke('subdomain_enum', provider_empty, dns=lambda host: '192.0.2.1')
        self.assertFalse(result['subdomains'])
        self.assertTrue(result.get('wildcard_dns'))
        self.assertLessEqual(len(dns), 26)
        self.assertFalse(result['coverage_complete'])

    async def test_positive_dns_candidate_is_retained_and_bounded(self):
        def dns(host):
            if host == 'api.fixture.test':
                return '192.0.2.2'
            raise socket.gaierror(socket.EAI_NONAME, 'absent')
        result, _, resolutions = await invoke('subdomain_enum', provider_empty, dns=dns)
        self.assertIn('api.fixture.test', result['subdomains'])
        self.assertLessEqual(len(resolutions), 26)
        self.assertGreater(result.get('dns_candidates_deferred', 0), 0)

    async def test_http_errors_timeouts_malformed_and_size_limits(self):
        for name in MODULES:
            for kind in ('429', '503', 'redirect', 'timeout', 'oversize'):
                def handler(request):
                    if kind == 'timeout':
                        raise httpx.ReadTimeout(SECRET, request=request)
                    if kind == 'oversize':
                        return httpx.Response(200, content=b'x' * 262145)
                    return httpx.Response(302 if kind == 'redirect' else int(kind), headers={'location':'https://outside.test/'}, text=SECRET)
                with self.subTest(tool=name, kind=kind):
                    result, seen, _ = await invoke(name, handler)
                    self.assertFalse(result.get('coverage_complete', True))
                    self.assertTrue(result.get('error'))
                    self.assertNotIn(SECRET, json.dumps(result))
                    self.assertTrue(all(r.url.host != 'outside.test' for r in seen))
                    self.assertLessEqual(len(seen), 3 if name=='subdomain_enum' else 1)

    async def test_malformed_provider_schema_not_empty_success(self):
        for name in ('subdomain_enum', 'origin_ip_discovery'):
            for data in (None, {'error':SECRET}, [None]):
                with self.subTest(tool=name, data=type(data).__name__):
                    result, _, _ = await invoke(name, lambda r: httpx.Response(200, json=data))
                    self.assertFalse(result.get('coverage_complete', True))
                    self.assertTrue(result.get('error'))
                    self.assertNotIn(SECRET, json.dumps(result))

    async def test_provider_result_caps_are_explicit(self):
        def handler(request):
            if request.url.host == 'crt.sh':
                return httpx.Response(200, json=[{'name_value':f'n{i}.fixture.test'} for i in range(601)])
            return provider_empty(request)
        result, _, _ = await invoke('subdomain_enum', handler)
        self.assertLessEqual(result['count'], 200)
        self.assertTrue(result.get('truncated'))
        self.assertFalse(result['coverage_complete'])

    async def test_empty_success_distinguished_from_provider_incomplete(self):
        result, _, _ = await invoke('subdomain_enum', provider_empty)
        self.assertFalse(result['subdomains'])
        self.assertTrue(result['selected_sources_complete'])
        self.assertEqual(result['assessment'], 'no_candidates_in_selected_checks')
        self.assertNotIn('error', result)
        result, _, _ = await invoke('origin_ip_discovery', lambda r: httpx.Response(200,json=[]))
        self.assertFalse(result['ip_addresses'])
        self.assertTrue(result['selected_checks_complete'])
        self.assertNotIn('error', result)

    async def test_dns_provider_errors_are_not_nxdomain(self):
        def fail(host):
            raise socket.gaierror(socket.EAI_AGAIN, SECRET)
        for name in ('subdomain_enum','origin_ip_discovery'):
            with self.subTest(tool=name):
                result, _, _ = await invoke(name, provider_empty, dns=fail)
                self.assertFalse(result['coverage_complete'])
                self.assertTrue(result.get('error'))
                self.assertNotIn(SECRET,json.dumps(result))

    async def test_origin_dns_candidates_not_origin_or_scope_proof(self):
        def dns(host):
            if host in ('fixture.test', 'origin.fixture.test'):
                return '192.0.2.10' if host=='fixture.test' else '192.0.2.20'
            raise socket.gaierror(socket.EAI_NONAME, 'absent')
        rows = [{'name_value':'outside.test', 'ip':'198.51.100.1'},
                {'name_value':'fixture.test', 'ip':SECRET}]
        result, _, resolutions = await invoke('origin_ip_discovery', lambda r: httpx.Response(200, json=rows), dns=dns)
        self.assertEqual(set(result['ip_addresses']), {'192.0.2.10','192.0.2.20'})
        self.assertFalse(result.get('origin_verified', True))
        self.assertFalse(result.get('scope_authorized', True))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertLessEqual(len(resolutions), 7)

    async def test_origin_ct_field_not_supported_mapping(self):
        rows = [{'name_value':'fixture.test','ip':'192.0.2.30'}]
        result, _, _ = await invoke('origin_ip_discovery', lambda r: httpx.Response(200, json=rows))
        self.assertFalse(result['ip_addresses'])
        self.assertIn('ct_ip_mapping', result.get('unsupported_detection', []))

    async def test_origin_ct_page_limit_explicit(self):
        result, seen, _ = await invoke('origin_ip_discovery', lambda r: httpx.Response(200,json=[{'name_value':'fixture.test'}]*51))
        self.assertTrue(result.get('truncated'))
        self.assertFalse(result['selected_checks_complete'])
        self.assertEqual(len(seen),1)

    async def test_takeover_generic_service_prose_never_confirmation(self):
        for status in (200, 400, 403, 404):
            with self.subTest(status=status):
                result, _, _ = await invoke('sub_takeover', lambda r: httpx.Response(status, text='Documentation about github.io: repository not found; there is nothing here'))
                self.assertFalse(result['takeover'])
                self.assertFalse(result.get('candidates'))

    async def test_takeover_specific_error_is_candidate_only(self):
        for body in ('<html><title>Site not found · GitHub Pages</title><h1>There isn\'t a GitHub Pages site here.</h1></html>',
                     '<Error><Code>NoSuchBucket</Code><BucketName>' + SECRET + '</BucketName></Error>',
                     '<html><title>No such app</title><a href="https://www.heroku.com/">Heroku</a></html>'):
            with self.subTest(body=body[:25]):
                result, seen, _ = await invoke('sub_takeover', lambda r: httpx.Response(404, text=body))
                self.assertFalse(result['takeover'])
                self.assertTrue(result.get('candidates'))
                self.assertEqual(len(seen), 1)
                self.assertFalse(result.get('scope_authorized', True))
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_takeover_malformed_xml_is_not_candidate(self):
        for body in ('<Error><Code>NoSuchBucket', '<!DOCTYPE Error [<!ENTITY x "test">]><Error><Code>NoSuchBucket</Code></Error>'):
            with self.subTest(body=body[:20]):
                result, _, _ = await invoke('sub_takeover',lambda r: httpx.Response(404,text=body))
                self.assertFalse(result['takeover'])
                self.assertFalse(result['candidates'])


class WhoisAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_non_string_domain_is_structured_failure(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        for value in (None, 123, [], {}):
            with self.subTest(value=type(value).__name__):
                with patch.object(module.shutil, 'which') as which:
                    result = await module.whois_lookup(value)
                which.assert_not_called()
                self.assertFalse(result['coverage_complete'])
                self.assertTrue(result.get('error'))

    async def test_real_synthetic_output_cap_drains_and_reaps(self):
        await self._synthetic_output(False)

    @unittest.skipUnless(os.name == 'posix', 'POSIX inherited-pipe process group fixture')
    async def test_real_synthetic_inherited_pipe_drains_and_reaps(self):
        await self._synthetic_output(True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process group cancellation fixture')
    async def test_repeated_caller_cancellation_during_output_limit_cleanup(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        original_spawn, original_killpg = asyncio.create_subprocess_exec, os.killpg
        processes, delivered = [], []
        loop = asyncio.get_running_loop()
        caller = None
        async def spawn(*args, **kwargs):
            self.assertEqual(args, ('whois', 'fixture.test'))
            process = await original_spawn(sys.executable, '-c',
                'import sys; sys.stdout.buffer.write(b"x" * (10 * 1024 * 1024)); sys.stdout.flush()', **kwargs)
            processes.append(process)
            return process
        def cancel_again():
            if caller.cancel():
                delivered.append(True)
            if len(delivered) < 3 and not caller.done():
                loop.call_soon(cancel_again)
        def kill_and_cancel(pid, sig):
            original_killpg(pid, sig)
            loop.call_soon(cancel_again)
        try:
            with patch.object(module.shutil, 'which', return_value='/mock/whois'), \
                 patch.object(module.asyncio, 'create_subprocess_exec', side_effect=spawn), \
                 patch.object(module.os, 'killpg', side_effect=kill_and_cancel):
                caller = asyncio.create_task(module.whois_lookup('fixture.test'))
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(caller, timeout=5)
            self.assertGreaterEqual(len(delivered), 2)
            self.assertTrue(caller.cancelled(), 'caller cancellation must propagate after cleanup')
            self.assertTrue(processes[0].stdout.at_eof(), 'cancelled cleanup left buffered/paused stdout')
            self.assertIsNotNone(processes[0].returncode)
        finally:
            for process in processes:
                try:
                    original_killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                async def discard():
                    while await process.stdout.read(16384):
                        pass
                await asyncio.wait_for(asyncio.gather(discard(), process.wait()), timeout=3)

    async def _synthetic_output(self, inherited):
        module = importlib.import_module('cyber_tools.whois_lookup')
        original = asyncio.create_subprocess_exec
        processes = []
        source = 'import sys,subprocess; '
        if inherited:
            source += 'subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
        source += 'sys.stdout.buffer.write(b"x" * (10 * 1024 * 1024)); sys.stdout.flush()'
        async def spawn(*args, **kwargs):
            self.assertEqual(args, ('whois','fixture.test'))
            if os.name == 'posix':
                kwargs['start_new_session'] = True
            process = await original(sys.executable, '-c', source, **kwargs)
            processes.append(process)
            return process
        try:
            with patch.object(module.shutil, 'which', return_value='/mock/whois'), \
                 patch.object(module.asyncio, 'create_subprocess_exec', side_effect=spawn):
                result = await asyncio.wait_for(module.whois_lookup('fixture.test'), timeout=10)
            self.assertFalse(result['coverage_complete'])
            self.assertTrue(result.get('error'))
            self.assertIsNotNone(processes[0].returncode)
            self.assertTrue(processes[0].stdout.at_eof(), 'stdout must be drained, not left paused')
            self.assertTrue(result.get('cleanup_complete'))
        finally:
            for process in processes:
                try:
                    if os.name == 'posix':
                        os.killpg(process.pid, signal.SIGKILL)
                    elif process.returncode is None:
                        process.kill()
                except ProcessLookupError:
                    pass
                async def discard():
                    while await process.stdout.read(16384):
                        pass
                await asyncio.wait_for(asyncio.gather(discard(), process.wait()), timeout=3)

    async def cli(self, text, code=0, failure=None):
        module = importlib.import_module('cyber_tools.whois_lookup')
        process = Mock(returncode=code, stdout=Mock(read=AsyncMock(side_effect=[text.encode(), b''])), wait=AsyncMock(return_value=code))
        with patch.object(module.shutil, 'which', return_value='/mock/whois'), \
             patch.object(module.subprocess, 'run', side_effect=failure, return_value=Mock(returncode=code, stdout=text, stderr='')), \
             patch.object(module.asyncio, 'create_subprocess_exec', new=AsyncMock(side_effect=failure, return_value=process)), \
             patch.object(module, '_whois_socket', new=AsyncMock(side_effect=OSError('offline'))) as fallback:
            result = await module.whois_lookup('fixture.test')
        return result, process, fallback

    async def test_cli_positive_identity_and_allowlisted_redacted_fields(self):
        text = 'Domain Name: FIXTURE.TEST\nCreation Date: 2020-01-01T00:00:00Z\nName Server: ns.fixture.test\nRegistrant Email: '+SECRET+'\nAuthorization: '+SECRET
        result, _, _ = await self.cli(text)
        self.assertEqual(result['parsed']['domain_name'], 'fixture.test')
        self.assertIn('creation_date', result['parsed'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertFalse(result.get('scope_authorized', True))

    async def test_cli_failed_mismatched_malformed_timeout_and_oversized(self):
        for text, code, failure in [('Domain Name: OUTSIDE.TEST',0,None), ('error: '+SECRET,1,None),
                                     ('Rate limit exceeded: '+SECRET,0,None), ('',0,asyncio.TimeoutError()),
                                     ('Domain Name: FIXTURE.TEST\n' + 'x'*65537,0,None), ('',0,None)]:
            with self.subTest(size=len(text),code=code):
                result, _, _ = await self.cli(text, code, failure)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertTrue(result.get('error'))
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_socket_positive_bounded_and_closed(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        reader = Mock(read=AsyncMock(side_effect=[b'Domain Name: FIXTURE.TEST\nName Server: ns.fixture.test\n',b'']))
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        with patch.object(module.shutil,'which',return_value=None), patch.object(module,'_tld_servers',return_value=['whois.pir.org']), \
             patch.object(module.asyncio,'open_connection',new=AsyncMock(return_value=(reader,writer))):
            result = await module.whois_lookup('fixture.test')
        self.assertEqual(result['parsed']['domain_name'], 'fixture.test')
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_untrusted_iana_referral_not_followed(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        with patch.object(module.shutil,'which',return_value=None), \
             patch.object(module,'_whois_socket',new=AsyncMock(return_value='whois: 127.0.0.1\n')) as lookup:
            result = await module.whois_lookup('fixture.test')
        self.assertEqual(lookup.await_count,1)
        self.assertFalse(result.get('coverage_complete', True))
        self.assertTrue(result.get('error'))

    async def test_explicit_no_match_and_line_limit(self):
        result, _, _ = await self.cli('No match for "FIXTURE.TEST".')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['assessment'],'provider_no_record')
        result, _, _ = await self.cli('Domain Name: FIXTURE.TEST\n' + 'Name Server: ns.fixture.test\n'*201)
        self.assertFalse(result['coverage_complete'])
        self.assertTrue(result['truncated'])

    async def test_partial_socket_timeout_and_size_limit_close_writer(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        for chunks in ([b'Domain Name: FIXTURE.TEST\n',asyncio.TimeoutError()], [b'x'*65537]):
            reader = Mock(read=AsyncMock(side_effect=chunks))
            writer = Mock(drain=AsyncMock(),wait_closed=AsyncMock())
            with patch.object(module.shutil,'which',return_value=None),patch.object(module,'_tld_servers',return_value=['whois.pir.org']), \
                 patch.object(module.asyncio,'open_connection',new=AsyncMock(return_value=(reader,writer))):
                result = await module.whois_lookup('fixture.test')
            self.assertFalse(result['coverage_complete'])
            self.assertTrue(result.get('error'))
            writer.close.assert_called_once()
            writer.wait_closed.assert_awaited_once()

    async def test_cli_oversize_kills_and_reaps_running_process(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        reader = asyncio.StreamReader()
        reader.feed_data(b'x'*65537)
        reader.feed_eof()
        process = Mock(pid=None,returncode=None,stdout=reader,wait=AsyncMock(return_value=-9))
        with patch.object(module.shutil,'which',return_value='/mock/whois'), \
             patch.object(module.asyncio,'create_subprocess_exec',new=AsyncMock(return_value=process)):
            result = await module.whois_lookup('fixture.test')
        self.assertFalse(result['coverage_complete'])
        process.kill.assert_called_once()
        process.wait.assert_awaited_once()

    async def test_cli_cleanup_failure_is_reported_without_source_text(self):
        module = importlib.import_module('cyber_tools.whois_lookup')
        reader = Mock(read=AsyncMock(side_effect=[b'x'*65537,OSError(SECRET)]),at_eof=Mock(return_value=False))
        process = Mock(pid=None,returncode=None,stdout=reader,wait=AsyncMock(return_value=-9))
        with patch.object(module.shutil,'which',return_value='/mock/whois'), \
             patch.object(module.asyncio,'create_subprocess_exec',new=AsyncMock(return_value=process)):
            result = await module.whois_lookup('fixture.test')
        self.assertFalse(result['cleanup_complete'])
        self.assertTrue(result.get('cleanup_error'))
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn(SECRET,json.dumps(result))
        process._transport.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
