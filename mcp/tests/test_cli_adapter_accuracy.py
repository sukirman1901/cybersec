"""Offline CLI adapter contracts; no binaries or network are executed."""
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
cli = importlib.import_module('cyber_tools.cli_tools')
CALLS = {
    'cmseek_check': ('https://fixture.test/a?x=1&y=two words',),
    'gobuster_dir': ('https://fixture.test/a?x=1&y=two words', '/fixture/word list.txt'),
    'masscan_scan': ('192.0.2.0/30', '80,443', 1000),
    'xsstrike_check': ('https://fixture.test/a?x=1&y=two words',),
    'testssl_check': ('fixture.test', 8443),
    'sslyze_check': ('fixture.test', 8443),
}
OUTPUTS = {
    'cmseek_check': 'CMS Detected: WordPress\nCMS Version: 6.0',
    'gobuster_dir': '/admin (Status: 403) [Size: 123]',
    'masscan_scan': 'Discovered open port 443/tcp on 192.0.2.1',
    'xsstrike_check': '[+] XSS vulnerability found',
    'testssl_check': '[{"id":"TLS1_2","severity":"OK","finding":"offered"}]',
    'sslyze_check': '{"server_scan_results":[{"scan_status":"COMPLETED","scan_result":{}}],"invalid_server_strings":[]}',
}


class CliAdapterAccuracy(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, name, stdout=None, stderr='', code=0):
        run = AsyncMock(return_value={'stdout': OUTPUTS[name] if stdout is None else stdout,
                                     'stderr': stderr, 'exit_code': code})
        with patch.object(cli, '_which', return_value='/fixture/bin/tool with spaces'), \
             patch.object(cli, '_run_cli', run), patch('os.path.isfile', return_value=True):
            result = await getattr(cli, name)(*CALLS[name])
        return result, run.call_args.args[0]

    async def test_resolved_executable_and_arguments_preserved(self):
        for name, args in CALLS.items():
            with self.subTest(tool=name):
                _, argv = await self.invoke(name)
                self.assertEqual(argv[0], '/fixture/bin/tool with spaces')
                self.assertIn(f'{args[0]}:{args[1]}' if name in ('testssl_check', 'sslyze_check') else args[0], argv)
                if name == 'gobuster_dir':
                    self.assertIn(args[1], argv)
                if name == 'masscan_scan':
                    self.assertEqual(argv[argv.index('-p') + 1], '80,443')
                    self.assertEqual(argv[argv.index('--rate') + 1], '1000')

    async def test_masscan_fields_and_stderr_records(self):
        result, _ = await self.invoke('masscan_scan', stdout='banner: open tcp scans\n', stderr=OUTPUTS['masscan_scan'])
        self.assertEqual(result['open_ports'], [{'port': '443', 'protocol': 'tcp', 'ip': '192.0.2.1'}])
        result, _ = await self.invoke('masscan_scan', stdout='Discovered open port 99999/tcp on not-an-ip')
        self.assertEqual(result['count'], 0)
        self.assertFalse(result['coverage_complete'])

    async def test_xsstrike_banner_and_negation_not_positive(self):
        for output in ('XSStrike XSS scanner\nNo reflection found', 'Target is not vulnerable', 'No XSS found'):
            result, _ = await self.invoke('xsstrike_check', stdout=output)
            self.assertFalse(result['vulnerable'])
        result, _ = await self.invoke('xsstrike_check', stdout='XSStrike banner', stderr='[+] XSS vulnerability found')
        self.assertTrue(result['vulnerable'])

    async def test_cmseek_ansi_spacing_and_stderr(self):
        result, _ = await self.invoke('cmseek_check', stdout='CMSeeK banner',
                                    stderr='\x1b[32m[+] CMS Detected : WordPress\x1b[0m\n[+] CMS Version : 6.0')
        self.assertEqual(result['cms'], 'WordPress')
        self.assertEqual(result['version'], '6.0')

    async def test_gobuster_diagnostics_not_entries(self):
        result, _ = await self.invoke('gobuster_dir', stdout='Error (connection failed)\n/admin (Status: 403) [Size: 123]')
        self.assertEqual(result['entries'], ['/admin (Status: 403) [Size: 123]'])
        self.assertFalse(result['coverage_complete'])

    async def test_tls_json_wrong_shapes_are_incomplete(self):
        for name in ('testssl_check', 'sslyze_check'):
            for output in ('not JSON', 'null', '42', '"text"', '{}', '[42]'):
                with self.subTest(tool=name, output=output):
                    result, _ = await self.invoke(name, stdout=output)
                    self.assertFalse(result['coverage_complete'])
                    self.assertIn('error', result)

    async def test_sslyze_internal_failures_not_completed(self):
        for record in ({'scan_status': 'ERROR_NO_CONNECTIVITY', 'scan_result': None},
                       {'scan_status': 'COMPLETED', 'scan_result': {'tls_1_2_cipher_suites': {'status': 'ERROR', 'error_reason': 'timeout'}}}):
            result, _ = await self.invoke('sslyze_check', stdout=json.dumps({'server_scan_results': [record], 'invalid_server_strings': []}))
            self.assertFalse(result['coverage_complete'])

    async def test_nonzero_and_timeout_keep_partial_evidence_incomplete(self):
        for name in CALLS:
            for code in (2, -1):
                result, _ = await self.invoke(name, code=code, stderr='timed out' if code == -1 else 'failed')
                self.assertFalse(result['coverage_complete'])
                self.assertEqual(result['exit_code'], code)
                self.assertIn('error', result)
                self.assertEqual(result['confidence'], 'LOW')
        result, _ = await self.invoke('masscan_scan', code=-1, stderr='timed out')
        self.assertEqual(result['count'], 1)

    async def test_missing_dependency_never_dispatches(self):
        with patch.object(cli, '_which', return_value=None), patch.object(cli, '_run_cli', new_callable=AsyncMock) as run:
            for name, args in CALLS.items():
                result = await getattr(cli, name)(*args)
                self.assertFalse(result['ran'])
                self.assertFalse(result['coverage_complete'])
            run.assert_not_awaited()

    async def test_supported_positive_outputs_retained(self):
        for name in CALLS:
            result, _ = await self.invoke(name)
            self.assertTrue(result['coverage_complete'], name)
            self.assertTrue(result['ran'])
        result, _ = await self.invoke('testssl_check')
        self.assertEqual(result['findings'][0]['id'], 'TLS1_2')

    async def test_text_only_banner_is_not_completed_negative(self):
        for name in ('xsstrike_check', 'cmseek_check'):
            result, _ = await self.invoke(name, stdout='Scanner banner only')
            self.assertFalse(result['coverage_complete'])
            self.assertIn('error', result)

    async def test_explicit_text_negative_is_supported(self):
        for name, output in (('xsstrike_check', '[-] No reflection found'),
                             ('cmseek_check', '[-] CMS not detected')):
            result, _ = await self.invoke(name, stdout=output)
            self.assertTrue(result['coverage_complete'])

    async def test_testssl_fatal_records_and_partial_valid_records(self):
        result, _ = await self.invoke('testssl_check', stdout=json.dumps([
            {'id': 'connect', 'severity': 'FATAL', 'finding': 'Cannot connect'}]))
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['count'], 1)
        result, _ = await self.invoke('testssl_check', stdout=json.dumps([
            {'id': 'TLS1_2', 'severity': 'OK', 'finding': 'offered'}, 42]))
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['exit_code'], 0)
        self.assertIn('Invalid testssl', result['error'])

    async def test_gobuster_missing_wordlist_not_started(self):
        with patch.object(cli, '_which', return_value='/fixture/gobuster'), \
             patch('os.path.isfile', return_value=False), patch.object(cli, '_run_cli', new_callable=AsyncMock) as run:
            result = await cli.gobuster_dir('https://fixture.test', '/missing')
        self.assertEqual(result['execution_status'], 'not_started')
        self.assertFalse(result['ran'])
        run.assert_not_awaited()

    async def test_adapter_errors_do_not_echo_credentials_or_query_secrets(self):
        secret = 'https://fixture-user:fixture-password@fixture.test/?token=fixture-token'
        for name in CALLS:
            result, _ = await self.invoke(name, code=2, stderr='Request failed: ' + secret)
            for value in ('fixture-user', 'fixture-password', 'fixture-token'):
                self.assertNotIn(value, json.dumps(result), name)
            self.assertEqual(result['error_type'], 'execution_error')
        for name in ('testssl_check', 'sslyze_check'):
            result, _ = await self.invoke(name, stdout='invalid JSON', stderr=secret)
            self.assertNotIn('fixture-password', json.dumps(result))
            self.assertEqual(result['error_type'], 'invalid_output')

    async def test_xsstrike_report_is_redacted_candidate_not_browser_proof(self):
        result, _ = await self.invoke('xsstrike_check', stdout='[+] Vulnerable webpage: https://user:private-password@fixture.test/?token=private-token')
        self.assertTrue(result['vulnerable'])
        self.assertTrue(result['candidate'])
        self.assertEqual(result['evidence_type'], 'external_tool_report')
        self.assertFalse(result['browser_confirmed'])
        self.assertNotIn('private-password', json.dumps(result))
        self.assertNotIn('private-token', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
