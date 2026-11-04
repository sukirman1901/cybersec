"""Offline credential adapter regressions; synthetic markers, no login/CLI traffic."""
import asyncio
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with patch.dict(sys.modules, {'cyber_tools.http_guard': SimpleNamespace(guarded_urlopen=Mock(side_effect=AssertionError('unmocked HTTP')))}):
    pa = importlib.import_module('cyber_tools.password_audit')
hb = importlib.import_module('cyber_tools.hydra_brute')


class PasswordAccuracy(unittest.TestCase):
    def audit(self, **kwargs):
        with patch.object(pa.time, 'sleep'):
            return json.loads(pa.password_audit('fixture.invalid', password_list='SYNTH_A,SYNTH_B,SYNTH_C', **kwargs))

    def test_budget_exact_across_users(self):
        with patch.object(pa, '_ssh_attempt', return_value=False) as attempt:
            result = self.audit(username='auto', max_attempts=2)
        self.assertEqual(attempt.call_count, 2)
        self.assertEqual(result['attempts'], 2)

    def test_password_only_ssh_and_auth_timeouts(self):
        client = Mock()
        module = SimpleNamespace(SSHClient=Mock(return_value=client), AutoAddPolicy=Mock(), AuthenticationException=type('AuthError', (Exception,), {}))
        with patch.dict(sys.modules, {'paramiko': module}):
            result = self.audit(max_attempts=1)
        self.assertEqual(result['success_count'], 1)
        kwargs = client.connect.call_args.kwargs
        self.assertIs(kwargs['allow_agent'], False)
        self.assertIs(kwargs['look_for_keys'], False)
        self.assertEqual(kwargs['auth_timeout'], 8)
        self.assertEqual(kwargs['banner_timeout'], 8)
        self.assertEqual(result['successful'][0]['confidence'], 'HIGH')
        self.assertIn('coverage', result['successful'][0])

    def test_invalid_arguments_never_attempt(self):
        cases = [{'max_attempts': value} for value in ('2', None, True, 1.5)]
        cases += [{'password_list': value} for value in (None, ['SYNTH_A'], 'x' * 81921, 'x' * 4097, 'x\x00')]
        cases += [{'target': value} for value in ('-option', 'bad host', '', None, 'x' * 2049)]
        cases += [{'username': '-option'}, {'username': 'x' * 129}, {'port': '22'}, {'port': 65536}, {'protocol': []}]
        for case in cases:
            with self.subTest(case=str(case)[:80]), patch.object(pa, '_ssh_attempt') as attempt:
                args = {'target': 'fixture.invalid', 'password_list': 'SYNTH_A', **case}
                result = json.loads(pa.password_audit(**args))
                attempt.assert_not_called()
                self.assertEqual(result['attempts'], 0)
                self.assertFalse(result['coverage_complete'])
                self.assertIn('error', result)

    def test_target_url_secrets_are_not_returned(self):
        with patch.object(pa, '_http_attempt', return_value='candidate'), patch.object(pa.time, 'sleep'):
            result = json.loads(pa.password_audit('https://SYNTH_U:SYNTH_P@fixture.invalid/login?token=SYNTH_Q#SYNTH_F', protocol='https', password_list='SYNTH_A', max_attempts=1))
        self.assertNotIn('SYNTH_', json.dumps(result))
        self.assertEqual(result['target'], 'https://fixture.invalid/login')

    def test_zero_and_negative_budget(self):
        for limit in (0, -1):
            with patch.object(pa, '_ssh_attempt') as attempt:
                result = self.audit(max_attempts=limit)
            attempt.assert_not_called()
            self.assertEqual(result['attempts'], 0)
            self.assertFalse(result['coverage_complete'])

    def test_hard_cap_twenty(self):
        with patch.object(pa, '_ssh_attempt', return_value=False) as attempt, patch.object(pa.time, 'sleep'):
            result = json.loads(pa.password_audit('fixture.invalid', username='auto', max_attempts=10000))
        self.assertEqual(attempt.call_count, 20)
        self.assertEqual(result['attempts'], 20)

    def test_protocol_authentication_rejections(self):
        import ftplib
        import smtplib
        for protocol, module, constructor, error in [
            ('ftp', 'ftplib', 'FTP', ftplib.error_perm('530 denied')),
            ('smtp', 'smtplib', 'SMTP', smtplib.SMTPAuthenticationError(535, b'denied')),
        ]:
            client = Mock()
            client.login.side_effect = error
            with patch(f'{module}.{constructor}', return_value=client):
                result = self.audit(protocol=protocol, max_attempts=1)
            self.assertEqual(len(result['failed']), 1)
            self.assertTrue(result['coverage_complete'])

    def test_success_and_failure_are_indexed_redacted(self):
        with patch.object(pa, '_ssh_attempt', side_effect=[True, False]):
            result = self.audit(max_attempts=2)
        self.assertEqual(result['success_count'], 1)
        self.assertNotIn('SYNTH_', json.dumps(result))
        self.assertEqual(result['successful'][0]['attempt_index'], 1)
        self.assertEqual(result['failed'][0]['attempt_index'], 2)

    def test_unsupported_is_not_failed_authentication(self):
        for protocol in ('rdp', 'mysql', 'postgres', 'unknown'):
            result = self.audit(protocol=protocol)
            self.assertEqual(result['attempts'], 0)
            self.assertEqual(result['failed'], [])
            self.assertFalse(result['coverage_complete'])

    def test_missing_library_is_incomplete(self):
        with patch.dict(sys.modules, {'paramiko': None}):
            result = self.audit(max_attempts=1)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['failed'], [])

    def test_http_keywords_are_only_candidates_and_response_closed(self):
        response = Mock()
        response.read.return_value = b'welcome dashboard logout'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock()
        with patch.object(pa, 'guarded_urlopen', return_value=response):
            result = self.audit(protocol='https', max_attempts=1)
        self.assertEqual(result['success_count'], 0)
        self.assertEqual(len(result['candidates']), 1)
        self.assertEqual(result['candidates'][0]['confidence'], 'LOW')
        self.assertIn('coverage', result['candidates'][0])
        self.assertFalse(result['coverage_complete'])
        response.read.assert_called_once_with(65537)
        self.assertTrue(response.close.called or response.__exit__.called)

    def test_ssh_timeout_closes_and_redacts_error(self):
        client = Mock()
        client.connect.side_effect = TimeoutError('SYNTH_A')
        module = SimpleNamespace(SSHClient=Mock(return_value=client), AutoAddPolicy=Mock(), AuthenticationException=type('AuthError', (Exception,), {}))
        with patch.dict(sys.modules, {'paramiko': module}):
            result = self.audit(max_attempts=1)
        client.close.assert_called_once()
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('SYNTH_A', json.dumps(result))

    def test_ftp_smtp_positive_and_error_cleanup(self):
        for protocol, module, constructor in [('ftp', 'ftplib', 'FTP'), ('smtp', 'smtplib', 'SMTP')]:
            for fails in (False, True):
                client = Mock()
                if fails:
                    client.login.side_effect = TimeoutError('SYNTH_A')
                with patch(f'{module}.{constructor}', return_value=client):
                    result = self.audit(protocol=protocol, max_attempts=1)
                self.assertEqual(result['success_count'], 0 if fails else 1)
                client.close.assert_called_once()
                if fails:
                    self.assertFalse(result['coverage_complete'])


class HydraAccuracy(unittest.TestCase):
    def run_hydra(self, runner_result=None, error=None):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'synthetic.txt'
            source.write_text(''.join(f'SYNTH_{i}\n' for i in range(25)))
            observed = {}
            async def fake_run(cmd, timeout):
                observed['cmd'] = cmd
                observed['timeout'] = timeout
                observed['path'] = Path(cmd[cmd.index('-P') + 1])
                observed['lines'] = observed['path'].read_text().splitlines()
                if error:
                    raise error
                return runner_result
            with patch.object(hb, '_run_cli', side_effect=fake_run, create=True), patch.object(hb.asyncio, 'create_subprocess_exec', side_effect=AssertionError('unmocked subprocess')):
                try:
                    result = asyncio.run(hb.hydra_brute('fixture.invalid', wordlist=str(source)))
                finally:
                    if observed:
                        self.assertFalse(observed['path'].exists())
            return result, observed

    def test_bounded_redacted_protocol_positive(self):
        result, observed = self.run_hydra({'exit_code': 0, 'stdout': '[22][ssh] host: fixture.invalid   login: synthetic-user   password: SYNTH_0\nnoise login: SYNTH_1', 'stderr': '', 'cleanup_complete': True})
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['results'][0]['confidence'], 'MEDIUM')
        self.assertIn('coverage', result['results'][0])
        self.assertNotIn('SYNTH_', json.dumps(result))
        self.assertEqual(len(observed['lines']), 20)
        self.assertEqual(observed['timeout'], 300)
        self.assertIn('-f', observed['cmd'])
        self.assertEqual(observed['cmd'][observed['cmd'].index('-t') + 1], '1')

    def test_execution_failures_incomplete_and_private(self):
        for kind in ('timeout', 'spawn_error', 'output_limit'):
            result, _ = self.run_hydra({'exit_code': -1, 'stdout': 'password: SYNTH_0', 'stderr': 'SYNTH_1', 'error_kind': kind, 'cleanup_complete': True})
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(result['count'], 0)
            self.assertNotIn('SYNTH_', json.dumps(result))

    def test_empty_zero_exit_is_not_complete(self):
        result, _ = self.run_hydra({'exit_code': 0, 'stdout': '', 'stderr': '', 'cleanup_complete': True})
        self.assertFalse(result['coverage_complete'])

    def test_wrong_host_positive_is_not_a_finding(self):
        result, _ = self.run_hydra({'exit_code': 0, 'stdout': '[22][ssh] host: other.invalid   login: synthetic-user   password: SYNTH_0', 'stderr': '', 'cleanup_complete': True})
        self.assertEqual(result['count'], 0)
        self.assertFalse(result['coverage_complete'])

    def test_invalid_arguments_do_not_open_input_or_run(self):
        for case in ({'target': '-option'}, {'target': 'fixture.invalid/path'}, {'target': None}, {'target': 'https://SYNTH_U:SYNTH_P@fixture.invalid/?token=SYNTH_Q#SYNTH_F'}, {'service': []}, {'service': 'ssh -x'}, {'username': '-option'}, {'username': 'a\nb'}, {'username': 'x' * 129}, {'wordlist': None}):
            with self.subTest(case=case), patch.object(hb, '_run_cli', new_callable=AsyncMock) as run, patch('builtins.open') as opened:
                result = asyncio.run(hb.hydra_brute(**{'target': 'fixture.invalid', 'wordlist': 'unused', **case}))
            run.assert_not_called()
            opened.assert_not_called()
            self.assertFalse(result['coverage_complete'])
            self.assertNotIn('SYNTH_', json.dumps(result))

    def test_wordlist_symlink_fifo_and_swap_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.write_text('SYNTH_A\n')
            link = Path(directory) / 'link'
            link.symlink_to(source)
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            with patch.object(hb, '_run_cli', new_callable=AsyncMock) as run:
                for path in (link, fifo):
                    # Prevent baseline FIFO blocking while checking pre-open rejection.
                    with patch('builtins.open', side_effect=OSError('unexpected open')) as opened:
                        result = asyncio.run(hb.hydra_brute('fixture.invalid', wordlist=str(path)))
                    opened.assert_not_called()
                    self.assertFalse(result['coverage_complete'])
                real_open = os.open
                observed = []
                def swapped_open(path, flags, *args, **kwargs):
                    if str(path) == str(source):
                        observed.append(flags)
                        source.unlink()
                        source.symlink_to(fifo)
                    return real_open(path, flags, *args, **kwargs)
                with patch.object(os, 'open', side_effect=swapped_open):
                    result = asyncio.run(hb.hydra_brute('fixture.invalid', wordlist=str(source)))
                self.assertFalse(result['coverage_complete'])
                self.assertTrue(observed)
                self.assertTrue(observed[0] & os.O_NOFOLLOW)
                self.assertTrue(observed[0] & os.O_NONBLOCK)
            run.assert_not_called()

    def test_wordlist_descriptor_identity_type_and_size(self):
        for mode in ('replacement', 'fifo', 'oversize'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'source'
                source.write_bytes(b'x' * 81921 if mode == 'oversize' else b'SYNTH_A\n')
                replacement = Path(directory) / 'replacement'
                replacement.write_text('SYNTH_B\n')
                real_open = os.open
                def swapped_open(path, flags, *args, **kwargs):
                    if str(path) == str(source):
                        if mode == 'replacement':
                            replacement.replace(source)
                        elif mode == 'fifo':
                            source.unlink()
                            os.mkfifo(source)
                        # Guard the fixture against a regression that could block.
                        self.assertTrue(flags & os.O_NONBLOCK)
                    return real_open(path, flags, *args, **kwargs)
                with patch.object(os, 'open', side_effect=swapped_open), patch.object(hb, '_run_cli', new_callable=AsyncMock) as run:
                    result = asyncio.run(hb.hydra_brute('fixture.invalid', wordlist=str(source)))
                run.assert_not_called()
                self.assertFalse(result['coverage_complete'])
                self.assertIn('error', result)

    def test_cancellation_removes_private_input(self):
        with self.assertRaises(asyncio.CancelledError):
            self.run_hydra(error=asyncio.CancelledError())

    def test_exception_cleanup_and_redaction(self):
        result, _ = self.run_hydra(error=OSError('SYNTH_0'))
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('SYNTH_', json.dumps(result))

    def test_no_default_unbounded_wordlist(self):
        with patch.object(hb.asyncio, 'create_subprocess_exec', new_callable=AsyncMock) as spawn:
            result = asyncio.run(hb.hydra_brute('fixture.invalid'))
        spawn.assert_not_called()
        self.assertFalse(result['coverage_complete'])


if __name__ == '__main__':
    unittest.main()
