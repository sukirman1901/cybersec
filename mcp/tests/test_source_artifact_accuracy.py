"""Synthetic source/binary fixtures; HTTP, advisories and executables are mocked."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import httpx
from cyber_tools.secret_scanner import secret_scanner
from cyber_tools.sast_review import sast_review
from cyber_tools.supply_chain import supply_chain
from cyber_tools.binary_checksec import binary_checksec
from cyber_tools.binary_checksec import _run_bounded


class Response:
    def __init__(self, body=b'', status=404):
        self.status_code = status
        self.body = body if isinstance(body, bytes) else body.encode()
        self.text = self.body.decode(errors='replace')
        self.headers = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def aiter_bytes(self, chunk_size=8192):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset:offset + chunk_size]


class Client:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def response(self, url):
        self.calls.append(url)
        response = self.responses.get(url.rsplit('/', 1)[-1], Response())
        if isinstance(response, Exception):
            raise response
        return response

    async def get(self, url):
        return self.response(url)

    def stream(self, method, url):
        return self.response(url)


class Process:
    def __init__(self, body=b'', code=0, timeout=False):
        self.body = body
        self.returncode = code
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(body)
        self.stdout.feed_eof()
        if timeout:
            async def fail(*args):
                raise asyncio.TimeoutError()
            self.stdout.read = fail
        self.timeout = timeout
        self.killed = False
        self.waited = False

    async def communicate(self):
        if self.timeout:
            raise asyncio.TimeoutError()
        return self.body, b''

    def kill(self):
        self.killed = True

    async def wait(self):
        self.waited = True
        return self.returncode


class SourceArtifactAccuracy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return str(path)

    def call(self, tool, *args, **kwargs):
        return asyncio.run(tool(*args, **kwargs))

    def http(self, responses):
        client = Client(responses)
        with patch('cyber_tools.supply_chain.httpx.AsyncClient', return_value=client):
            result = self.call(supply_chain, 'https://fixture.invalid')
        self.assertLessEqual(len(client.calls), 6)
        return result

    def binary(self, outputs):
        processes = []
        calls = []
        async def create(*args, **kwargs):
            calls.append((args, kwargs))
            spec = outputs.get(args[0], (b'', 0, False))
            if isinstance(spec, Exception):
                raise spec
            proc = Process(*spec)
            processes.append(proc)
            return proc
        with patch('asyncio.create_subprocess_exec', side_effect=create):
            result = self.call(binary_checksec, self.file('fixture.bin', b'\x7fELFsynthetic'))
        return result, processes, calls

    def test_secret_redaction_and_location(self):
        value = 'ghp_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
        result = self.call(secret_scanner, self.file('a.py', f'# fixture\nkey = "{value}"\n'))
        self.assertEqual(result['secrets_found'], 1)
        finding = result['findings'][0]
        self.assertNotIn(value[:25], json.dumps(result))
        self.assertEqual(finding.get('line'), 2)
        self.assertEqual(finding.get('assessment'), 'candidate')
        self.assertEqual(finding['file'], 'a.py')

    def test_secret_dotenv_and_low_entropy_structural_key(self):
        self.file('.env', 'AWS_KEY=AKIA' + 'A' * 16)
        result = self.call(secret_scanner, str(self.root))
        self.assertEqual(result['files_scanned'], 1)
        self.assertEqual(result['secrets_found'], 1)

    def test_secret_false_assignments_and_prefixes(self):
        source = 'notpassword="AbCdEf012345!@#$"\npassword=os.getenv("PASSWORD")\ntoken=process.env.ACCESS_TOKEN\nxghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789x\n'
        result = self.call(secret_scanner, self.file('a.py', source), min_entropy=0)
        self.assertEqual(result['secrets_found'], 0)

    def test_secret_invalid_entropy(self):
        for value in [None, True, -1, float('nan'), float('inf'), 9, 10 ** 1000]:
            with self.subTest(value=value):
                self.assertIn('error', self.call(secret_scanner, self.file('a.py', ''), min_entropy=value))

    def test_secret_generic_entropy_and_pem_boundaries(self):
        source = 'password="AbCdEf012345!@#$"\npassword="aaaaaaaaaaaa"\n-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGR0g=\n-----END EC PRIVATE KEY-----\n'
        result = self.call(secret_scanner, self.file('assignments.env', source), min_entropy=3.5)
        self.assertEqual([f['type'] for f in result['findings']], ['Password'])
        self.assertEqual(result['findings'][0]['line'], 1)
        self.assertNotIn('AbCdEf012345', json.dumps(result))

    def test_secret_private_key_pattern_positive(self):
        source = '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----\n'
        result = self.call(secret_scanner, self.file('fixture.txt', source))
        self.assertEqual([f['type'] for f in result['findings']], ['Private Key'])
        self.assertNotIn('QUJDREV', json.dumps(result))

    def test_sast_real_calls_are_candidates_not_raw_source(self):
        result = self.call(sast_review, self.file('a.py', 'eval("synthetic-sensitive-value")\n'))
        self.assertTrue(result['findings'])
        self.assertNotIn('synthetic-sensitive-value', json.dumps(result))
        self.assertEqual(result['findings'][0].get('assessment'), 'candidate')
        self.assertIn('coverage', result['findings'][0])

    def test_sast_comments_and_literals_not_executable(self):
        for name, source in [('a.py', '# eval(user)\ns = "exec(user)"\n'),
                             ('a.js', '// eval(user)\nconst s="eval(user)"; /* eval(user) */')]:
            with self.subTest(name=name):
                self.assertEqual(self.call(sast_review, self.file(name, source))['total_findings'], 0)

    def test_sast_python3_input_not_code_injection(self):
        self.assertEqual(self.call(sast_review, self.file('a.py', 'input("name")\n'))['total_findings'], 0)

    def test_sast_multiline_calls_and_parameterized_sql(self):
        source = 'value = eval(\n user\n)\ncursor.execute("SELECT * FROM t WHERE id=?", (user,))\ncursor.execute(f"SELECT {user}")\n'
        result = self.call(sast_review, self.file('multiline.py', source))
        self.assertEqual(result['total_findings'], 2)
        self.assertEqual([f['line'] for f in result['findings']], [1, 5])

    def test_sast_js_positive_and_unclosed_comments(self):
        result = self.call(sast_review, self.file('review.js', 'eval(user);\nelement.innerHTML=user;\nrequire("child_process");\n/* unclosed exec(user)'))
        self.assertEqual(result['total_findings'], 3)

    def test_sast_malformed_python_is_incomplete(self):
        result = self.call(sast_review, self.file('a.py', 'def broken(:\n'))
        self.assertIs(result.get('coverage_complete'), False)
        self.assertTrue(result.get('errors') or result.get('error'))

    def test_source_missing_invalid_and_read_errors(self):
        for tool in [secret_scanner, sast_review]:
            for path in [None, str(self.root / 'absent')]:
                with self.subTest(tool=tool.__name__, path=path):
                    result = self.call(tool, path)
                    self.assertIn('error', result)
                    self.assertIs(result.get('coverage_complete'), False)
            path = self.file('a.py', 'eval(x)')
            with patch('builtins.open', side_effect=PermissionError('synthetic-sensitive-error')):
                result = self.call(tool, path)
            self.assertIs(result.get('coverage_complete'), False)
            self.assertEqual(result['files_scanned'], 0)
            self.assertNotIn('synthetic-sensitive-error', json.dumps(result))

    def test_source_oversize_and_symlinks(self):
        for tool in [secret_scanner, sast_review]:
            path = self.file('large.py', b'')
            with open(path, 'wb') as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with patch('builtins.open', side_effect=AssertionError('Oversize read')):
                result = self.call(tool, path)
            self.assertIs(result.get('coverage_complete'), False)
            link = self.root / 'link.py'
            os.symlink(path, link)
            result = self.call(tool, str(link))
            self.assertIs(result.get('coverage_complete'), False)
            link.unlink()

    def test_source_swap_rejected(self):
        import builtins
        real_open = builtins.open
        for tool in [secret_scanner, sast_review]:
            path = self.file('swap.py', 'ordinary = 1')
            outside = self.file('outside.txt', 'eval(x)')
            def swapped(file, *args, **kwargs):
                if file == path:
                    os.unlink(path)
                    os.symlink(outside, path)
                return real_open(file, *args, **kwargs)
            with patch('builtins.open', side_effect=swapped):
                result = self.call(tool, path)
            self.assertIs(result.get('coverage_complete'), False)
            self.assertEqual(result['files_scanned'], 0)
            os.unlink(path)

    def test_source_directory_swap_rejected(self):
        real_scandir = os.scandir
        for tool in [secret_scanner, sast_review]:
            directory = self.root / tool.__name__
            directory.mkdir()
            (directory / 'a.py').write_text('x=1')
            external = self.root / (tool.__name__ + '-outside')
            external.mkdir()
            (external / 'a.py').write_text('eval(user)')
            moved = self.root / (tool.__name__ + '-moved')
            def swap(fd):
                directory.rename(moved)
                os.symlink(external, directory)
                return real_scandir(fd)
            with patch('os.scandir', side_effect=swap):
                result = self.call(tool, str(directory))
            self.assertIs(result['coverage_complete'], False)
            self.assertEqual(result['files_scanned'], 0)

    def test_source_directory_file_budget(self):
        for i in range(110):
            self.file(f'{i}.py', 'eval(user)\n')
        result = self.call(sast_review, str(self.root))
        self.assertLessEqual(result['files_scanned'], 100)
        self.assertIs(result.get('coverage_complete'), False)

    def test_source_total_bytes_and_entry_budgets(self):
        for i in range(34):
            self.file(f'large-{i}.py', '# ' + 'a' * (256 * 1024 - 3) + '\n')
        for tool in [secret_scanner, sast_review]:
            result = self.call(tool, str(self.root))
            self.assertLessEqual(result['bytes_read'], 8 * 1024 * 1024)
            self.assertIs(result['coverage_complete'], False)
        directory = self.root / 'entries'
        directory.mkdir()
        for i in range(1001):
            (directory / f'{i}.dat').touch()
        for tool in [secret_scanner, sast_review]:
            result = self.call(tool, str(directory))
            self.assertIs(result['coverage_complete'], False)
            self.assertTrue(result['errors'])

    def test_source_nonregular_directory_entry_is_incomplete(self):
        self.file('regular.py', 'x=1\n')
        os.mkfifo(self.root / 'pipe.py')
        for tool in [secret_scanner, sast_review]:
            result = self.call(tool, str(self.root))
            self.assertIs(result['coverage_complete'], False)

    def test_secret_findings_cap(self):
        value = 'ghp_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
        result = self.call(secret_scanner, self.file('many.txt', (value + '\n') * 201))
        self.assertLessEqual(len(result['findings']), 200)
        self.assertIs(result.get('coverage_complete'), False)

    def test_supply_version_comparison_with_mock_advisory(self):
        with patch('cyber_tools.supply_chain.KNOWN_VULN_PACKAGES', {'lodash': {'max': '2.0.0', 'cve': 'SYNTHETIC'}}):
            result = self.http({'package.json': Response('{"dependencies":{"lodash":"3.0.0"}}', 200)})
            self.assertFalse(any(f.get('cve') for f in result['findings']))
            result = self.http({'package.json': Response('{"dependencies":{"lodash":"1.0.0"}}', 200)})
            candidate = [f for f in result['findings'] if f.get('cve')]
            self.assertEqual(len(candidate), 1)
            self.assertEqual(candidate[0].get('assessment'), 'candidate')

    def test_supply_html_and_malformed_are_not_manifests(self):
        for body in ['<html>login page</html>', '[]', '{"dependencies": []}', '{"name": []}', '{"name":"fixture", "custom": NaN}']:
            result = self.http({'package.json': Response(body, 200)})
            self.assertFalse(any(f.get('packages_found') is not None for f in result['findings']))
            self.assertIs(result.get('coverage_complete'), False)

    def test_supply_duplicate_sections(self):
        result = self.http({'package.json': Response('{"dependencies":{},"dependencies":{}}', 200)})
        self.assertIs(result['coverage_complete'], False)

    def test_supply_mock_advisories_composer_and_pip(self):
        hints = {'guzzlehttp/guzzle': {'max': '9.0.0', 'cve': 'SYNTHETIC'},
                 'requests': {'max': '9.0.0', 'cve': 'SYNTHETIC'}}
        with patch('cyber_tools.supply_chain.KNOWN_VULN_PACKAGES', hints):
            result = self.http({'composer.json': Response('{"require":{"guzzlehttp/guzzle":"1.0.0"}}', 200),
                                'requirements.txt': Response('requests==1.0.0\n', 200)})
        self.assertEqual(len([f for f in result['findings'] if f.get('cve')]), 2)

    def test_supply_unsupported_advisory_ecosystems_and_dependency_budget(self):
        for path, body in [('go.mod', 'module fixture\ngo 1.22\nrequire example.invalid/pkg v1.0.0'),
                           ('Gemfile', "gem 'fixture', '1.0.0'"),
                           ('build.gradle', "implementation 'fixture:library:1.0.0'")]:
            result = self.http({path: Response(body, 200)})
            self.assertTrue(any(f.get('packages_found') == 1 for f in result['findings']))
            self.assertIs(result['coverage_complete'], False)
        body = json.dumps({'dependencies': {f'fixture-{i}': '1.0.0' for i in range(201)}})
        result = self.http({'package.json': Response(body, 200)})
        self.assertIs(result['coverage_complete'], False)
        self.assertEqual(result['findings'][0]['packages_found'], 200)

    def test_supply_metadata_ranges_and_ecosystems(self):
        for body in ['{"description":"lodash", "lodash":"1.0.0"}', '{"dependencies":{"lodash":"^1.0.0"}}']:
            result = self.http({'package.json': Response(body, 200)})
            self.assertFalse(any(f.get('cve') for f in result['findings']))
        result = self.http({'requirements.txt': Response('lodash==1.0.0', 200)})
        self.assertFalse(any(f.get('cve') for f in result['findings']))

    def test_supply_blocked_network_and_response_bounds(self):
        for response in [Response('sensitive-block-page', 403), Response('', 302), httpx.ConnectError('sensitive-error'), asyncio.TimeoutError(), Response('x' * (2 * 1024 * 1024), 200)]:
            result = self.http({'package.json': response})
            self.assertIs(result.get('coverage_complete'), False)
            self.assertNotIn('sensitive-', json.dumps(result))

    def test_supply_invalid_advisory_is_inconclusive(self):
        with patch('cyber_tools.supply_chain.KNOWN_VULN_PACKAGES', {'lodash': {'max': 'not-a-version', 'cve': 'SYNTHETIC'}}):
            result = self.http({'package.json': Response('{"dependencies":{"lodash":"1.0.0"}}', 200)})
        self.assertIs(result['coverage_complete'], False)
        self.assertFalse(any(f.get('cve') for f in result['findings']))

    def test_supply_invalid_target_no_client(self):
        with patch('cyber_tools.supply_chain.httpx.AsyncClient', side_effect=AssertionError('No client')):
            for value in [None, 'file:///local', 'https://user:secret@fixture.invalid']:
                self.assertIn('error', self.call(supply_chain, value))

    def test_binary_failed_command_not_success(self):
        result, _, _ = self.binary({'file': (b'ELF sensitive-output', 1, False)})
        self.assertIs(result.get('coverage_complete'), False)
        self.assertNotIn('sensitive-output', json.dumps(result))
        self.assertFalse(any(f.get('enabled') is True for f in result['findings']))

    def test_binary_missing_tools_and_timeout_cleanup(self):
        result, _, _ = self.binary({'file': FileNotFoundError()})
        self.assertIs(result.get('coverage_complete'), False)
        result, processes, _ = self.binary({'file': (b'', None, True)})
        self.assertIs(result.get('coverage_complete'), False)
        self.assertTrue(processes[0].killed)
        self.assertTrue(processes[0].waited)

    def test_binary_nx_is_not_pie(self):
        elf = b'Type: EXEC (Executable file)\n GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x10\n'
        result, _, calls = self.binary({'file': (b'ELF 64-bit executable', 0, False), 'readelf': (elf, 0, False)})
        checks = {f['check']: f for f in result['findings']}
        self.assertIs(checks.get('NX', {}).get('enabled'), True)
        self.assertIs(checks.get('PIE/ASLR', {}).get('enabled'), False)
        self.assertFalse(any(args[0] == 'otool' for args, _ in calls))

    def test_binary_output_is_bounded(self):
        result, processes, _ = self.binary({'file': (b'X' * (2 * 1024 * 1024), None, False)})
        self.assertIs(result.get('coverage_complete'), False)
        self.assertLess(len(json.dumps(result)), 10000)
        self.assertTrue(processes[0].killed)

    def test_binary_keywords_are_not_high_severity_secrets(self):
        result, _, _ = self.binary({'file': (b'PE32 executable', 0, False), 'strings': (b'password synthetic-secret admin debug', 0, False)})
        self.assertNotIn('synthetic-secret', json.dumps(result))
        self.assertFalse(any(f.get('severity') == 'high' for f in result['findings']))

    def test_binary_pie_executable_stack_and_unknown_headers(self):
        elf = b'Type: DYN (Position-Independent Executable file)\n INTERP 0x0\n GNU_STACK 0x0 0x0 0x0 0x0 0x0 RWE 0x10\n'
        result, _, _ = self.binary({'file': (b'ELF 64-bit executable', 0, False), 'readelf': (elf, 0, False)})
        checks = {f['check']: f for f in result['findings']}
        self.assertIs(checks['PIE/ASLR']['enabled'], True)
        self.assertIs(checks['NX']['enabled'], False)
        result, _, _ = self.binary({'file': (b'ELF 64-bit executable', 0, False), 'readelf': (b'invalid headers', 0, False)})
        self.assertIs(result['coverage_complete'], False)
        self.assertTrue(all(f['enabled'] == 'unknown' for f in result['findings'] if 'enabled' in f))

    def test_binary_macho_redacts_libraries_and_scopes_checks(self):
        result, _, calls = self.binary({'file': (b'Mach-O 64-bit executable', 0, False),
                                       'otool': (b'artifact:\n /private/secret-library (compatibility version 1.0.0, current version 1.0.0)\n', 0, False)})
        self.assertNotIn('secret-library', json.dumps(result))
        self.assertTrue(any(f.get('library_count') == 1 for f in result['findings']))
        self.assertFalse(any(args[0] == 'readelf' for args, _ in calls))
        self.assertIs(result['coverage_complete'], False)

    def test_binary_arguments_snapshot_and_cleanup(self):
        result, _, calls = self.binary({'file': (b'PE32 executable', 0, False)})
        for args, kwargs in calls:
            self.assertIn('--', args)
            self.assertEqual(kwargs['stderr'], asyncio.subprocess.DEVNULL)
            self.assertFalse(os.path.exists(args[-1]))
            self.assertNotEqual(args[-1], result['target'])

    def test_binary_cancel_reaps_process(self):
        processes = []
        async def create(*args, **kwargs):
            process = Process(b'', None)
            async def cancelled(*args):
                raise asyncio.CancelledError()
            process.stdout.read = cancelled
            processes.append(process)
            return process
        with patch('asyncio.create_subprocess_exec', side_effect=create):
            with self.assertRaises(asyncio.CancelledError):
                self.call(binary_checksec, self.file('cancel.bin', b'fixture'))
        self.assertTrue(processes[0].killed)
        self.assertTrue(processes[0].waited)

    def test_binary_real_synthetic_output_limit_closes_transport(self):
        """Only Python's harmless writer runs; no artifact or binary tool executes."""
        async def scenario():
            spawn = asyncio.create_subprocess_exec
            processes = []
            async def replacement(*args, **kwargs):
                process = await spawn(sys.executable, '-c',
                                      'import sys; sys.stdout.buffer.write(b"x" * (10 * 1024 * 1024)); sys.stdout.flush()',
                                      **kwargs)
                processes.append(process)
                return process
            try:
                with patch('asyncio.create_subprocess_exec', side_effect=replacement):
                    result = await asyncio.wait_for(binary_checksec(self.file('writer-fixture.bin', b'synthetic')), timeout=4)
                self.assertIs(result['coverage_complete'], False)
                self.assertEqual(len(processes), 1)
                process = processes[0]
                self.assertIsNotNone(process.returncode)
                self.assertTrue(process.stdout.at_eof(), 'Cleanup must discard buffered stdout to EOF')
                self.assertTrue(process._transport.is_closing(), 'Subprocess transport must be closed before returning')
                self.assertFalse(any('cleanup_failed' in error for error in result['errors']))
            finally:
                # Keep a failing regression from leaking its synthetic child/pipe.
                for process in processes:
                    if process.returncode is None:
                        process.kill()
                    process._transport.close()
                    await asyncio.wait_for(process.wait(), timeout=2)
        asyncio.run(scenario())

    def test_binary_cleanup_failure_is_reported(self):
        async def scenario():
            process = Process(b'x' * (128 * 1024), None)
            async def failed_wait():
                raise asyncio.TimeoutError()
            process.wait = failed_wait
            with patch('asyncio.create_subprocess_exec', return_value=process):
                _, error = await _run_bounded('synthetic-tool')
            self.assertIn('cleanup_failed', error)
        asyncio.run(scenario())

    @unittest.skipUnless(os.name == 'posix', 'POSIX process-group cleanup regression')
    def test_binary_repeated_cancellation_during_output_cleanup(self):
        """A synthetic writer fills stdout; caller cancellation must not abort cleanup."""
        async def scenario():
            spawn = asyncio.create_subprocess_exec
            killpg = os.killpg
            processes, handles, cancellations = [], [], []
            cleanup_started = False
            task = None
            async def replacement(*args, **kwargs):
                process = await spawn(sys.executable, '-c',
                                      'import sys; sys.stdout.buffer.write(b"x" * (10 * 1024 * 1024)); sys.stdout.flush()',
                                      **kwargs)
                processes.append(process)
                read = process.stdout.read
                delayed = False
                async def controlled_read(size):
                    nonlocal delayed
                    if cleanup_started and not delayed:
                        delayed = True
                        # Keep cleanup pending long enough to deliver distinct cancellations.
                        await asyncio.sleep(0.03)
                    return await read(size)
                process.stdout.read = controlled_read
                return process
            def cancel_caller():
                cancellations.append(task.cancel())
            def kill_and_cancel(pid, sig):
                nonlocal cleanup_started
                cleanup_started = True
                killpg(pid, sig)
                loop = asyncio.get_running_loop()
                handles.extend([loop.call_soon(cancel_caller),
                                loop.call_later(0.005, cancel_caller),
                                loop.call_later(0.01, cancel_caller)])
            try:
                with patch('asyncio.create_subprocess_exec', side_effect=replacement), patch('os.killpg', side_effect=kill_and_cancel):
                    task = asyncio.create_task(_run_bounded('synthetic-tool'))
                    with self.assertRaises(asyncio.CancelledError):
                        await asyncio.wait_for(task, timeout=4)
                self.assertTrue(cleanup_started)
                self.assertIsNotNone(processes[0].returncode)
                self.assertTrue(processes[0].stdout.at_eof())
                self.assertTrue(processes[0]._transport.is_closing())
                self.assertGreaterEqual(sum(cancellations), 2)
            finally:
                for handle in handles:
                    handle.cancel()
                for process in processes:
                    if process.returncode is None:
                        process.kill()
                    process._transport.close()
                    await asyncio.wait_for(process.wait(), timeout=2)
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
        asyncio.run(scenario())

    def test_binary_invalid_or_oversize_no_process(self):
        path = self.file('big.bin', b'')
        with open(path, 'wb') as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
        with patch('asyncio.create_subprocess_exec', side_effect=AssertionError('Must not spawn')):
            for target in [None, str(self.root / 'missing'), path]:
                result = self.call(binary_checksec, target)
                self.assertIs(result.get('coverage_complete'), False)
                self.assertIn('error', result)

    def test_binary_open_time_swap_no_process(self):
        import builtins
        real_open = builtins.open
        path = self.file('swap.bin', b'synthetic')
        external = self.file('external.bin', b'synthetic-sensitive-replacement')
        def swap(file, *args, **kwargs):
            if file == path:
                os.unlink(path)
                os.symlink(external, path)
            return real_open(file, *args, **kwargs)
        with patch('builtins.open', side_effect=swap), patch('asyncio.create_subprocess_exec', side_effect=AssertionError('No spawn')):
            result = self.call(binary_checksec, path)
        self.assertIs(result['coverage_complete'], False)
        self.assertNotIn('synthetic-sensitive-replacement', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
