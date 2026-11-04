"""Nmap/searchsploit adapters with mocked processes only."""
import asyncio
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
NMAP = b'''<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="fixture" version="1"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''
SEARCH = b'''Exploit Title | Path
--------------- | ---------------
Fixture issue | linux/local/123.py
Shellcodes: No Results
'''


class CliRemainingAccuracy(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, name, stdout=None, code=0, timeout=False):
        module = importlib.import_module('cyber_tools.' + name)
        proc = AsyncMock()
        proc.returncode = None if timeout else code
        proc.kill = Mock()
        proc.communicate.return_value = (stdout if stdout is not None else (NMAP if name == 'nmap_scan' else SEARCH),
                                         b'Authorization: secret-exception-material')
        with patch.object(module.asyncio, 'create_subprocess_exec', return_value=proc) as spawn:
            if timeout:
                async def expired(awaitable, timeout):
                    if asyncio.iscoroutine(awaitable):
                        awaitable.close()
                    raise asyncio.TimeoutError('secret-exception-material')
                with patch.object(module.asyncio, 'wait_for', side_effect=expired):
                    result = await getattr(module, name)('fixture argument; unchanged')
            else:
                result = await getattr(module, name)('fixture argument; unchanged')
        return result, proc, spawn.call_args.args

    async def test_nmap_positive_open_ports_and_argv(self):
        result, _, argv = await self.invoke('nmap_scan')
        self.assertEqual(result['total_open'], 1)
        self.assertEqual(result['hosts'][0]['open_ports'][0]['port'], '443')
        self.assertIn('fixture argument; unchanged', argv)
        self.assertTrue(result['coverage_complete'])

    async def test_search_header_excluded_and_columns_preserved(self):
        result, _, argv = await self.invoke('searchsploit')
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['results'][0]['title'], 'Fixture issue')
        self.assertEqual(result['results'][0]['path'], 'linux/local/123.py')
        self.assertEqual(argv, ('searchsploit', 'fixture argument; unchanged'))
        self.assertTrue(result['coverage_complete'])

    async def test_malformed_and_wrong_root_are_structured_incomplete(self):
        for name, outputs in (('nmap_scan', (b'not XML secret-exception-material', b'<unrelated/>')),
                              ('searchsploit', (b'garbled secret-exception-material', b'Title | invalid path'))):
            for output in outputs:
                result, _, _ = await self.invoke(name, stdout=output)
                self.assertFalse(result['coverage_complete'])
                self.assertIn('error', result)
                self.assertNotIn('secret-exception-material', json.dumps(result))

    async def test_nonzero_retains_structured_partial_results(self):
        for name in ('nmap_scan', 'searchsploit'):
            result, _, _ = await self.invoke(name, code=2)
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(result['exit_code'], 2)
            self.assertEqual(result.get('total_open', result.get('count')), 1)
            self.assertNotIn('secret-exception-material', json.dumps(result))

    async def test_timeout_reaps_process_and_is_incomplete(self):
        for name in ('nmap_scan', 'searchsploit'):
            result, proc, _ = await self.invoke(name, timeout=True)
            proc.kill.assert_called_once()
            self.assertEqual(proc.communicate.await_count, 1)
            self.assertFalse(result['coverage_complete'])
            self.assertNotIn('secret-exception-material', json.dumps(result))

    async def test_missing_binary_is_generic_error(self):
        for name in ('nmap_scan', 'searchsploit'):
            module = importlib.import_module('cyber_tools.' + name)
            with patch.object(module.asyncio, 'create_subprocess_exec', side_effect=FileNotFoundError('secret-exception-material')):
                result = await getattr(module, name)('fixture')
            self.assertFalse(result['coverage_complete'])
            self.assertNotIn('secret-exception-material', json.dumps(result))

    async def test_supported_empty_results(self):
        for name, output in (('nmap_scan', b'<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'),
                             ('searchsploit', b'Exploits: No Results\nShellcodes: No Results')):
            result, _, _ = await self.invoke(name, stdout=output)
            self.assertTrue(result['coverage_complete'])
            self.assertEqual(result.get('total_open', result.get('count')), 0)

    async def test_nmap_failure_marker_overrides_zero_exit(self):
        result, _, _ = await self.invoke('nmap_scan', stdout=NMAP.replace(b'exit="success"', b'exit="error" errormsg="secret-exception-material"'))
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('secret-exception-material', json.dumps(result))

    async def test_existing_timeouts_and_nmap_options_are_preserved(self):
        for name, seconds in (('nmap_scan', 180), ('searchsploit', 30)):
            module = importlib.import_module('cyber_tools.' + name)
            run = AsyncMock(return_value={'exit_code': 0, 'stdout': (NMAP if name == 'nmap_scan' else SEARCH).decode(), 'stderr': ''})
            with patch.object(module, '_run_cli', run):
                if name == 'nmap_scan':
                    await module.nmap_scan('fixture;literal', ports='80,443', scripts='safe and default')
                    self.assertEqual(run.call_args.args[0], ['nmap', '-oX', '-', 'fixture;literal', '-p', '80,443', '--script', 'safe and default', '-sV'])
                else:
                    await module.searchsploit('one query with spaces')
                    self.assertEqual(run.call_args.args[0], ['searchsploit', 'one query with spaces'])
                self.assertEqual(run.call_args.kwargs['timeout'], seconds)

    async def test_search_result_cap_preserves_total_count(self):
        output = '\n'.join(f'Fixture {i} | linux/local/{i}.py' for i in range(35)).encode()
        result, _, _ = await self.invoke('searchsploit', stdout=output)
        self.assertEqual(len(result['results']), 30)
        self.assertEqual(result['count'], 35)


if __name__ == '__main__':
    unittest.main()
