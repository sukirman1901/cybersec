"""Bound subprocess collection with synthetic Python children, never scanners."""
import asyncio
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
cli = importlib.import_module('cyber_tools.cli_tools')


class CliCollectionLimits(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(sys.platform != 'win32', 'POSIX process-group cleanup')
    async def test_repeated_cancellation_during_limit_cleanup_drains_pipes(self):
        original_spawn = asyncio.create_subprocess_exec
        original_killpg = cli.os.killpg
        children = []
        task = None
        async def spawn(*args, **kwargs):
            child = await original_spawn(*args, **kwargs)
            children.append(child)
            return child
        def cancel_repeatedly(remaining):
            task.cancel()
            if remaining:
                asyncio.get_running_loop().call_soon(cancel_repeatedly, remaining - 1)
        def killpg(pid, sig):
            original_killpg(pid, sig)
            asyncio.get_running_loop().call_soon(cancel_repeatedly, 2)
        try:
            with patch.object(cli, 'MAX_OUTPUT_BYTES', 4096), \
                 patch.object(cli.asyncio, 'create_subprocess_exec', side_effect=spawn), \
                 patch.object(cli.os, 'killpg', side_effect=killpg):
                task = asyncio.create_task(cli._run_cli([sys.executable, '-c',
                    'import sys,time; sys.stdout.write("x"*10000000); sys.stdout.flush(); time.sleep(10)']))
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 4)
            self.assertTrue(children[0].stdout.at_eof())
            self.assertTrue(children[0].stderr.at_eof())
            self.assertIsNotNone(children[0].returncode)
        finally:
            for child in children:
                if child.returncode is None:
                    child.kill()
                await asyncio.wait_for(asyncio.gather(child.stdout.read(), child.stderr.read(), child.wait()), 3)

    async def test_noisy_child_is_reaped_after_output_limit(self):
        with patch.object(cli, 'MAX_OUTPUT_BYTES', 4096):
            result = await asyncio.wait_for(cli._run_cli([sys.executable, '-c',
                'import sys,time; sys.stdout.write("x" * 10000000); sys.stdout.flush(); time.sleep(10)'], timeout=3), 4)
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(result['error_kind'], 'output_limit')

    async def test_wrapper_failure_metadata_does_not_export_raw_stderr(self):
        result = cli._stamp_ok({'count': 0}, 'fixture', {
            'exit_code': 2, 'stderr': 'Authorization: synthetic-private-value'})
        self.assertNotIn('synthetic-private-value', str(result))
        self.assertFalse(result['coverage_complete'])

    async def test_stdout_and_stderr_share_bounded_budget(self):
        for channel in ('stdout', 'stderr'):
            with self.subTest(channel=channel), patch.object(cli, 'MAX_OUTPUT_BYTES', 4096, create=True):
                result = await cli._run_cli([sys.executable, '-c',
                    f'import sys; sys.{channel}.write("x" * 100000); sys.{channel}.flush()'], timeout=3)
                self.assertTrue(result['output_truncated'])
                self.assertEqual(result['exit_code'], -1)
                self.assertLessEqual(len(result['stdout'].encode()) + len(result['stderr'].encode()), 4200)
                self.assertEqual(result['error_kind'], 'output_limit')

    async def test_timeout_retains_partial_output(self):
        result = await cli._run_cli([sys.executable, '-c',
            'import time; print("partial", flush=True); time.sleep(10)'], timeout=.2)
        self.assertEqual(result['exit_code'], -1)
        self.assertIn('partial', result['stdout'])
        self.assertEqual(result['error_kind'], 'timeout')

    async def test_cancellation_reaps_spawned_child(self):
        original = asyncio.create_subprocess_exec
        spawned = asyncio.Event()
        children = []
        async def create(*args, **kwargs):
            process = await original(*args, **kwargs)
            children.append(process)
            spawned.set()
            return process
        with patch.object(cli.asyncio, 'create_subprocess_exec', side_effect=create):
            task = asyncio.create_task(cli._run_cli([sys.executable, '-c', 'import time; time.sleep(10)']))
            await asyncio.wait_for(spawned.wait(), 3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)
        self.assertIsNotNone(children[0].returncode)

    @unittest.skipUnless(sys.platform != 'win32', 'POSIX process-group cleanup')
    async def test_inherited_pipe_descendant_cannot_extend_timeout(self):
        script = ('import subprocess,sys; '
                  'subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"]); '
                  'print("parent-exited",flush=True)')
        result = await asyncio.wait_for(cli._run_cli([sys.executable, '-c', script], timeout=.2), 3)
        self.assertEqual(result['error_kind'], 'timeout')
        self.assertTrue(result['cleanup_complete'])
        self.assertIn('parent-exited', result['stdout'])

    async def test_spawn_errors_do_not_echo_private_arguments(self):
        with patch.object(cli.asyncio, 'create_subprocess_exec', side_effect=OSError('synthetic-private-value')):
            result = await cli._run_cli(['missing'])
        self.assertNotIn('synthetic-private-value', str(result))
        self.assertEqual(result['error_kind'], 'spawn_error')


if __name__ == '__main__':
    unittest.main()
