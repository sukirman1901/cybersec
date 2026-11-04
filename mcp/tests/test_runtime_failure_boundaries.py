"""Offline runtime boundary regressions, discoverable by pytest and unittest."""
import ast
import asyncio
import importlib
import inspect
import json
import sys
import unittest
from contextlib import ExitStack, asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx

auth = importlib.import_module('cyber_tools.auth_macro_runner')
captcha = importlib.import_module('cyber_tools.captcha_test')
frida = importlib.import_module('cyber_tools.ios_frida')
objection = importlib.import_module('cyber_tools.ios_objection')


class RuntimeFailureBoundaries(unittest.TestCase):
    def setUp(self):
        self.patches = self.enterContext(ExitStack())
        self.patches.enter_context(patch.object(auth.urllib.request, 'build_opener', side_effect=AssertionError('unexpected network')))
        self.patches.enter_context(patch.object(captcha, 'GuardedAsyncClient', side_effect=AssertionError('unexpected network')))
        self.patches.enter_context(patch.object(asyncio, 'create_subprocess_exec', AsyncMock(side_effect=AssertionError('unexpected process'))))
        self.patches.enter_context(patch.object(frida.shutil, 'which', side_effect=lambda name: '/mock/' + name))

    def mock_opener(self, response=None, error=None):
        opener = MagicMock(addheaders=[])
        opener.open.return_value = response or MagicMock(status=200)
        opener.open.side_effect = error
        self.patches.enter_context(patch.object(auth.urllib.request, 'build_opener', return_value=opener))
        return opener

    def mock_http(self, body=b'captcha_secret', error=None, chunks=None):
        """Model streaming transport; legacy get/post also mocked for red runs."""
        client = MagicMock()
        sent, closed, consumed = [], [], []

        async def request(*args, **kwargs):
            sent.append(1)
            if error:
                raise error
            return httpx.Response(200, content=body, request=httpx.Request('GET', 'https://example.test'))

        @asynccontextmanager
        async def stream(method, url, **kwargs):
            sent.append(1)
            try:
                if error:
                    raise error
                response = MagicMock(status_code=200, headers=httpx.Headers(), request=httpx.Request(method, url))
                async def iterate():
                    for chunk in chunks if chunks is not None else [body]:
                        consumed.append(len(chunk))
                        yield chunk
                response.aiter_bytes = iterate
                yield response
            finally:
                closed.append(1)

        client.stream = MagicMock(side_effect=stream)
        client.get = AsyncMock(side_effect=request)
        client.post = AsyncMock(side_effect=request)
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=client)
        context.__aexit__ = AsyncMock(return_value=False)
        self.patches.enter_context(patch.object(captcha, 'GuardedAsyncClient', return_value=context))
        return client, sent, closed, consumed

    def test_auth_invalid_input_never_opens(self):
        for kwargs in [{'target': ''}, {'target': 'https://example.test', 'auth_type': 'unknown'},
                       {'target': 'https://example.test', 'steps_json': '{}'},
                       {'target': 'https://example.test', 'steps_json': '[null]'},
                       {'target': 'https://example.test', 'steps_json': json.dumps([{}] * 9)},
                       {'target': 'https://user:secret@example.test'}]:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(json.loads(auth.auth_macro_runner(**kwargs))['error_kind'], 'invalid_input')
        auth.urllib.request.build_opener.assert_not_called()

    def test_auth_basic_redacts_and_does_not_confirm(self):
        self.mock_opener()
        result = json.loads(auth.auth_macro_runner('https://example.test', 'basic', 'alice', 'secret'))
        self.assertEqual(result['session']['headers']['Authorization'], '[REDACTED]')
        self.assertFalse(result['session']['authenticated'])
        self.assertEqual(result['session']['verification'], 'unverified')

    def test_auth_failure_does_not_echo_exception(self):
        self.mock_opener(error=TimeoutError('password=secret'))
        output = auth.auth_macro_runner('https://example.test', 'basic', 'alice', 'secret')
        self.assertNotIn('secret', output)
        self.assertFalse(json.loads(output)['steps'][0]['authenticated'])

    def test_runtime_suppresses_raw_output_and_preserves_failure(self):
        for module, kwargs in [(frida, {'action': 'ps'}), (objection, {'package': 'app'})]:
            for kind, code in [(None, 0), (None, 2), ('timeout', -1), ('spawn_error', -1), ('output_limit', -1)]:
                with self.subTest(module=module.__name__, kind=kind, code=code):
                    runner = AsyncMock(return_value={'stdout': 'secret', 'stderr': 'token=secret', 'exit_code': code,
                                                    'error_kind': kind, 'cleanup_complete': True})
                    with patch.object(module, '_run_cli', runner):
                        result = asyncio.run(getattr(module, module.__name__.split('.')[-1])(**kwargs))
                    self.assertNotIn('secret', json.dumps(result))
                    self.assertEqual(result['exit_code'], code)
                    self.assertFalse(result['confirmed'])
                    self.assertEqual(result['status'], 'completed' if code == 0 else 'failed')
                    self.assertEqual(runner.await_args.kwargs['timeout'], 120)

    def test_frida_ps_checks_actual_executable(self):
        with patch.object(frida.shutil, 'which', side_effect=lambda name: None if name == 'frida-ps' else '/mock/frida'):
            self.assertFalse(asyncio.run(frida.ios_frida('ps'))['available'])

    def test_frida_placeholder_is_explicitly_unsupported(self):
        self.assertEqual(asyncio.run(frida.ios_frida('ssl_pinning', 'app'))['error_kind'], 'unsupported')

    def test_runtime_invalid_input(self):
        for module, kwargs in [(frida, {'action': 'methods', 'process': ' '}), (objection, {'package': ' '}),
                               (frida, {'action': 'invalid'}), (objection, {'action': 'invalid', 'package': 'app'})]:
            with self.subTest(module=module.__name__, kwargs=kwargs):
                result = asyncio.run(getattr(module, module.__name__.split('.')[-1])(**kwargs))
                self.assertEqual(result['error_kind'], 'invalid_input')

    def test_captcha_invalid_or_unsupported_never_connects(self):
        for kwargs, kind in [({'target': ''}, 'invalid_input'),
                             ({'target': 'https://example.test', 'action': 'invalid'}, 'invalid_input'),
                             ({'target': 'https://example.test', 'action': 'recaptcha'}, 'unsupported'),
                             ({'target': 'https://example.test', 'captcha_url': 'https://example.test/image'}, 'unsupported')]:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(asyncio.run(captcha.captcha_test(**kwargs))['error_kind'], kind)
        captcha.GuardedAsyncClient.assert_not_called()

    def test_captcha_detection_failure_stops_and_redacts(self):
        client, sent, _, _ = self.mock_http(error=TimeoutError('cookie=secret'))
        result = asyncio.run(captcha.captcha_test('https://example.test'))
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(len(sent), 1)
        client.post.assert_not_called()

    def test_captcha_heuristics_are_not_confirmed(self):
        self.mock_http()
        result = asyncio.run(captcha.captcha_test('https://example.test', 'detect'))
        self.assertIsNone(result['summary']['vulnerable'])
        self.assertFalse(result['confirmed'])

    def test_captcha_runtime_unavailable_is_structured(self):
        result = asyncio.run(captcha.captcha_test('https://example.test', 'detect'))
        self.assertEqual(result['status'], 'incomplete')
        self.assertNotIn('unexpected network', json.dumps(result))

    def test_auth_response_read_is_bounded_and_closed(self):
        response = MagicMock(status=200)
        response.read.return_value = b'{}'
        self.mock_opener(response)
        auth.auth_macro_runner('https://example.test', 'bearer')
        response.read.assert_called_once_with(1048577)
        response.close.assert_called_once()

    def test_auth_failed_step_stops_chain(self):
        opener = self.mock_opener(error=TimeoutError('secret'))
        result = json.loads(auth.auth_macro_runner('https://example.test', steps_json='[{}, {}]'))
        self.assertEqual(len(result['steps']), 1)
        self.assertEqual(opener.open.call_count, 1)

    def test_captcha_total_timeout_is_redacted(self):
        async def timeout(coro, timeout):
            self.assertEqual(timeout, 30)
            coro.close()
            raise asyncio.TimeoutError('secret')
        with patch.object(captcha.asyncio, 'wait_for', timeout):
            result = asyncio.run(captcha.captcha_test('https://example.test', 'detect'))
        self.assertEqual(result['error_kind'], 'timeout')
        self.assertNotIn('secret', json.dumps(result))

    def test_server_mapping_and_signatures(self):
        tree = ast.parse((Path(__file__).parents[1] / 'server.py').read_text())
        for module, name, alias in [(auth, 'auth_macro_runner', '_auth_macro_runner'), (captcha, 'captcha_test', '_captcha'),
                                   (frida, 'ios_frida', '_ios_fr'), (objection, 'ios_objection', '_ios_obj')]:
            with self.subTest(name=name):
                node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
                self.assertEqual([a.arg for a in node.args.args], list(inspect.signature(getattr(module, name)).parameters))
                self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == alias for n in ast.walk(node)))

    def test_captcha_request_budget(self):
        _, sent, _, _ = self.mock_http(body=b'captcha invalid')
        result = asyncio.run(captcha.captcha_test('https://example.test', 'all'))
        self.assertLessEqual(len(sent), 8)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['error_kind'], 'request_budget')

    def test_runtime_missing_cli_and_cancellation(self):
        for module, kwargs in [(frida, {'action': 'ps'}), (objection, {'package': 'app'})]:
            with self.subTest(module=module.__name__):
                call = getattr(module, module.__name__.split('.')[-1])
                with patch.object(module.shutil, 'which', return_value=None):
                    self.assertEqual(asyncio.run(call(**kwargs))['error_kind'], 'unavailable')
                with patch.object(module, '_run_cli', AsyncMock(side_effect=asyncio.CancelledError)):
                    with self.assertRaises(asyncio.CancelledError):
                        asyncio.run(call(**kwargs))

    def test_auth_oversized_response_closes_and_stops(self):
        response = MagicMock(status=200)
        response.read.return_value = b'x' * 1048577
        self.mock_opener(response)
        result = json.loads(auth.auth_macro_runner('https://example.test', steps_json='[{}, {}]'))
        self.assertIn('error', result['steps'][0])
        self.assertEqual(len(result['steps']), 1)
        response.close.assert_called_once()

    def test_captcha_stream_limit_closes_without_consuming_tail(self):
        client, sent, closed, consumed = self.mock_http(chunks=[b'x' * 262144, b'x', b'secret'])
        result = asyncio.run(captcha.captcha_test('https://example.test', 'all'))
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['error_kind'], 'body_limit_exceeded')
        self.assertEqual(len(sent), 1)
        self.assertEqual(closed, [1])
        self.assertEqual(consumed, [262144, 1])
        client.get.assert_not_called()
        client.post.assert_not_called()
        self.assertNotIn('secret', json.dumps(result))

    def test_auth_aggregate_deadline_clamps_remaining_and_skips(self):
        clock = [0.0]
        response = MagicMock(status=200)
        def read(size):
            clock[0] += 26
            return b'{}'
        response.read.side_effect = read
        opener = self.mock_opener(response)
        with patch.object(auth.time, 'monotonic', side_effect=lambda: clock[0]):
            result = json.loads(auth.auth_macro_runner('https://example.test', steps_json='[{}, {}, {}]'))
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual([call.kwargs['timeout'] for call in opener.open.call_args_list], [15, 4])
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['error_kind'], 'deadline_exceeded')
        self.assertEqual(result['skipped_steps'], 1)
        self.assertFalse(result['session']['authenticated'])
        self.assertIn('cooperative', result['coverage'])
        self.assertEqual(response.close.call_count, 2)

    def test_auth_deadline_after_open_closes_before_read(self):
        clock = [0.0]
        response = MagicMock(status=200)
        opener = self.mock_opener(response)
        def open_response(*args, **kwargs):
            clock[0] = 31
            return response
        opener.open.side_effect = open_response
        with patch.object(auth.time, 'monotonic', side_effect=lambda: clock[0]):
            result = json.loads(auth.auth_macro_runner('https://example.test', 'bearer'))
        self.assertEqual(result['error_kind'], 'deadline_exceeded')
        response.read.assert_not_called()
        response.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
