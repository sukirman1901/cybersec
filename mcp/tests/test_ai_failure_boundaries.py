"""Offline AI-tool failure boundaries; no browser or external model is used."""
import asyncio
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TOOLS = ('browser_agent_hijack', 'llm_agent_hijack', 'llm_data_exposure',
         'llm_guardrails', 'llm_model_dos', 'mcp_abuse_test', 'prompt_injection')
SECRET = 'synthetic-private-do-not-export'


async def invoke(name, handler, target='https://fixture.test', **kwargs):
    module = importlib.import_module('cyber_tools.' + name)
    seen = []
    def offline(request):
        seen.append(request)
        assert request.url.host == 'fixture.test', 'unexpected destination'
        return handler(request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(offline))
    with patch.object(httpx, 'AsyncClient', return_value=client):
        result = await getattr(module, name)(target, **kwargs)
    return result, seen


class CountingStream(httpx.AsyncByteStream):
    def __init__(self):
        self.reads = 0
        self.closed = False

    async def __aiter__(self):
        for _ in range(100):
            self.reads += 1
            yield b'x' * 8192

    async def aclose(self):
        self.closed = True


class AiFailureBoundaries(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_non_rpc_success_status_is_not_complete(self):
        result, seen = await invoke('mcp_abuse_test', lambda r: httpx.Response(204))
        self.assertFalse(result.get('coverage_complete', True))
        self.assertEqual(len(seen), 1)
        self.assertIn('error', result)

    async def test_stream_wall_deadline_closes_without_retry(self):
        class StalledStream(CountingStream):
            async def __aiter__(self):
                yield b'partial'
                await asyncio.Future()
        helper = importlib.import_module('cyber_tools.prompt_injection')
        for name in TOOLS:
            with self.subTest(tool=name), patch.object(helper, 'REQUEST_DEADLINE', 0.01):
                stream = StalledStream()
                result, seen = await invoke(name, lambda r: httpx.Response(200, stream=stream))
                self.assertTrue(stream.closed)
                self.assertEqual(len(seen), 1)
                self.assertEqual(result['error'], 'TimeoutError')
                self.assertFalse(result['coverage_complete'])

    async def test_partial_candidates_survive_later_failure(self):
        for name in ('llm_data_exposure', 'llm_agent_hijack', 'llm_model_dos', 'mcp_abuse_test'):
            with self.subTest(tool=name):
                calls = 0
                def response(request):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise httpx.ReadTimeout(SECRET, request=request)
                    if name == 'mcp_abuse_test':
                        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': 1, 'result': {'tools': []}})
                    return httpx.Response(200, text='executing 123-45-6789')
                result, seen = await invoke(name, response)
                self.assertEqual(len(seen), 2)
                self.assertFalse(result['coverage_complete'])
                self.assertTrue(result.get('findings', result.get('results')))
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_compressed_body_is_rejected_without_reading(self):
        for name in TOOLS:
            with self.subTest(tool=name):
                stream = CountingStream()
                result, seen = await invoke(name, lambda r: httpx.Response(200,
                    headers={'content-encoding': 'gzip'}, stream=stream))
                self.assertEqual(stream.reads, 0)
                self.assertTrue(stream.closed)
                self.assertEqual(len(seen), 1)
                self.assertFalse(result['coverage_complete'])

    async def test_input_prompts_and_url_credentials_are_not_reported(self):
        for name, kwargs in (('prompt_injection', {'prompt': SECRET}),
                             ('llm_data_exposure', {'extraction_prompt': SECRET}),
                             ('llm_guardrails', {'prompt': SECRET})):
            with self.subTest(tool=name):
                result, _ = await invoke(name, lambda r: httpx.Response(200, text='ok'),
                                        target='https://fixture.test/?token=' + SECRET, **kwargs)
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_echo_and_rpc_result_are_not_confirmed_effects(self):
        for name in TOOLS:
            with self.subTest(tool=name):
                def echo(request):
                    if name == 'mcp_abuse_test':
                        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': json.loads(request.content)['id'],
                                                        'result': {'content': [{'text': 'executed successfully'}]}})
                    return httpx.Response(200, text='SYSTEM_PROMPT_EXPOSED executing function <script>alert(1)</script> 123-45-6789')
                result, _ = await invoke(name, echo)
                self.assertFalse(result.get('vulnerable', False))
                self.assertFalse(result.get('detected_exposure', False))
                self.assertFalse(result.get('data_exposure_found', False))
                self.assertEqual(result.get('external_effects'), 'unverified')
                self.assertTrue(all(not item.get('detected_execution') for item in result.get('results', [])))
                self.assertTrue(all(not item.get('injected') for item in result.get('findings', [])))

    async def test_failed_http_stops_and_reports_incomplete(self):
        for name in TOOLS:
            for status in (302, 401, 429, 503):
                with self.subTest(tool=name, status=status):
                    result, seen = await invoke(name, lambda r: httpx.Response(status, text=SECRET,
                        headers={'location': 'https://outside.test/'}))
                    self.assertEqual(len(seen), 1)
                    self.assertFalse(result.get('coverage_complete', True))
                    self.assertIn('error', result)
                    self.assertNotIn(SECRET, json.dumps(result))

    async def test_timeout_is_private_and_incomplete(self):
        def fail(request):
            raise httpx.ReadTimeout(SECRET, request=request)
        for name in TOOLS:
            with self.subTest(tool=name):
                result, seen = await invoke(name, fail)
                self.assertEqual(len(seen), 1)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertIn('error', result)
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_response_limit_closes_stream_and_stops(self):
        for name in TOOLS:
            with self.subTest(tool=name):
                stream = CountingStream()
                result, seen = await invoke(name, lambda r: httpx.Response(200, stream=stream))
                self.assertEqual(len(seen), 1)
                self.assertLess(stream.reads, 100)
                self.assertTrue(stream.closed)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertIn('error', result)

    async def test_raw_content_is_not_exported(self):
        bodies = {
            'browser_agent_hijack': f'<input type="hidden" name="token" value="{SECRET}"><iframe src="https://other.test/?token={SECRET}">',
            'llm_data_exposure': f'person@example.test 123-45-6789 {SECRET}',
            'llm_guardrails': f'<script>var token="{SECRET}"</script>',
            'mcp_abuse_test': json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [{'name': SECRET, 'description': 'system token ' + SECRET}]}}),
        }
        for name in TOOLS:
            with self.subTest(tool=name):
                result, _ = await invoke(name, lambda r: httpx.Response(200, text=bodies.get(name, SECRET)))
                serialized = json.dumps(result)
                self.assertNotIn(SECRET, serialized)
                self.assertNotIn('123-45-6789', serialized)
                self.assertNotIn('person@example.test', serialized)

    async def test_malformed_rpc_is_coverage_gap(self):
        for body in ('null', '[]', '{', '{"result":null}',
                     '{"jsonrpc":"2.0","id":1,"result":{"tools":[null]}}',
                     '{"jsonrpc":"2.0","id":1,"result":{"tools":{}}}',
                     '{"jsonrpc":"2.0","id":2,"result":{}}',
                     '{"jsonrpc":"2.0","id":1,"error":{"message":"' + SECRET + '"}}'):
            with self.subTest(body=body):
                result, seen = await invoke('mcp_abuse_test', lambda r: httpx.Response(200, text=body))
                self.assertFalse(result.get('coverage_complete', True))
                self.assertIn('error', result)
                self.assertEqual(len(seen), 1)

    async def test_invalid_inputs_make_no_requests(self):
        cases = [(name, {'target': None}) for name in TOOLS]
        cases += [('llm_model_dos', {'iterations': value}) for value in (-1, 0, 6, True, '5')]
        cases += [('prompt_injection', {'prompt': []}), ('llm_guardrails', {'prompt': 12}),
                  ('llm_data_exposure', {'extraction_prompt': {}}),
                  ('browser_agent_hijack', {'page_content': []})]
        for name, kwargs in cases:
            with self.subTest(tool=name, kwargs=kwargs):
                result, seen = await invoke(name, lambda r: httpx.Response(200), **kwargs)
                self.assertFalse(seen)
                self.assertIn('error', result)
                self.assertFalse(result.get('coverage_complete', True))


if __name__ == '__main__':
    unittest.main()
