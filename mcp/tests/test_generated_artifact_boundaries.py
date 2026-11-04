"""Offline boundary checks; mocks do not establish operational effectiveness."""
import asyncio
import base64
import importlib
import json
from pathlib import Path
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class ArtifactBoundaries(unittest.TestCase):
    def test_invalid_targets_do_not_reach_transport(self):
        names = ('java_deserialize', 'php_deserialize', 'pickle_deserialize',
                 'upload_bypass', 'upload_exploit_chain', 'webshell_upload',
                 'webshell_connect', 'sqli_exploit', 'xss_exploit')
        for name in names:
            module = importlib.import_module('cyber_tools.' + name)
            for value in ('', None, 'https://example.invalid/\r\nsecret', 'x' * 8193):
                with self.subTest(tool=name, value_type=type(value).__name__):
                    with ExitStack() as stack:
                        mocks = [stack.enter_context(patch('httpx.AsyncClient', side_effect=AssertionError('transport forbidden')))]
                        for transport in ('GuardedAsyncClient', 'guarded_urlopen'):
                            if hasattr(module, transport):
                                mocks.append(stack.enter_context(patch.object(module, transport, side_effect=AssertionError('transport forbidden'))))
                        result = getattr(module, name)(value)
                        if asyncio.iscoroutine(result):
                            result = asyncio.run(result)
                        if isinstance(result, str):
                            result = json.loads(result)
                        self.assertTrue(result.get('error'))
                        for transport in mocks:
                            transport.assert_not_called()

    def test_download_invalid_id_does_not_construct_client(self):
        from cyber_tools.exploit_db import exploit_db_download
        with patch('httpx.AsyncClient') as client:
            for value in ('../secret', '12?token=secret', '', None, '１２', '1' * 21):
                self.assertTrue(asyncio.run(exploit_db_download(value)).get('error'))
            client.assert_not_called()

    def test_generator_template_failure_is_structured(self):
        from cyber_tools.webshell_gen import webshell_gen
        result = asyncio.run(webshell_gen(shell_type='full'))
        self.assertTrue(result['error'])
        self.assertFalse(result['generated'])
        self.assertFalse(result['executed'])

    def test_generator_synthetic_template_metadata(self):
        from cyber_tools import webshell_gen as module
        with patch.object(module, '_SHELLS', {'php': {'cmd': 'synthetic {param}'}}):
            result = asyncio.run(module.webshell_gen())
        self.assertTrue(result['generated'])
        self.assertFalse(result['executed'])
        self.assertFalse(result['verified'])

    def test_connector_http_success_is_not_execution_proof(self):
        from cyber_tools import webshell_connect as module
        client = AsyncMock()
        client.get.return_value = MagicMock(status_code=200, text='ordinary static page')
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=client)
        context.__aexit__ = AsyncMock(return_value=False)
        with patch.object(module, 'GuardedAsyncClient', return_value=context):
            result = asyncio.run(module.webshell_connect('https://example.invalid/', command='synthetic'))
        self.assertFalse(result['executed'])
        self.assertFalse(result['shell_alive'])
        self.assertTrue(result['request_sent'])

    def test_jwt_rejects_nonobject_and_invalid_claim_types(self):
        from cyber_tools.jwt_forgery import jwt_forgery
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        for header, payload in (([], {}), ({'alg': 'HS256'}, []),
                                ({'alg': 'HS256'}, {'exp': 'secret'}),
                                ({'alg': 'HS256', 'kid': 1}, {})):
            result = asyncio.run(jwt_forgery(encode(header) + '.' + encode(payload) + '.'))
            self.assertTrue(result.get('error'))
            self.assertNotIn('secret', result['error'])

    def test_jwt_generated_candidate_is_not_verified_vulnerability(self):
        from cyber_tools import jwt_forgery as module
        token = 'eyJhbGciOiJIUzI1NiJ9.e30.synthetic'
        with patch.object(module, '_build_forged_token', return_value='synthetic-artifact'):
            result = asyncio.run(module.jwt_forgery(token))
        self.assertFalse(result['vulnerable'])
        self.assertFalse(result['verified'])
        self.assertEqual(result['coverage'], 'offline_token_analysis')

    def test_response_heuristics_are_not_verified_exploits_and_close_response(self):
        for name, constant, options, response_body in (
            ('xss_exploit', 'XSS_PAYLOADS', {'xss_type': 'reflected'}, b'synthetic'),
            ('sqli_exploit', 'SQLI_PAYLOADS', {'technique': 'error_based'}, b'mysql error'),
        ):
            module = importlib.import_module('cyber_tools.' + name)
            response = MagicMock()
            response.read.return_value = response_body
            response.__enter__.return_value = response
            with self.subTest(tool=name), patch.object(module, constant, {next(iter(options.values())): ['synthetic']}), patch.object(module, 'guarded_urlopen', return_value=response):
                result = json.loads(getattr(module, name)('https://example.invalid/', **options))
            self.assertFalse(result['exploitable'])
            self.assertEqual(result['total_verified'], 0)
            self.assertTrue(result['observations'])
            response.__exit__.assert_called_once()
            response.read.assert_called_once_with(1048576)

    def test_connector_failure_does_not_echo_credentials(self):
        from cyber_tools import webshell_connect as module
        with patch.object(module, 'GuardedAsyncClient', side_effect=RuntimeError('secret-token')):
            result = asyncio.run(module.webshell_connect('https://example.invalid/'))
        self.assertNotIn('secret-token', json.dumps(result))

    def test_upload_chain_static_page_does_not_prove_execution(self):
        from cyber_tools import upload_exploit_chain as module
        response = MagicMock(status=200)
        response.read.return_value = b'ordinary static page longer than twenty characters'
        response.__enter__.return_value = response
        with patch.object(module, 'guarded_urlopen', return_value=response):
            result = module._execute_payload('https://example.invalid', '/synthetic', 'txt', 'synthetic')
        self.assertFalse(result['success'])
        self.assertFalse(result['verified'])
        response.__exit__.assert_called_once()

    def test_download_mocked_failure_and_truncation_metadata(self):
        from cyber_tools import exploit_db as module
        client, context, response, stream = self.download_transport([b'x' * 10001])
        with patch.object(module.httpx, 'AsyncClient', return_value=context) as factory:
            result = asyncio.run(module.exploit_db_download('123'))
            self.assertTrue(result['truncated'])
            self.assertEqual(result['status'], 'downloaded')
            self.assertEqual(result['content'], 'x' * 10000)
            self.assertEqual(result['content_length'], 10001)
            self.assertFalse(result['executed'])
            self.assertFalse(result['verified'])
            self.assertFalse(factory.call_args.kwargs['follow_redirects'])
            client.get.assert_not_called()
            stream.__aexit__.assert_awaited_once()
            client.stream.side_effect = RuntimeError('secret-token')
            result = asyncio.run(module.exploit_db_download('123'))
            self.assertEqual(result['status'], 'incomplete')
            self.assertNotIn('secret-token', json.dumps(result))

    @staticmethod
    def download_transport(chunks, status=200):
        async def iterate(**kwargs):
            for chunk in chunks:
                yield chunk
        response = MagicMock(status_code=status, encoding='utf-8')
        response.aiter_bytes.side_effect = iterate
        stream = MagicMock()
        stream.__aenter__ = AsyncMock(return_value=response)
        stream.__aexit__ = AsyncMock(return_value=False)
        client = MagicMock()
        client.stream.return_value = stream
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=client)
        context.__aexit__ = AsyncMock(return_value=False)
        return client, context, response, stream

    def test_download_byte_limit_and_redirect(self):
        from cyber_tools import exploit_db as module
        for chunks, status, expected in (([b'x' * 262144], 200, 'downloaded'),
                                         ([b'x' * 262144, b'y'], 200, 'incomplete'),
                                         ([], 302, 'incomplete')):
            with self.subTest(status=status, sizes=list(map(len, chunks))):
                client, context, response, stream = self.download_transport(chunks, status)
                with patch.object(module.httpx, 'AsyncClient', return_value=context):
                    result = asyncio.run(module.exploit_db_download('123'))
                self.assertEqual(result['status'], expected)
                if expected == 'incomplete':
                    self.assertFalse(result['coverage_complete'])
                    self.assertNotIn('content', result)
                if len(chunks) == 2:
                    self.assertTrue(result['truncated'])
                client.stream.assert_called_once()
                stream.__aexit__.assert_awaited_once()

    def test_download_wall_deadline_cancels_stalled_stream(self):
        from cyber_tools import exploit_db as module
        client, context, response, stream = self.download_transport([])
        async def stalled(**kwargs):
            await asyncio.get_running_loop().create_future()
            yield b''
        response.aiter_bytes.side_effect = stalled
        real_timeout = asyncio.timeout
        with patch.object(module.httpx, 'AsyncClient', return_value=context), patch(
            'asyncio.timeout', side_effect=lambda seconds: real_timeout(0)
        ) as deadline:
            result = asyncio.run(module.exploit_db_download('123'))
        deadline.assert_called_once_with(15.0)
        self.assertEqual(result['status'], 'incomplete')
        self.assertIn('deadline', result['error'])
        stream.__aexit__.assert_awaited_once()

    def test_upload_chain_limit_and_private_failure(self):
        from cyber_tools import upload_exploit_chain as module
        for size in (1048576, 1048577):
            response = MagicMock(status=200)
            response.read.return_value = b'x' * size
            response.__enter__.return_value = response
            with patch.object(module, 'guarded_urlopen', return_value=response):
                result = module._execute_payload('https://example.invalid', '/synthetic', 'txt', 'synthetic')
            self.assertEqual(result['truncated'], size > 1048576)
            self.assertEqual(result['coverage_complete'], size <= 1048576)
            self.assertFalse(result['success'])
            response.read.assert_called_once_with(1048577)
            response.__exit__.assert_called_once()
        with patch.object(module, 'guarded_urlopen', side_effect=RuntimeError('secret-token')):
            result = module._execute_payload('https://example.invalid', '/synthetic', 'txt', 'synthetic')
        self.assertNotIn('secret-token', json.dumps(result))
        self.assertFalse(result['coverage_complete'])


if __name__ == '__main__':
    unittest.main()
