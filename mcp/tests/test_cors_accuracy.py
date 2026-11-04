"""Offline browser-policy semantics and bounded CORS probes."""
import asyncio
import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
module = importlib.import_module('cyber_tools.cors_check')
REAL_CLIENT = httpx.AsyncClient


class UnreadBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise AssertionError('body must not be consumed')
        yield b''


async def run_case(case, preset='observe-first', target='https://fixture.test:8443/api?token=SECRET'):
    requests = []
    def handler(request):
        requests.append(request)
        origin = request.headers.get('Origin', '')
        headers = {'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'}
        status = 200
        if case == 'wildcard':
            headers['Access-Control-Allow-Origin'] = '*'
        if case == 'uppercase':
            headers['Access-Control-Allow-Credentials'] = 'TRUE'
        if case == 'public':
            headers.pop('Access-Control-Allow-Credentials')
        host = request.url.raw_host.decode()
        host = '[' + host + ']' if ':' in host else host
        own = request.url.scheme + '://' + host + (':' + str(request.url.port) if request.url.port else '')
        if case == 'own_only' and origin != own:
            headers = {}
        if case == 'default_port_only' and origin != 'https://fixture.test':
            headers = {}
        if case == 'preflight_only' and request.method != 'OPTIONS':
            headers = {}
        if case == 'null_only' and origin != 'null':
            headers = {}
        if case == 'duplicate':
            headers = [('Access-Control-Allow-Origin', origin), ('Access-Control-Allow-Origin', origin),
                       ('Access-Control-Allow-Credentials', 'true')]
        if case == 'duplicate_acac':
            headers = [('Access-Control-Allow-Origin', origin), ('Access-Control-Allow-Credentials', 'true'),
                       ('Access-Control-Allow-Credentials', 'true')]
        if case == 'preflight_unsupported' and request.method == 'OPTIONS':
            status = 405
        if case in ('403', '429', '500', '404'):
            status = int(case)
        if case == 'redirect':
            status = 302
            headers['Location'] = 'https://outside.test/private?secret=SECRET'
        if case == 'transport':
            raise httpx.ConnectError('SECRET backend detail', request=request)
        return httpx.Response(status, headers=headers, stream=UnreadBody() if case == 'unread' else None)
    with patch.object(module.httpx, 'AsyncClient', side_effect=lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw)):
        result = await module.cors_check(target, preset)
    return result, requests


class CorsAccuracy(unittest.TestCase):
    def test_external_credentials_are_policy_candidate_not_leak(self):
        result, _ = asyncio.run(run_case('positive'))
        self.assertTrue(result['vulnerable'])
        for finding in result['findings']:
            self.assertEqual(finding['classification'], 'cors_policy_candidate')
            self.assertFalse(finding['sensitive_data_leak_verified'])
            self.assertEqual(finding['test_type'], 'actual_request')
            self.assertIn('coverage', finding)
            self.assertIn('confidence', finding)

    def test_invalid_or_public_policy_not_credentialed_vulnerability(self):
        for case in ('wildcard', 'uppercase', 'public', 'duplicate', 'duplicate_acac', 'preflight_only', 'own_only'):
            with self.subTest(case=case):
                result, _ = asyncio.run(run_case(case))
                self.assertFalse(result['vulnerable'])

    def test_null_get_policy_is_candidate(self):
        result, _ = asyncio.run(run_case('null_only'))
        self.assertTrue(result['vulnerable'])
        self.assertTrue(all(f['origin'] == 'null' for f in result['findings']))

    def test_simple_get_does_not_require_preflight_support(self):
        result, _ = asyncio.run(run_case('preflight_unsupported'))
        self.assertTrue(result['vulnerable'])
        self.assertEqual(result['execution_status'], 'partial')
        self.assertIn('OPTIONS_status:405', result['errors'])

    def test_same_origin_default_port_and_ipv6_normalization(self):
        for target, own in (('https://fixture.test:443/api', 'https://fixture.test'),
                            ('http://fixture.test:80/api', 'http://fixture.test'),
                            ('https://[::1]:8443/api', 'https://[::1]:8443')):
            with self.subTest(target=target):
                result, requests = asyncio.run(run_case('own_only', target=target))
                self.assertFalse(result['vulnerable'])
                self.assertIn(own, [r.headers.get('Origin') for r in requests])

    def test_invalid_inputs_do_not_send_requests(self):
        for target, preset in (('https://user:SECRET@fixture.test/', 'observe-first'),
                               ('https://fixture.test:bad/', 'observe-first'),
                               ('https://fixture.test/', 'invalid-preset')):
            result, requests = asyncio.run(run_case('positive', preset, target))
            self.assertEqual(requests, [])
            self.assertEqual(result['execution_status'], 'partial')
            self.assertNotIn('SECRET', json.dumps(result))

    def test_own_origin_port_is_exact_and_other_port_cross_origin(self):
        result, requests = asyncio.run(run_case('own_only'))
        self.assertFalse(result['vulnerable'])
        self.assertIn('https://fixture.test:8443', [r.headers.get('Origin') for r in requests])
        result, _ = asyncio.run(run_case('default_port_only'))
        self.assertTrue(result['vulnerable'])

    def test_blocking_status_redirect_and_errors_are_incomplete(self):
        for case in ('403', '429', '500', '404', 'redirect', 'transport'):
            with self.subTest(case=case):
                result, requests = asyncio.run(run_case(case))
                self.assertFalse(result['vulnerable'])
                self.assertEqual(result['execution_status'], 'partial')
                self.assertTrue(result['errors'])
                self.assertTrue(all(r.url.host == 'fixture.test' for r in requests))
                self.assertNotIn('SECRET', json.dumps(result))

    def test_deep_never_sends_writes_or_non_browser_origins(self):
        result, requests = asyncio.run(run_case('positive', 'staging-deep'))
        self.assertTrue(result['vulnerable'])
        self.assertTrue(all(r.method in ('GET', 'OPTIONS') and not r.content for r in requests))
        self.assertLessEqual(len(requests), 64)
        for request in requests:
            origin = request.headers.get('Origin')
            if origin != 'null':
                url = httpx.URL(origin)
                self.assertEqual(url.path, '/')
                self.assertFalse(url.query or url.fragment or url.userinfo)
        self.assertIn('mutating', result['coverage'])

    def test_bodies_not_consumed(self):
        result, _ = asyncio.run(run_case('unread'))
        self.assertTrue(result['vulnerable'])

    def test_expired_deadline_and_request_cap(self):
        with patch.object(module, 'OBSERVE_SECONDS', 0):
            result, requests = asyncio.run(run_case('positive'))
        self.assertEqual(requests, [])
        self.assertIn('budget_exhausted', result['errors'])
        with patch.object(module, 'OBSERVE_REQUESTS', 1):
            result, requests = asyncio.run(run_case('positive'))
        self.assertEqual(len(requests), 1)
        self.assertEqual(result['execution_status'], 'partial')

    def test_stalled_headers_cancel_at_deadline(self):
        async def scenario():
            async def handler(request):
                await asyncio.Event().wait()
            with patch.object(module, 'OBSERVE_SECONDS', .02), patch.object(module.httpx, 'AsyncClient', side_effect=lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw)):
                result = await asyncio.wait_for(module.cors_check('https://fixture.test'), 1)
            self.assertIn('TimeoutError', result['errors'])
            self.assertFalse(result['vulnerable'])
        asyncio.run(scenario())


if __name__ == '__main__':
    unittest.main()
