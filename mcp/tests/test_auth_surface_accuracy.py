"""Offline auth/bypass accuracy and bounded execution regressions."""
import asyncio
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class AuthSurfaceAccuracy(unittest.IsolatedAsyncioTestCase):
    async def run_tool(self, name, handler, target='https://fixture.test/private'):
        module = importlib.import_module('cyber_tools.' + name)
        requests = []

        async def record(request):
            requests.append(request)
            result = handler(request)
            return await result if asyncio.iscoroutine(result) else result

        client = httpx.AsyncClient(transport=httpx.MockTransport(record))
        # A raw-socket fallback must never escape MockTransport.
        with patch.object(module.httpx, 'AsyncClient', return_value=client), patch(
            'asyncio.open_connection', side_effect=AssertionError('raw socket escaped transport')
        ):
            result = await getattr(module, name)(target)
        return result, requests

    async def test_public_api_is_not_auth_bypass(self):
        result, _ = await self.run_tool('api_auth', lambda r: httpx.Response(200, json={'status': 'ok'}))
        self.assertEqual(result['critical_findings'], 0)
        self.assertFalse(any(row.get('auth_bypass_possible') for row in result['tests']))

    async def test_root_denial_does_not_make_public_docs_critical(self):
        result, _ = await self.run_tool('api_auth', lambda r: httpx.Response(
            403 if r.url.path == '/private' else 200, text='public docs'))
        self.assertEqual(result['critical_findings'], 0)

    async def test_redirect_and_empty_method_success_are_not_bypasses(self):
        for status in (302, 204):
            with self.subTest(status=status):
                def handler(r):
                    if r.headers.get('x-forwarded-for') or r.method in ('HEAD', 'OPTIONS'):
                        return httpx.Response(status, headers={'Location': '/login'})
                    return httpx.Response(403, text='denied')
                result, _ = await self.run_tool('bypass_403', handler)
                self.assertFalse(result['bypass_found'])

    async def test_transport_failure_is_incomplete_not_fabricated_denial(self):
        for name in ('api_auth', 'bypass_403'):
            with self.subTest(tool=name):
                def handler(r):
                    raise httpx.ConnectError('secret-token-value', request=r)
                result, requests = await self.run_tool(name, handler)
                self.assertFalse(result['coverage_complete'])
                self.assertEqual(len(requests), 1)
                self.assertNotIn('secret-token-value', json.dumps(result))
                if name == 'bypass_403':
                    self.assertIsNone(result['baseline_status'])

    async def test_unmatched_success_is_only_candidate(self):
        for name in ('api_auth', 'bypass_403'):
            def handler(r):
                return httpx.Response(200, text='<h1>Login or generic homepage</h1>') if r.headers.get('x-forwarded-for') else httpx.Response(403, text='denied')
            result, _ = await self.run_tool(name, handler)
            self.assertTrue(result['candidates'])
            self.assertFalse(result.get('bypass_found', False))
            self.assertEqual(result.get('critical_findings', 0), 0)

    async def test_matched_resource_differential_preserves_positive_without_secrets(self):
        for name in ('api_auth', 'bypass_403'):
            def handler(r):
                if r.headers.get('x-forwarded-for'):
                    return httpx.Response(200, json={'resource': r.url.path, 'data': {'secret': 'never-output-this'}})
                return httpx.Response(403, json={'resource': r.url.path, 'error': 'forbidden'})
            result, _ = await self.run_tool(name, handler)
            self.assertTrue(result['bypass_found'] if name == 'bypass_403' else result['api_endpoints_exposed'])
            self.assertNotIn('never-output-this', json.dumps(result))

    async def test_unstable_negative_baseline_does_not_confirm(self):
        for name in ('api_auth', 'bypass_403'):
            seen = {}
            def handler(r):
                key = r.url.path
                seen[key] = seen.get(key, 0) + 1
                return httpx.Response(403 if seen[key] == 1 else 200, json={'resource': key, 'data': {'value': 1}})
            result, _ = await self.run_tool(name, handler)
            self.assertFalse(result.get('bypass_found', False))
            self.assertFalse(result['coverage_complete'])

    async def test_oversized_body_stops_and_marks_incomplete(self):
        for name in ('api_auth', 'bypass_403'):
            result, requests = await self.run_tool(name, lambda r: httpx.Response(403, content=b'x' * 262145))
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(len(requests), 1)

    async def test_denied_surface_has_bounded_requests_and_no_raw_protocol(self):
        for name in ('api_auth', 'bypass_403'):
            result, requests = await self.run_tool(name, lambda r: httpx.Response(403, text='denied'))
            self.assertLessEqual(len(requests), 128)
            self.assertEqual(result['requests_attempted'], len(requests))
            self.assertIn('protocol', result['coverage'])
            self.assertTrue(all(r.method in ('GET', 'HEAD', 'OPTIONS') for r in requests))

    async def test_path_mutations_preserve_query_and_have_single_leading_slash(self):
        result, requests = await self.run_tool('bypass_403', lambda r: httpx.Response(403, text='denied'),
                                               'https://fixture.test/private?token=do-not-print')
        self.assertTrue(all(r.url.query == b'token=do-not-print' for r in requests))
        self.assertTrue(any(r.url.path == '/private/' for r in requests))
        self.assertNotIn('do-not-print', json.dumps(result))

    async def test_non_403_baseline_status_is_reported(self):
        result, requests = await self.run_tool('bypass_403', lambda r: httpx.Response(200, text='public'))
        self.assertEqual(result['baseline_status'], 200)
        self.assertFalse(result['bypass_found'])
        self.assertEqual(len(requests), 1)

    async def test_cookies_cannot_contaminate_controls(self):
        for name in ('api_auth', 'bypass_403'):
            def handler(r):
                if 'cookie' in r.headers:
                    return httpx.Response(200, json={'resource': r.url.path, 'data': {'private': True}})
                return httpx.Response(403, json={'resource': r.url.path, 'error': 'forbidden'},
                                      headers={'Set-Cookie': 'session=secret; Path=/'})
            result, requests = await self.run_tool(name, handler)
            self.assertTrue(all('cookie' not in r.headers for r in requests))
            self.assertFalse(result.get('bypass_found', False))

    async def test_rate_limit_and_server_failure_stop(self):
        for name in ('api_auth', 'bypass_403'):
            for status in (429, 500):
                result, requests = await self.run_tool(name, lambda r: httpx.Response(status))
                self.assertFalse(result['coverage_complete'])
                self.assertEqual(len(requests), 1)

    async def test_budget_caps_actual_requests_and_total_wait(self):
        from cyber_tools.api_auth import _AuthProbe
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403))) as client:
            probe = _AuthProbe(client, max_requests=1)
            await probe.request('GET', 'https://fixture.test')
            self.assertIsNone(await probe.request('GET', 'https://fixture.test'))
            self.assertEqual(probe.requests, 1)
            self.assertIn('budget_exhausted', probe.errors)

        async def slow(r):
            await asyncio.sleep(.1)
            return httpx.Response(403)
        async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as client:
            probe = _AuthProbe(client, seconds=.01)
            self.assertIsNone(await probe.request('GET', 'https://fixture.test'))
            self.assertFalse(probe.summary()['coverage_complete'])

    async def test_positive_must_stay_denied_without_probe_header(self):
        for name in ('api_auth', 'bypass_403'):
            changed = False
            def handler(r):
                nonlocal changed
                if r.headers.get('x-forwarded-for'):
                    changed = True
                if changed:
                    return httpx.Response(200, json={'resource': r.url.path, 'data': {'private': True}})
                return httpx.Response(403, json={'resource': r.url.path, 'error': 'forbidden'})
            result, _ = await self.run_tool(name, handler)
            self.assertFalse(result.get('bypass_found', False))
            self.assertEqual(result.get('api_endpoints_exposed', 0), 0)
            self.assertFalse(result['coverage_complete'])

    async def test_generic_candidate_does_not_hide_later_matched_positive(self):
        def handler(r):
            if r.headers.get('authorization'):
                return httpx.Response(200, text='login')
            if r.headers.get('x-forwarded-for'):
                return httpx.Response(200, json={'resource': r.url.path, 'data': {'private': True}})
            return httpx.Response(403, json={'resource': r.url.path, 'error': 'forbidden'})
        result, _ = await self.run_tool('api_auth', handler)
        self.assertTrue(result['api_endpoints_exposed'])
        self.assertTrue(result['candidates'])

    async def test_extracted_rows_retain_coverage(self):
        for name in ('api_auth', 'bypass_403'):
            for matched in (False, True):
                def handler(r):
                    if r.headers.get('x-forwarded-for'):
                        return httpx.Response(200, json={'resource': r.url.path, 'data': {'private': True}}) if matched else httpx.Response(200, text='generic')
                    return httpx.Response(403, json={'resource': r.url.path, 'error': 'forbidden'})
                result, _ = await self.run_tool(name, handler)
                rows = result.get('tests', result.get('bypasses', [])) if matched else result['candidates']
                self.assertTrue(rows)
                for row in rows:
                    self.assertIn('coverage', row)
                    self.assertIn('roles not verified', row['coverage'])

    async def test_service_port_identity_survives_redaction(self):
        for name in ('api_auth', 'bypass_403'):
            for authority in ('fixture.test:8443', '[::1]:8443'):
                result, _ = await self.run_tool(name, lambda r: httpx.Response(200),
                    'https://user:secret@' + authority + '/private?token=secret#secret')
                self.assertEqual(result['target'], 'https://' + authority)
                self.assertNotIn('secret', json.dumps(result))

    async def test_malformed_target_is_structured_without_requests(self):
        for name in ('api_auth', 'bypass_403'):
            for target in ('https://[broken', 'https://fixture.test:bad', 'https://fixture.test:99999',
                           'https:///missing-host', 'ftp://fixture.test', ''):
                with self.subTest(tool=name, target=target):
                    result, requests = await self.run_tool(name, lambda r: httpx.Response(200), target)
                    self.assertEqual(requests, [])
                    self.assertEqual(result['requests_attempted'], 0)
                    self.assertFalse(result['coverage_complete'])
                    self.assertIn('invalid_target', result['errors'])


if __name__ == '__main__':
    unittest.main()
