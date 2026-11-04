"""Offline HTTP recognition regressions; every request uses MockTransport."""
import importlib
import asyncio
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SECRET = 'synthetic-private-do-not-export'
ASYNC_TOOLS = ('misplaced_files', 'webshell_detect')


async def run_async(name, handler, **kwargs):
    module = importlib.import_module('cyber_tools.' + name)
    seen = []
    def offline(request):
        seen.append(request)
        if request.url.host != 'fixture.test':
            raise AssertionError('out-of-origin request')
        return handler(request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(offline))
    with patch.object(module.httpx, 'AsyncClient', return_value=client):
        result = await getattr(module, name)('https://fixture.test', **kwargs)
    return result, seen


def run_waf(handler, target='https://fixture.test/path'):
    module = importlib.import_module('cyber_tools.waf_detect')
    seen = []
    def offline(request):
        seen.append(request)
        if request.url.host != 'fixture.test':
            raise AssertionError('out-of-origin request')
        return handler(request)
    client = httpx.Client(transport=httpx.MockTransport(offline))
    # The old urllib seam also routes through MockTransport for the red phase.
    def legacy(request, **kwargs):
        response = client.get(request.full_url)
        body = io.BytesIO(response.content)
        body.headers = response.headers
        body.status = response.status_code
        return body
    try:
        with patch.object(module, 'guarded_urlopen', side_effect=legacy), patch.object(httpx, 'Client', return_value=client):
            result = module.waf_detect(target)
    finally:
        client.close()
    return result, seen


class RemainingHttpAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_successful_html_and_shell_prose_are_not_findings(self):
        for name in ASYNC_TOOLS:
            for body in ('<html>Welcome to our site</html>',
                         '<html><h1>c99shell r57shell PHPSpy</h1><p>Documentation about eval($_POST[ and fsockopen(</p></html>'):
                with self.subTest(tool=name, body=body[:25]):
                    result, _ = await run_async(name, lambda r: httpx.Response(200, text=body))
                    self.assertFalse(result.get('findings', result.get('found_shells')))
                    self.assertFalse(result.get('candidates'))

    async def test_blocked_redirect_and_server_errors_stop_at_one(self):
        for name in ASYNC_TOOLS:
            for status in (401, 403, 429, 302, 503):
                with self.subTest(tool=name, status=status):
                    result, seen = await run_async(name, lambda r: httpx.Response(status, headers={'location':'https://outside.test/'}))
                    self.assertEqual(len(seen), 1)
                    self.assertFalse(result.get('coverage_complete', True))
                    self.assertIn('error', result)

    async def test_transport_failure_is_incomplete_without_exception_text(self):
        def fail(request):
            raise httpx.ConnectError(SECRET, request=request)
        for name in ASYNC_TOOLS:
            with self.subTest(tool=name):
                result, seen = await run_async(name, fail)
                self.assertEqual(len(seen), 1)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_oversized_body_is_bounded_and_incomplete(self):
        for name in ASYNC_TOOLS:
            with self.subTest(tool=name):
                result, seen = await run_async(name, lambda r: httpx.Response(200, content=b'x' * 262145))
                self.assertEqual(len(seen), 1)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertIn('body_limit_exceeded', result.get('errors', []))

    async def test_misplaced_structural_positives_without_secret_snippets(self):
        fixtures = {
            '/.env': 'APP_ENV=production\nDB_PASSWORD=' + SECRET,
            '/.git/HEAD': 'ref: refs/heads/main\n',
            '/config.php': '<?php $db_password = "' + SECRET + '";',
            '/config.json': json.dumps({'database':{'password':SECRET}}),
            '/dump.sql': '-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);',
            '/private_key.pem': '-----BEGIN PRIVATE KEY-----\n' + 'A' * 64 + '\n-----END PRIVATE KEY-----',
        }
        result, seen = await run_async('misplaced_files', lambda r: httpx.Response(200, text=fixtures[r.url.path]) if r.url.path in fixtures else httpx.Response(404))
        self.assertEqual({x['path'] for x in result['findings']}, set(fixtures))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertTrue(all('snippet' not in x for x in result['findings']))
        self.assertLessEqual(len(seen), 33)

    async def test_misplaced_public_documents_and_malformed_formats_not_secrets(self):
        fixtures = {'/robots.txt':'User-agent: *\nDisallow: /admin', '/security.txt':'Contact: security@example.test',
                    '/package.json':'{"name":"public-package","version":"1.0.0"}',
                    '/cert.pem':'-----BEGIN CERTIFICATE-----\n' + 'A' * 64 + '\n-----END CERTIFICATE-----',
                    '/config.json':'{"password":', '/private_key.pem':'a guide to PRIVATE KEY files'}
        result, _ = await run_async('misplaced_files', lambda r: httpx.Response(200, text=fixtures[r.url.path]) if r.url.path in fixtures else httpx.Response(404))
        self.assertFalse(result['findings'])
        self.assertNotEqual(result['risk'], 'PASS')
        self.assertTrue(result.get('unsupported_paths'))

    async def test_signature_catchalls_rejected(self):
        for name, body in [('misplaced_files', 'APP_ENV=production\nDB_PASSWORD=' + SECRET),
                           ('webshell_detect', '<?php system($_GET["cmd"]); ?>')]:
            with self.subTest(tool=name):
                result, _ = await run_async(name, lambda r: httpx.Response(200, text=body))
                self.assertFalse(result.get('findings', []))
                self.assertFalse(result.get('candidates', []))

    async def test_webshell_source_is_candidate_not_confirmed_execution(self):
        for deep in (False, True):
            for code in ('<?php system($_GET["cmd"]); ?>', '<?php eval($_POST["x"]); ?>',
                         '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'):
                with self.subTest(deep=deep, code=code):
                    result, seen = await run_async('webshell_detect', lambda r: httpx.Response(200, text=code + SECRET) if r.url.path=='/shell.php' else httpx.Response(404), deep_scan=deep)
                    self.assertFalse(result['found_shells'])
                    self.assertEqual(result['count'], 0)
                    self.assertEqual(len(result.get('candidates', [])), 1)
                    self.assertTrue(result['signatures_matched'])
                    self.assertNotIn(SECRET, json.dumps(result))
                    self.assertLessEqual(len(seen), 33)

    async def test_webshell_normal_source_and_filenames_not_candidates(self):
        for body in ('<?php fsockopen("localhost", 80); ?>',
                     '<?php echo "r57shell"; ?>', '<html>Uploaded successfully</html>',
                     '<?php /* system($_GET["cmd"]); */ echo "example"; ?>',
                     '<?php echo \'system($_GET["cmd"]);\'; ?>',
                     '<?php echo "documentation"; ?>Example: system($_GET["cmd"]);'):
            with self.subTest(body=body):
                result, _ = await run_async('webshell_detect', lambda r: httpx.Response(200, text=body) if r.url.path=='/shell.php' else httpx.Response(404))
                self.assertFalse(result['found_shells'])
                self.assertFalse(result.get('candidates'))

    async def test_webshell_budget_and_uncrawled_links_explicit(self):
        result, seen = await run_async('webshell_detect', lambda r: httpx.Response(200, text='<a href="https://outside.test/shell.php">shell</a>') if r.url.path=='/' else httpx.Response(404), deep_scan=True)
        self.assertLessEqual(len(seen), 33)
        self.assertGreater(result.get('candidates_deferred', 0), 0)
        self.assertFalse(result.get('coverage_complete', True))
        self.assertTrue(result.get('unsupported_detection'))

    async def test_deadline_cancels_stalled_mock_response(self):
        from cyber_tools.surface_probe import SurfaceProbe
        for name in ASYNC_TOOLS:
            with self.subTest(tool=name):
                module = importlib.import_module('cyber_tools.' + name)
                closed = []
                async def stall(request):
                    try:
                        await asyncio.Event().wait()
                    finally:
                        closed.append(True)
                client = httpx.AsyncClient(transport=httpx.MockTransport(stall))
                def bounded(client, **kwargs):
                    kwargs['seconds'] = 0.01
                    return SurfaceProbe(client, **kwargs)
                with patch.object(module.httpx, 'AsyncClient', return_value=client), patch.object(module, 'SurfaceProbe', side_effect=bounded):
                    result = await getattr(module, name)('https://fixture.test')
                self.assertEqual(closed, [True])
                self.assertEqual(result['requests_attempted'], 1)
                self.assertFalse(result['coverage_complete'])
                self.assertIn('TimeoutError', result['errors'])


class WafAccuracy(unittest.TestCase):
    def test_prose_cookies_and_incidental_headers_not_waf(self):
        for headers, body in [({}, 'AWS F5 cloudflare ModSecurity NOYB Akamai security article'),
                              ({'set-cookie':'session=AWS-F5-cloudflare; Secure'}, ''),
                              ({'x-note':'cloudflare', 'server':'Apache'}, '')]:
            with self.subTest(headers=headers):
                result, seen = run_waf(lambda r: httpx.Response(200, headers=headers, text=body))
                self.assertFalse(result['waf_detected'])
                self.assertEqual(len(seen), 1)

    def test_cloudflare_edge_not_waf_attestation(self):
        result, _ = run_waf(lambda r: httpx.Response(200, headers={'server':'cloudflare','cf-ray':'synthetic-ray'}))
        self.assertFalse(result['waf_detected'])
        self.assertTrue(result.get('observations'))
        self.assertFalse(result.get('waf_confirmed', True))

    def test_specific_product_header_recognized_as_hint(self):
        result, _ = run_waf(lambda r: httpx.Response(200, headers={'server':'ModSecurity/3.0'}))
        self.assertTrue(result['waf_detected'])
        self.assertEqual(result['waf_name'], 'ModSecurity')
        self.assertEqual(result.get('assessment'), 'product_hint_only')
        self.assertFalse(result.get('waf_confirmed', True))

    def test_blocking_and_transport_are_incomplete_and_redacted(self):
        for status in (403, 429, 302, 503):
            with self.subTest(status=status):
                result, seen = run_waf(lambda r: httpx.Response(status, headers={'location':'https://outside.test/'}))
                self.assertFalse(result.get('coverage_complete', True))
                self.assertEqual(len(seen), 1)
                self.assertFalse(result['waf_detected'])
        def fail(request):
            raise httpx.ConnectError(SECRET, request=request)
        result, _ = run_waf(fail)
        self.assertFalse(result.get('coverage_complete', True))
        self.assertNotIn(SECRET, json.dumps(result))

    def test_original_http_scheme_path_and_query_redaction(self):
        result, seen = run_waf(lambda r: httpx.Response(200), target='http://fixture.test:8080/test?token=' + SECRET)
        self.assertEqual(str(seen[0].url), 'http://fixture.test:8080/test?token=' + SECRET)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_body_stream_is_not_consumed_and_is_closed(self):
        state = []
        class UnreadableBody(httpx.SyncByteStream):
            def __iter__(self):
                raise AssertionError('WAF body must not be downloaded')
            def close(self):
                state.append('closed')
        result, seen = run_waf(lambda r: httpx.Response(200, headers={'server':'ModSecurity'}, stream=UnreadableBody()))
        self.assertTrue(result['waf_detected'])
        self.assertEqual(len(seen), 1)
        self.assertEqual(state, ['closed'])

    def test_oversized_headers_are_incomplete(self):
        result, _ = run_waf(lambda r: httpx.Response(200, headers={'x-extra': 'x' * 16385}))
        self.assertFalse(result['coverage_complete'])
        self.assertIn('limit', result['error'])


if __name__ == '__main__':
    unittest.main()
