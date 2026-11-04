"""Offline HTTP behavior fixtures; no sockets or live targets."""
import asyncio
import importlib
import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
module = importlib.import_module('cyber_tools.crlf_inject')


class UnreadBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise AssertionError('header-only detector must not consume response body')
        yield b''


async def run_case(case, target='https://fixture.test/redirect?next=home&token=SECRET&tag=a&tag=b'):
    requests = []
    injected = 0

    def handler(request):
        nonlocal injected
        requests.append(request)
        if case == 'transport':
            raise httpx.ConnectError('SECRET private network detail', request=request)
        if case == 'blocked':
            return httpx.Response(429)
        decoded = unquote(str(request.url))
        if case == 'double_positive':
            decoded = unquote(decoded)
        marker = re.search(r'(X-Crlf-Probe-[a-f0-9]+):\s*([a-f0-9]+)', decoded, re.I)
        has_newline = bool(marker and decoded[marker.start()-2:marker.start()] == '\r\n')
        if case == 'lf_positive':
            has_newline = bool(marker and decoded[marker.start()-1:marker.start()] == '\n'
                               and decoded[marker.start()-2:marker.start()] != '\r\n')
        if case == 'double_positive':
            has_newline = has_newline and '%250d%250a' in str(request.url).lower()
        headers = {'Set-Cookie': 'session=SECRET', 'X-Notice': 'injected', 'Location': '/safe%0d%0aX-Injected:true'}
        if marker and (case == 'control_echo' or has_newline and case in ('positive', 'redirect', 'once', 'lf_positive', 'double_positive')):
            if case != 'once' or injected == 0:
                headers[marker[1]] = marker[2]
            if has_newline:
                injected += 1
        if case == 'wrong_value' and marker and has_newline:
            headers[marker[1]] = 'not-the-marker'
        if case == 'other_header' and marker:
            headers['X-Echo'] = marker[0]
        if case == 'huge_body':
            return httpx.Response(200, headers=headers, stream=UnreadBody())
        body = '<script src="app.js"></script> alert(1) document.cookie [FAKE] Login successful for admin Set-Cookie'
        if case == 'reflection':
            body += decoded
        return httpx.Response(302 if case == 'redirect' else 200, headers=headers, text=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with patch.object(module.httpx, 'AsyncClient', return_value=client):
        result = await module.crlf_inject(target)
    return result, requests


class CrlfAccuracy(unittest.TestCase):
    def test_real_injected_header_confirmed_including_redirect(self):
        for case in ('positive', 'redirect', 'lf_positive', 'double_positive'):
            with self.subTest(case=case):
                result, requests = asyncio.run(run_case(case))
                self.assertTrue(result['vulnerable'])
                self.assertTrue(all(f['evidence']['repeat_confirmed'] and f['evidence']['control_absent'] for f in result['results']))
                self.assertGreaterEqual(len(requests), 5)
                self.assertTrue(all(r.url.host == 'fixture.test' for r in requests))
                markers = [re.search(r'X-Crlf-Probe-([a-f0-9]+)', str(r.url)) for r in requests]
                markers = [m[1] for m in markers if m]
                self.assertTrue(all(markers.count(m) == 2 for m in set(markers)))

    def test_incidental_and_reflected_content_is_not_confirmation(self):
        for case in ('static', 'reflection', 'control_echo', 'once', 'wrong_value', 'other_header'):
            with self.subTest(case=case):
                result, _ = asyncio.run(run_case(case))
                self.assertFalse(result['vulnerable'])
                self.assertEqual(result['results'], [])

    def test_query_preserved_and_secrets_not_reported(self):
        result, requests = asyncio.run(run_case('positive'))
        self.assertNotIn('SECRET', json.dumps(result))
        for request in requests:
            tags = request.url.params.get_list('tag')
            self.assertEqual(tags[-1], 'b')
            if 'X-Crlf-Probe-' not in tags[0]:
                self.assertEqual(tags, ['a', 'b'])
            # Existing values are retained unless that parameter is the tested point.
            self.assertIn('token', request.url.params)
        self.assertIn('untested_techniques', result['coverage'])
        self.assertFalse(result['coverage']['coverage_complete'])

    def test_requests_bounded(self):
        result, requests = asyncio.run(run_case('static'))
        self.assertLessEqual(len(requests), 49)
        self.assertEqual(result['coverage']['requests_attempted'], len(requests))

    def test_failures_visible_and_redacted(self):
        for case in ('transport', 'blocked'):
            result, requests = asyncio.run(run_case(case))
            self.assertFalse(result['vulnerable'])
            self.assertEqual(len(requests), 1)
            self.assertEqual(result['coverage']['execution_status'], 'partial')
            self.assertTrue(result['coverage']['errors'])
            self.assertNotIn('SECRET', json.dumps(result))

    def test_body_is_never_read(self):
        result, _ = asyncio.run(run_case('huge_body'))
        self.assertFalse(result['vulnerable'])

    def test_budget_cannot_leave_unconfirmed_finding(self):
        with patch.object(module, 'MAX_REQUESTS', 3):
            result, requests = asyncio.run(run_case('positive'))
        self.assertEqual(len(requests), 3)
        self.assertFalse(result['vulnerable'])
        self.assertIn('budget_exhausted', result['coverage']['errors'])

    def test_extracted_findings_have_independent_coverage_snapshots(self):
        result, _ = asyncio.run(run_case('positive'))
        finding = result['results'][0]
        snapshot = json.dumps(finding['coverage'], sort_keys=True)
        self.assertEqual(finding['coverage']['surface'], 'GET query; first-hop response headers')
        self.assertEqual(finding['coverage']['parameter_occurrence'], 1)
        self.assertEqual(finding['coverage']['encoding'], finding['payload'])
        self.assertFalse(finding['coverage']['coverage_complete'])
        self.assertFalse(finding['coverage']['redirects_followed'])
        self.assertIn('log_forgery', finding['coverage']['untested'])
        result['coverage']['untested_techniques'].clear()
        result['coverage']['requests_attempted'] = -1
        result['results'][1]['coverage']['surface'] = 'changed'
        self.assertEqual(json.dumps(finding['coverage'], sort_keys=True), snapshot)

    def test_zero_deadline_sends_no_requests(self):
        with patch.object(module, 'MAX_SECONDS', 0):
            result, requests = asyncio.run(run_case('positive'))
        self.assertEqual(requests, [])
        self.assertFalse(result['vulnerable'])
        self.assertIn('budget_exhausted', result['coverage']['errors'])

    def test_deadline_interrupts_stalled_headers(self):
        async def scenario():
            cancelled = asyncio.Event()
            async def handler(request):
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            with patch.object(module.httpx, 'AsyncClient', return_value=client), patch.object(module, 'MAX_SECONDS', 0.02):
                result = await asyncio.wait_for(module.crlf_inject('https://fixture.test'), 1)
            self.assertTrue(cancelled.is_set())
            self.assertEqual(result['coverage']['requests_attempted'], 1)
            self.assertIn('TimeoutError', result['coverage']['errors'])
            self.assertFalse(result['vulnerable'])
        asyncio.run(scenario())

    def test_invalid_and_credential_urls_are_not_sent(self):
        for target in ('https://user:SECRET@fixture.test/', 'https://fixture.test:bad/'):
            result, requests = asyncio.run(run_case('positive', target))
            self.assertEqual(requests, [])
            self.assertIn('invalid_target', result['coverage']['errors'])
            self.assertNotIn('SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
