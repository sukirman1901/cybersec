"""Labelled mock HTTP cases for Git exposure, Next.js and GraphQL surfaces."""
import asyncio
import importlib
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TOOLS = ('exposed_git', 'nextjs_scan', 'graphql_introspect')
CASES = ('positive', 'catchall', 'negative', 'blocked', 'transport', 'malformed', 'incidental')


async def run_case(tool, case):
    module = importlib.import_module('cyber_tools.' + tool)
    requests = []
    def handler(req):
        requests.append(str(req.url))
        path = req.url.path
        if case == 'transport':
            raise httpx.ConnectError('synthetic offline', request=req)
        if case == 'blocked':
            return httpx.Response(429, text='rate limited')
        if case == 'catchall':
            return httpx.Response(200, text='<html>Next page, source code and GraphQL __schema documentation</html>')
        if tool == 'exposed_git':
            if case == 'positive' and path == '/.git/HEAD':
                return httpx.Response(200, text='ref: refs/heads/main\n')
            if case == 'incidental' and path == '/.gitignore':
                return httpx.Response(200, text='node_modules/\n.env\n')
            if case == 'malformed':
                return httpx.Response(200, text='not a git repository')
        if tool == 'nextjs_scan':
            if case in ('positive', 'malformed') and path == '/':
                return httpx.Response(200, text='<script id="__NEXT_DATA__" type="application/json">{"buildId":"demo"}</script><a href="/_next/static/chunks/a.js.map">map</a>')
            if path == '/_next/static/chunks/a.js.map' and case == 'positive':
                return httpx.Response(200, json={'version':3, 'sources':['src/a.ts'], 'sourcesContent':['export const fixture = 1;'], 'mappings':'AAAA'})
            if path == '/_next/static/chunks/a.js.map' and case == 'malformed':
                return httpx.Response(200, text='<html>' + 'not a source map ' * 20 + '</html>')
            if case == 'incidental':
                return httpx.Response(200, text='<html>Click next to continue</html>')
        if tool == 'graphql_introspect':
            if case == 'positive':
                return httpx.Response(200, json={'data':{'__schema':{'types':[{'name':'Query'}, {'name':'Product'}]}}})
            if case == 'malformed':
                return httpx.Response(200, json={'data':{'__schema':None}})
            if case == 'incidental':
                return httpx.Response(200, json={'data':{'description':'__schema docs'}})
        return httpx.Response(404, text='Not found')
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    start = time.perf_counter()
    error = None
    try:
        with patch.object(module.httpx, 'AsyncClient', return_value=client):
            result = await getattr(module, tool)('https://fixture.test')
    except Exception as exc:
        result = {}
        error = type(exc).__name__
    detected = (result.get('git_exposed', False) if tool == 'exposed_git' else
                result.get('introspection_open', False) if tool == 'graphql_introspect' else
                any(f.get('severity') in ('high','critical') or
                    isinstance(f.get('evidence'), dict) and f['evidence'].get('embedded_source')
                    for f in result.get('findings', [])))
    return {'tool':tool, 'case':case, 'expected_positive':case=='positive', 'detected':detected,
            'elapsed_ms':(time.perf_counter()-start)*1000, 'requests':len(requests),
            'result':result, 'exception':error}


class WebSurfaceAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_source_map_without_secret_proof_not_high_or_critical(self):
        row = await run_case('nextjs_scan', 'positive')
        self.assertTrue(row['detected'])
        self.assertTrue(all(f['severity'] not in ('high', 'critical') for f in row['result']['findings']))

    async def test_surface_request_budget_is_enforced(self):
        from cyber_tools.surface_probe import SurfaceProbe
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, text='ok'))) as client:
            probe = SurfaceProbe(client, max_requests=1)
            self.assertIsNotNone(await probe.request('GET', 'https://fixture.test'))
            self.assertIsNone(await probe.request('GET', 'https://fixture.test'))
            self.assertEqual(probe.requests, 1)
            self.assertFalse(probe.summary()['coverage_complete'])

    async def test_surface_deadline_cancels_slow_response(self):
        from cyber_tools.surface_probe import SurfaceProbe
        async def slow(req):
            await asyncio.sleep(1)
            return httpx.Response(200)
        async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as client:
            probe = SurfaceProbe(client, seconds=.01)
            start = time.monotonic()
            self.assertIsNone(await probe.request('GET', 'https://fixture.test'))
            self.assertLess(time.monotonic()-start, .5)
            self.assertFalse(probe.summary()['coverage_complete'])

    async def test_surface_oversized_body_is_incomplete(self):
        from cyber_tools.surface_probe import SurfaceProbe
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b'x'*100))) as client:
            probe = SurfaceProbe(client, max_bytes=32)
            self.assertIsNone(await probe.request('GET', 'https://fixture.test'))
            self.assertFalse(probe.summary()['coverage_complete'])

    async def test_positive_signatures_retained(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'positive')
                self.assertIsNone(row['exception'])
                self.assertTrue(row['detected'])

    async def test_catchall_not_sensitive_exposure(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'catchall')
                self.assertFalse(row['detected'])

    async def test_incidental_strings_do_not_detect(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'incidental')
                self.assertIsNone(row['exception'])
                self.assertFalse(row['detected'])
                if tool == 'nextjs_scan':
                    self.assertFalse(row['result']['nextjs_detected'])

    async def test_blocked_stops_and_is_incomplete(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'blocked')
                self.assertFalse(row['result'].get('coverage_complete', True))
                self.assertEqual(row['requests'], 1)

    async def test_transport_error_not_clean(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'transport')
                self.assertIsNone(row['exception'])
                self.assertFalse(row['result'].get('coverage_complete', True))
                self.assertIn('error', row['result'])

    async def test_malformed_does_not_crash_or_confirm(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'malformed')
                self.assertIsNone(row['exception'])
                self.assertFalse(row['detected'])

    async def test_nextjs_reuses_root_response(self):
        row = await run_case('nextjs_scan', 'negative')
        self.assertEqual(row['requests'], 1)


if __name__ == '__main__':
    unittest.main()
