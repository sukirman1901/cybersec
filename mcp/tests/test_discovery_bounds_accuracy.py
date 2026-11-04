"""Offline discovery evidence and resource-limit regression fixtures."""
import asyncio
import importlib
import json
import sys
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
s3 = importlib.import_module('cyber_tools.s3_scanner')
vh = importlib.import_module('cyber_tools.vhost_discovery')


class DiscoveryBoundsAccuracy(unittest.IsolatedAsyncioTestCase):
    async def run_tool(self, module, target, handler, **limits):
        seen = []
        async def respond(request):
            seen.append(request)
            value = handler(request)
            return await value if asyncio.iscoroutine(value) else value
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        with patch.object(module.httpx, 'AsyncClient', return_value=client):
            with patch.multiple(module, create=True, **limits) if limits else nullcontext():
                result = await getattr(module, module.__name__.split('.')[-1])(target)
        return result, seen

    async def test_bucket_listing_identity_and_privacy(self):
        xml = '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><IsTruncated>false</IsTruncated><Contents><Key>token=fixture-secret</Key><Size>3</Size></Contents></ListBucketResult>'
        result, seen = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(200, text=xml))
        self.assertTrue(result['public'])
        self.assertEqual(result['total_files'], 1)
        self.assertNotIn('fixture-secret', json.dumps(result))
        self.assertEqual(len(seen), 1)

    async def test_bucket_generic_status_is_not_identity(self):
        for status in (200, 403, 404, 301, 500):
            with self.subTest(status=status):
                result, seen = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(status, text='generic response', headers={'Location':'https://outside.test'}))
                self.assertIsNone(result['accessible'])
                self.assertIsNone(result['public'])
                self.assertFalse(result['complete'])
                self.assertEqual(len(seen), 1)

    async def test_bucket_malformed_or_wrong_identity(self):
        for xml in ('<ListBucketResult>', '<Other><Name>fixture-bucket</Name></Other>',
                    '<ListBucketResult><Name>other</Name><IsTruncated>false</IsTruncated></ListBucketResult>',
                    '<ListBucketResult><Name>fixture-bucket</Name><IsTruncated>maybe</IsTruncated></ListBucketResult>',
                    '<ListBucketResult><Name>fixture-bucket</Name><IsTruncated>false</IsTruncated><Contents><Key>x</Key></Contents></ListBucketResult>'):
            result, _ = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(200, text=xml))
            self.assertIsNone(result['public'])
            self.assertFalse(result['complete'])

    async def test_bucket_truncation_is_not_total_inventory(self):
        xml = '<ListBucketResult><Name>fixture-bucket</Name><IsTruncated>true</IsTruncated></ListBucketResult>'
        result, seen = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(200, text=xml))
        self.assertTrue(result['public'])
        self.assertFalse(result['complete'])
        self.assertEqual(len(seen), 1)

    async def test_bucket_invalid_input_no_requests_or_echo(self):
        for value in ('https://user:fixture-secret@evil.test', 'x/fixture-secret', '127.0.0.1', ''):
            result, seen = await self.run_tool(s3, value, lambda r: httpx.Response(200))
            self.assertEqual(seen, [])
            self.assertNotIn('fixture-secret', json.dumps(result))

    async def test_bucket_body_limit(self):
        result, _ = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(200, content=b'x' * 300000))
        self.assertFalse(result['complete'])
        self.assertIsNone(result['public'])

    async def test_transport_errors_are_redacted(self):
        def fail(r):
            raise httpx.ConnectError('token=fixture-secret', request=r)
        for module, target in ((s3, 'fixture-bucket'), (vh, 'https://fixture.test')):
            result, seen = await self.run_tool(module, target, fail)
            self.assertFalse(result['complete'])
            self.assertNotIn('fixture-secret', json.dumps(result))
            self.assertEqual(len(seen), 1)

    async def test_vhost_generic_differences_not_discovery(self):
        def handler(r):
            return httpx.Response(200 if r.headers['host'] == 'fixture.test' else 403, text='x' * 200)
        result, seen = await self.run_tool(vh, 'https://fixture.test', handler)
        self.assertEqual(result['discovered'], [])
        self.assertFalse(result['complete'])
        self.assertTrue(all(str(r.url) == 'https://fixture.test' for r in seen))

    async def test_vhost_soft404_is_incomplete(self):
        result, _ = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(200, text=f'<title>Not Found</title><link rel="canonical" href="https://{r.headers["host"]}/">'))
        self.assertEqual(result['discovered'], [])
        self.assertFalse(result['complete'])

    async def test_vhost_identity_candidate_without_authorization(self):
        def handler(r):
            if r.headers['host'] == 'admin.fixture.test':
                return httpx.Response(200, text='<title>fixture-secret</title><link rel="canonical" href="https://admin.fixture.test/">')
            return httpx.Response(404, text='not found')
        result, seen = await self.run_tool(vh, 'https://fixture.test:8443/path?token=fixture-secret', handler)
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['discovered'][0]['vhost'], 'admin.fixture.test')
        self.assertFalse(result['discovered'][0]['authorized'])
        self.assertNotIn('fixture-secret', json.dumps(result))
        self.assertTrue(all(str(r.url) == 'https://fixture.test:8443' for r in seen))

    async def test_vhost_reflected_catchall_not_discovery(self):
        result, _ = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(200, text=f'<link rel="canonical" href="https://{r.headers["host"]}/">Welcome'))
        self.assertEqual(result['count'], 0)
        self.assertFalse(result['complete'])

    async def test_vhost_rate_limit_stops(self):
        result, seen = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(429))
        self.assertEqual(len(seen), 1)
        self.assertFalse(result['complete'])

    async def test_vhost_request_and_body_budgets(self):
        result, seen = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(404), MAX_REQUESTS=3)
        self.assertEqual(len(seen), 3)
        self.assertEqual(result['vhosts_tested'], 2)
        self.assertFalse(result['complete'])
        result, seen = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(200, content=b'x' * 70000))
        self.assertEqual(len(seen), 1)
        self.assertFalse(result['complete'])

    async def test_total_deadlines(self):
        async def slow(r):
            await asyncio.sleep(.1)
            return httpx.Response(200)
        for module, target in ((s3, 'fixture-bucket'), (vh, 'https://fixture.test')):
            result, seen = await self.run_tool(module, target, slow, TOTAL_TIMEOUT=.01)
            self.assertFalse(result['complete'])
            self.assertEqual(len(seen), 1)

    async def test_vhost_invalid_target_no_requests(self):
        for value in ('file:///etc/passwd', 'https://user:fixture-secret@fixture.test', 'nonsense'):
            result, seen = await self.run_tool(vh, value, lambda r: httpx.Response(200))
            self.assertEqual(seen, [])
            self.assertFalse(result['complete'])
            self.assertNotIn('fixture-secret', json.dumps(result))

    async def test_vhost_aggregate_bytes_and_result_limits(self):
        result, seen = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(404, content=b'x' * 40000), MAX_TOTAL_BODY=90000)
        self.assertEqual(len(seen), 3)
        self.assertFalse(result['complete'])
        def identity(r):
            host = r.headers['host']
            if host == 'fixture.test':
                return httpx.Response(404)
            return httpx.Response(200, text=f'<link rel="canonical" href="https://{host}/">')
        result, seen = await self.run_tool(vh, 'https://fixture.test', identity, MAX_RESULTS=2)
        self.assertEqual(result['count'], 2)
        self.assertEqual(len(seen), 3)
        self.assertFalse(result['complete'])

    async def test_bucket_result_limit_and_dtd_rejection(self):
        xml = '<ListBucketResult><Name>fixture-bucket</Name><IsTruncated>false</IsTruncated>' + '<Contents><Key>private</Key><Size>1</Size></Contents>' * 101 + '</ListBucketResult>'
        result, _ = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(200, text=xml))
        self.assertTrue(result['public'])
        self.assertEqual(len(result['files']), 100)
        self.assertFalse(result['complete'])
        result, _ = await self.run_tool(s3, 'fixture-bucket', lambda r: httpx.Response(200, text='<!DOCTYPE foo [<!ENTITY x "value">]>' + xml))
        self.assertIsNone(result['public'])

    async def test_stream_limit_closes_without_consuming_tail(self):
        class Stream(httpx.AsyncByteStream):
            closed = False
            chunks = 0
            async def __aiter__(self):
                for _ in range(100):
                    self.chunks += 1
                    yield b'x' * 32768
            async def aclose(self):
                self.closed = True
        for module, target, maximum in ((s3, 'fixture-bucket', 9), (vh, 'https://fixture.test', 3)):
            stream = Stream()
            result, seen = await self.run_tool(module, target, lambda r: httpx.Response(200, stream=stream))
            self.assertEqual(stream.chunks, maximum)
            self.assertTrue(stream.closed)
            self.assertFalse(result['complete'])
            self.assertEqual(len(seen), 1)

    async def test_malformed_or_encoded_responses_incomplete(self):
        for module, target in ((s3, 'fixture-bucket'), (vh, 'https://fixture.test')):
            for content, headers in ((b'\xff', {}), (b'opaque', {'Content-Encoding': 'unsupported'})):
                result, seen = await self.run_tool(module, target, lambda r: httpx.Response(200, content=content, headers=headers))
                self.assertFalse(result['complete'])
                self.assertEqual(len(seen), 1)

    async def test_soft404_baseline_never_complete(self):
        result, _ = await self.run_tool(vh, 'https://fixture.test', lambda r: httpx.Response(200, text='Not found') if r.headers['host'] == 'fixture.test' else httpx.Response(404))
        self.assertFalse(result['complete'])
