"""Synthetic provider fixtures only: HTTP MockTransport and DNS/WHOIS mocks."""
import asyncio
import importlib
import json
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SECRET = 'synthetic-api-secret'
HTTP_TOOLS = ('crt_search', 'reverse_ip', 'wayback_urls', 'shodan_lookup')


async def http_case(name, response, **kwargs):
    module = importlib.import_module('cyber_tools.' + name)
    seen = []
    def handle(request):
        seen.append(request)
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response
    client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    with patch.object(module.httpx, 'AsyncClient', return_value=client), \
         patch('socket.gethostbyname', return_value='192.0.2.10'), \
         patch('socket.gethostbyaddr', return_value=('ptr.fixture.test', [], ['192.0.2.10'])):
        if name == 'shodan_lookup':
            result = await module.shodan_lookup('hostname:fixture.test', api_key=SECRET, **kwargs)
        else:
            result = await getattr(module, name)('fixture.test', **kwargs)
    return result, seen


class IntelAdapterAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_http_invalid_json_and_body_limits(self):
        for name in HTTP_TOOLS:
            for body in (b'{broken', b'x' * 262145):
                with self.subTest(tool=name, size=len(body)):
                    result, seen = await http_case(name, httpx.Response(200, content=body))
                    self.assertFalse(result['coverage_complete'])
                    self.assertTrue(result.get('error'))
                    self.assertEqual(len(seen), 1)

    async def test_http_provider_failures_incomplete_not_empty_success(self):
        for name in HTTP_TOOLS:
            for status in (401, 429, 503, 302):
                with self.subTest(tool=name, status=status):
                    result, seen = await http_case(name, httpx.Response(status, text=SECRET, headers={'location':'https://outside.test/'}))
                    self.assertFalse(result.get('coverage_complete', True))
                    self.assertTrue(result.get('error'))
                    self.assertEqual(len(seen), 1)
                    self.assertNotIn(SECRET, json.dumps(result))

    async def test_http_malformed_shapes_not_success(self):
        for name in HTTP_TOOLS:
            for value in (None, {'error':SECRET}, [None, 12]):
                with self.subTest(tool=name, value=type(value).__name__):
                    result, _ = await http_case(name, httpx.Response(200, json=value))
                    self.assertFalse(result.get('coverage_complete', True))
                    self.assertTrue(result.get('error'))
                    self.assertNotIn(SECRET, json.dumps(result))

    async def test_http_transport_errors_redacted(self):
        for name in HTTP_TOOLS:
            with self.subTest(tool=name):
                result, _ = await http_case(name, httpx.ConnectError('https://provider.test/?key=' + SECRET))
                self.assertFalse(result.get('coverage_complete', True))
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_crt_filters_names_to_domain_boundary_and_retains_missing_ids(self):
        rows = [{'name_value':'api.fixture.test\n*.fixture.test\nfixture.test.evil.test\noutside.test', 'issuer_name':'Synthetic CA'},
                {'name_value':'www.fixture.test'}, {'name_value':'https://fixture.test/?token=' + SECRET}]
        result, _ = await http_case('crt_search', httpx.Response(200, json=rows))
        self.assertEqual(result['count'], 2)
        names = '\n'.join(x['name_value'] for x in result['certificates'])
        self.assertIn('www.fixture.test', names)
        self.assertNotIn('outside.test', names)
        self.assertNotIn('evil.test', names)
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_crt_limit_and_empty_are_distinct(self):
        result, _ = await http_case('crt_search', httpx.Response(200, json=[{'id':i, 'name_value':f'n{i}.fixture.test'} for i in range(205)]))
        self.assertEqual(result['count'], 200)
        self.assertFalse(result.get('coverage_complete', True))
        self.assertTrue(result.get('truncated'))
        empty, _ = await http_case('crt_search', httpx.Response(200, json=[]))
        self.assertEqual(empty['count'], 0)
        self.assertEqual(empty.get('assessment'), 'no_results_in_response')
        self.assertIsNone(empty.get('error'))

    async def test_reverse_ip_requires_ip_association_not_arbitrary_certificate_names(self):
        rows = [{'name_value':'unrelated.test'}, {'name_value':'192.0.2.10\ncert.fixture.test\nnot a hostname\n*.fixture.test'}]
        result, _ = await http_case('reverse_ip', httpx.Response(200, json=rows))
        self.assertEqual(set(result['domains']), {'cert.fixture.test', 'ptr.fixture.test'})
        self.assertFalse(result.get('hosting_verified', True))
        self.assertEqual(result['count'], len(result['domains']))
        self.assertIn('sources_status', result)

    async def test_reverse_ip_limits_source_counts_and_partial_ptr_failure(self):
        rows = [{'name_value':'192.0.2.10\n' + f'n{i}.fixture.test'} for i in range(201)]
        result, _ = await http_case('reverse_ip', httpx.Response(200, json=rows))
        self.assertEqual(result['count'], 100)
        self.assertTrue(result['truncated'])
        self.assertFalse(result['coverage_complete'])
        self.assertLessEqual(result['sources']['crt.sh'], 100)
        module = importlib.import_module('cyber_tools.reverse_ip')
        for failure in (socket.herror(2, SECRET), ('wrong.fixture.test', [], ['198.51.100.1'])):
            client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[])))
            with patch.object(module.httpx, 'AsyncClient', return_value=client), \
                 patch.object(module.socket, 'gethostbyaddr', **({'side_effect':failure} if isinstance(failure, Exception) else {'return_value':failure})):
                result = await module.reverse_ip('192.0.2.10')
            self.assertFalse(result['coverage_complete'])
            self.assertFalse(result['domains'])
            self.assertNotIn(SECRET, json.dumps(result))

    async def test_reverse_ip_no_ptr_and_empty_ct_are_empty_not_failure(self):
        module = importlib.import_module('cyber_tools.reverse_ip')
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[])))
        with patch.object(module.httpx, 'AsyncClient', return_value=client), patch.object(module.socket, 'gethostbyaddr', side_effect=socket.herror(1, 'no PTR')):
            result = await module.reverse_ip('192.0.2.10')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['assessment'], 'no_results_in_response')


    async def test_wayback_header_scope_redaction_and_limit(self):
        rows = [['timestamp','original','statuscode','contenttype'],
                ['20260101000000','https://fixture.test/a?token=' + SECRET,'200','text/html'],
                ['20260101000000','https://fixture.test.evil.test/a','200','text/html'],
                ['20260101000000','javascript:alert(1)','200','text/html'],
                ['20260101000000','https://fixture.test/b','200','text/html']]
        result, _ = await http_case('wayback_urls', httpx.Response(200, json=rows), limit=2)
        self.assertLessEqual(result['total'], 2)
        self.assertNotIn('evil.test', json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertTrue(result.get('truncated'))
        self.assertFalse(result.get('coverage_complete', True))

    async def test_wayback_reordered_columns_and_invalid_limits(self):
        rows = [['original','timestamp','contenttype','statuscode'], ['https://fixture.test/a','20260101000000','text/html','200']]
        result, _ = await http_case('wayback_urls', httpx.Response(200, json=rows))
        self.assertEqual(result['urls'][0]['url'], 'https://fixture.test/a')
        for limit in (-1, 0, 10001, True):
            with self.subTest(limit=limit):
                result, seen = await http_case('wayback_urls', httpx.Response(200, json=[]), limit=limit)
                self.assertEqual(seen, [])
                self.assertTrue(result.get('error'))

    async def test_shodan_safe_parameters_paging_and_typed_fields(self):
        row = {'ip_str':'192.0.2.10', 'port':443, 'hostnames':['api.fixture.test','not a host'],
               'org':SECRET, 'vulns':{'CVE-2026-1234':{}, 'garbage':{}}, 'product':'fixture'}
        result, seen = await http_case('shodan_lookup', httpx.Response(200, json={'total':25,'matches':[row] * 25}))
        self.assertEqual(len(result['results']), 20)
        self.assertTrue(result.get('truncated'))
        self.assertFalse(result.get('coverage_complete', True))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(seen[0].url.params['key'], SECRET)
        self.assertEqual(result['results'][0]['hostnames'], ['api.fixture.test'])
        self.assertEqual(result['results'][0]['cve'], ['CVE-2026-1234'])
        self.assertFalse(result.get('scope_authorized', True))
        self.assertFalse(result.get('query_scope_verified', True))

    async def test_shodan_query_and_key_are_encoded_separately(self):
        module = importlib.import_module('cyber_tools.shodan_lookup')
        seen = []
        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={'total':0,'matches':[]})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        query, key = 'hostname:fixture.test &page=2', SECRET + '&query=outside.test'
        with patch.object(module.httpx, 'AsyncClient', return_value=client):
            result = await module.shodan_lookup(query, key)
        self.assertEqual(seen[0].url.params['query'], query)
        self.assertEqual(seen[0].url.params['key'], key)
        self.assertNotIn('page', seen[0].url.params)
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_shodan_malformed_match_and_nested_truncation(self):
        for match in (None, {'ip_str':'bad', 'port':443}, {'ip_str':'192.0.2.10','port':True},
                      {'ip_str':'192.0.2.10','port':443,'hostnames':'fixture.test'}):
            with self.subTest(match=match):
                result, _ = await http_case('shodan_lookup', httpx.Response(200, json={'total':1,'matches':[match]}))
                self.assertFalse(result['coverage_complete'])
                self.assertTrue(result.get('error'))
                self.assertEqual(result['results'], [])
        match = {'ip_str':'192.0.2.10','port':443,'hostnames':[f'n{i}.fixture.test' for i in range(101)]}
        result, _ = await http_case('shodan_lookup', httpx.Response(200, json={'total':1,'matches':[match]}))
        self.assertFalse(result['coverage_complete'])
        self.assertTrue(result['truncated'])

    async def test_valid_empty_provider_responses(self):
        for name, data, field in [('crt_search', [], 'certificates'),
                                  ('wayback_urls', [['timestamp','original','statuscode','contenttype']], 'urls'),
                                  ('shodan_lookup', {'total':0,'matches':[]}, 'results')]:
            with self.subTest(tool=name):
                result, _ = await http_case(name, httpx.Response(200, json=data))
                self.assertEqual(result[field], [])
                self.assertEqual(result.get('assessment'), 'no_results_in_response')
                self.assertIsNone(result.get('error'))


class AsnAccuracy(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, chunks):
        module = importlib.import_module('cyber_tools.asn_lookup')
        reader = Mock(read=AsyncMock(side_effect=chunks))
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        with patch.object(module.asyncio, 'open_connection', new=AsyncMock(return_value=(reader, writer))), \
             patch.object(module.socket, 'gethostbyname', return_value='192.0.2.10'):
            result = await module.asn_lookup('fixture.test')
        return result, writer

    async def test_header_skipped_and_matching_ip_prefix_validated(self):
        data = b'AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n64500 | 192.0.2.10 | 192.0.2.0/24 | ZZ | test | 2020-01-01 | fixture\n'
        result, writer = await self.invoke([data, b''])
        self.assertEqual(result.get('asn'), '64500')
        self.assertEqual(result.get('cidr'), '192.0.2.0/24')
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_wrong_ip_malformed_and_timeout_incomplete(self):
        for chunks in ([b'64500 | 198.51.100.1 | 198.51.100.0/24 | ZZ | test\n', b''],
                       [b'not data ' + SECRET.encode(), b''], [asyncio.TimeoutError()]):
            with self.subTest(kind=str(type(chunks[0]))):
                result, writer = await self.invoke(chunks)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertNotIn('asn', result)
                self.assertTrue(result.get('error'))
                self.assertNotIn(SECRET, json.dumps(result))
                writer.close.assert_called_once()

    async def test_empty_and_oversized_responses_not_complete(self):
        for chunks in ([b''], [b'x' * 65537, b'']):
            with self.subTest(size=len(chunks[0])):
                result, writer = await self.invoke(chunks)
                self.assertFalse(result.get('coverage_complete', True))
                self.assertTrue(result.get('error'))
                writer.close.assert_called_once()

    async def test_explicit_no_mapping_and_wrong_prefix(self):
        result, _ = await self.invoke([b'NA | 192.0.2.10 | NA | NA | NA\n', b''])
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['assessment'], 'no_results_in_response')
        result, _ = await self.invoke([b'64500 | 192.0.2.10 | 198.51.100.0/24 | ZZ | test\n', b''])
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('asn', result)

    async def test_dns_error_is_redacted_and_does_not_open_provider_connection(self):
        module = importlib.import_module('cyber_tools.asn_lookup')
        with patch.object(module.socket, 'gethostbyname', side_effect=socket.gaierror(SECRET)), \
             patch.object(module.asyncio, 'open_connection', new=AsyncMock()) as connect:
            result = await module.asn_lookup('fixture.test')
        connect.assert_not_awaited()
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_writer_closed_on_drain_failure(self):
        module = importlib.import_module('cyber_tools.asn_lookup')
        writer = Mock(drain=AsyncMock(side_effect=ConnectionResetError(SECRET)), wait_closed=AsyncMock())
        with patch.object(module.asyncio, 'open_connection', new=AsyncMock(return_value=(Mock(), writer))):
            result = await module.asn_lookup('192.0.2.10')
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn(SECRET, json.dumps(result))


if __name__ == '__main__':
    unittest.main()
