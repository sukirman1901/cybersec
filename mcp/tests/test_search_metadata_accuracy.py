"""Offline GHDB metadata contracts; all provider traffic is mocked."""
import asyncio
import importlib
import json
import io
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ghdb = importlib.import_module('cyber_tools.ghdb_search')
edb = importlib.import_module('cyber_tools.exploit_db')
google = importlib.import_module('cyber_tools.google_dork')
CLIENT = httpx.AsyncClient


def row(dork='intitle:&quot;Example&quot;', category='Footholds'):
    return f'<tr><td>2026-01-02</td><td>{dork}</td><td>{category}</td><td>Fixture</td></tr>'


class SearchMetadataAccuracy(unittest.TestCase):
    def setUp(self):
        for name in ('connect', 'connect_ex'):
            p = patch.object(socket.socket, name, side_effect=AssertionError('offline only'))
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(socket, 'getaddrinfo', side_effect=AssertionError('offline only'))
        p.start()
        self.addCleanup(p.stop)
        self.requests = []

    def lookup(self, body='', status=200, failure=None, stream=None, **kwargs):
        def handler(request):
            self.requests.append(request)
            if failure:
                raise failure
            return httpx.Response(status, text=body) if stream is None else httpx.Response(status, stream=stream)
        def client(**options):
            return CLIENT(**options, transport=httpx.MockTransport(handler))
        with patch.object(ghdb.httpx, 'AsyncClient', side_effect=client):
            return asyncio.run(ghdb.ghdb_search(**kwargs))

    def test_provider_metadata_decodes_entities(self):
        result = self.lookup(row())
        self.assertEqual(result['results'][0]['dork'], 'intitle:"Example"')
        self.assertEqual(result['results'][0]['date_added'], '2026-01-02')
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['assessment'], 'provider_records')

    def test_rate_limit_is_incomplete_even_with_templates(self):
        result = self.lookup(status=429, query='admin')
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['assessment'], 'incomplete')
        self.assertEqual(result['error'], 'HTTP 429')
        self.assertEqual(result['source'], 'builtin_templates')

    def test_timeout_is_incomplete_without_exception_secrets(self):
        result = self.lookup(failure=httpx.ReadTimeout('token=DO_NOT_EXPOSE'), query='admin')
        self.assertEqual(result['assessment'], 'incomplete')
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def test_challenge_html_is_not_empty_success(self):
        result = self.lookup('<html>Please enable JavaScript</html>')
        self.assertEqual(result['assessment'], 'incomplete')

    def test_explicit_empty_response_is_distinct(self):
        result = self.lookup('<table><tr><td colspan="4">No matching records found</td></tr></table>', query='no-fixture-match')
        self.assertEqual(result['assessment'], 'no_results_in_response')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['count'], 0)

    def test_fallback_count_equals_returned_results(self):
        result = self.lookup(status=503, limit=2)
        self.assertEqual(result['count'], len(result['results']))
        self.assertEqual(result['count'], 2)
        self.assertTrue(result['truncated'])

    def test_invalid_limits_make_no_request(self):
        for limit in (-1, 0, 101, True, '2', None):
            with self.subTest(limit=limit):
                result = self.lookup(limit=limit)
                self.assertEqual(result.get('execution_status'), 'invalid_input')
        self.assertEqual(self.requests, [])

    def test_invalid_query_makes_no_request(self):
        for query in (None, [], 'a' * 2049, 'line\nbreak'):
            with self.subTest(query=type(query).__name__):
                result = self.lookup(query=query)
                self.assertEqual(result.get('execution_status'), 'invalid_input')
        self.assertEqual(self.requests, [])

    def test_invalid_category_makes_no_request(self):
        result = self.lookup(category='unknown-category')
        self.assertEqual(result.get('execution_status'), 'invalid_input')
        self.assertEqual(self.requests, [])

    def test_category_filter_not_satisfied_by_unrelated_templates(self):
        result = self.lookup(status=429, category='Footholds')
        self.assertEqual(result['results'], [])

    def test_provider_results_are_bounded_and_marked(self):
        result = self.lookup(row() * 4, limit=2)
        self.assertEqual(result['count'], 2)
        self.assertTrue(result['truncated'])
        self.assertFalse(result['coverage_complete'])

    def test_rows_cannot_merge_across_table_boundaries(self):
        result = self.lookup('<tr><td>bad</td><td>partial</td></tr>' + row())
        self.assertEqual(result['results'][0]['date_added'], '2026-01-02')
        self.assertFalse(result['coverage_complete'])

    def test_provider_secret_assignments_are_redacted_in_links_too(self):
        result = self.lookup(row('inurl:config?api_key=DO_NOT_EXPOSE'))
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def test_response_read_is_bounded(self):
        class LargeStream(httpx.AsyncByteStream):
            reads = 0
            async def __aiter__(self):
                for _ in range(100):
                    self.reads += 1
                    yield b'x' * 65536
        stream = LargeStream()
        result = self.lookup(stream=stream)
        self.assertLess(stream.reads, 100)
        self.assertEqual(result['assessment'], 'incomplete')
        self.assertTrue(result['truncated'])

    def test_matches_have_explicit_evidence_limits(self):
        result = self.lookup(row())
        self.assertIn('not establish', result['coverage'])
        self.assertIn('authorization', result['coverage'])

    def test_legacy_single_cell_extraction_remains_partial(self):
        result = self.lookup('<table><tr><td>inurl:fixture</td></tr></table>')
        self.assertEqual(result['source'], 'exploit-db.com')
        self.assertEqual(result['results'][0]['dork'], 'inurl:fixture')
        self.assertEqual(result['results'][0]['category'], 'extracted')
        self.assertFalse(result['coverage_complete'])


class MappedSearchAccuracy(unittest.TestCase):
    setUp = SearchMetadataAccuracy.setUp

    def edb_call(self, payload=None, body=None, status=200, failure=None, detail=False, **kwargs):
        def handler(request):
            self.requests.append(request)
            self.assertNotIn('/download/', request.url.path)
            if failure:
                raise failure
            return httpx.Response(status, json=payload) if body is None else httpx.Response(status, text=body)
        def client(**options):
            return CLIENT(**options, transport=httpx.MockTransport(handler))
        with patch.object(edb.httpx, 'AsyncClient', side_effect=client):
            return asyncio.run((edb.exploit_db_detail if detail else edb.exploit_db_search)(**kwargs))

    def test_edb_positive_nested_metadata(self):
        result = self.edb_call({'data': [{'id': 123, 'description': '<a>Fixture &amp; title</a>',
            'date_published': '2026-01-02', 'author': {'name': 'Author'},
            'type': {'name': 'remote'}, 'platform': {'platform': 'Linux'}}]})
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['results'][0]['title'], 'Fixture & title')
        self.assertEqual(result['results'][0]['type'], 'remote')
        self.assertEqual(result['results'][0]['platform'], 'Linux')

    def test_edb_empty_is_completed(self):
        result = self.edb_call({'data': [], 'recordsFiltered': 0})
        self.assertEqual(result['assessment'], 'no_results_in_response')
        self.assertEqual(result['count'], 0)

    def test_edb_bad_schema_is_incomplete(self):
        for payload in ({}, [], {'data': None}, {'data': ['bad']}, {'data': [{'id': '../bad', 'description': 'title'}]}):
            with self.subTest(payload=payload):
                result = self.edb_call(payload)
                self.assertEqual(result.get('assessment'), 'incomplete')
                self.assertEqual(result['count'], 0)

    def test_edb_partial_rows_preserve_valid_records(self):
        result = self.edb_call({'data': [{'id': '12', 'description': 'Fixture', 'author': None}, None]})
        self.assertEqual(result['count'], 1)
        self.assertFalse(result['coverage_complete'])

    def test_edb_failures_not_counted_or_leaked(self):
        for options in ({'status': 429}, {'failure': httpx.ReadTimeout('token=DO_NOT_EXPOSE')}, {'body': '<html>challenge</html>'}):
            result = self.edb_call(**options)
            self.assertEqual(result['count'], 0)
            self.assertEqual(result['results'], [])
            self.assertEqual(result['assessment'], 'incomplete')
            self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def test_edb_invalid_input_no_http(self):
        for options in ({'limit': -1}, {'limit': True}, {'limit': 101}, {'port': 65536},
                        {'cve': 'bad'}, {'query': []}, {'type_': 'bad'}, {'platform': []}):
            result = self.edb_call(**options)
            self.assertEqual(result.get('execution_status'), 'invalid_input')
        self.assertEqual(self.requests, [])

    def test_edb_total_beyond_returned_is_partial(self):
        result = self.edb_call({'data': [{'id': 12, 'description': 'fixture'}], 'recordsFiltered': 20}, limit=1)
        self.assertTrue(result['truncated'])
        self.assertFalse(result['coverage_complete'])

    def test_edb_legacy_html_metadata(self):
        result = self.edb_call(body='<tr><td>12</td><td>Fixture &amp; title</td><td>Author</td><td>2026-01-02</td></tr>')
        self.assertEqual(result['results'][0]['title'], 'Fixture & title')

    def test_edb_detail_positive_metadata(self):
        result = self.edb_call(detail=True, exploit_id='12', body='<h1>Fixture &amp; title</h1><table><tr><th>Author</th><td><a>Writer</a></td></tr><tr><th>Date</th><td>2026-01-02</td></tr></table>')
        self.assertEqual(result['title'], 'Fixture & title')
        self.assertEqual(result['author'], 'Writer')
        self.assertEqual(result['date'], '2026-01-02')
        self.assertEqual(len(self.requests), 1)

    def test_edb_detail_invalid_id_no_http(self):
        for value in ('../12', '12?token=SECRET', '', None, True):
            result = self.edb_call(detail=True, exploit_id=value)
            self.assertEqual(result.get('execution_status'), 'invalid_input')
        self.assertEqual(self.requests, [])

    def test_edb_detail_challenge_and_rate_limit_incomplete(self):
        for options in ({'body': '<html>challenge</html>'}, {'status': 429}):
            result = self.edb_call(detail=True, exploit_id='12', **options)
            self.assertEqual(result.get('assessment'), 'incomplete')
            self.assertNotIn('not found', result.get('error', '').lower())

    def test_edb_query_and_metadata_redaction(self):
        result = self.edb_call({'data': [{'id': 12, 'description': 'token=DO_NOT_EXPOSE'}]}, query='api_key=DO_NOT_EXPOSE')
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def google_call(self, body='', failure=None, query='fixture'):
        response = io.BytesIO(body.encode())
        with patch.object(google.urllib.request, 'urlopen', side_effect=failure, return_value=response) as request:
            result = google.google_dork(query)
        return result, request, response

    def test_google_positive_decoded_redacted_results(self):
        result, _, _ = self.google_call('<a href="/url?q=https%3A%2F%2Ffixture.test%2F%3Ftoken%3DDO_NOT_EXPOSE&sa=U"><b>Fixture &amp; title</b></a>')
        self.assertEqual(result[0]['title'], 'Fixture & title')
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def test_google_timeout_redacted_and_incomplete(self):
        result, _, _ = self.google_call(failure=TimeoutError('token=DO_NOT_EXPOSE'))
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))
        self.assertEqual(result[0]['assessment'], 'incomplete')

    def test_google_challenge_distinct_from_explicit_empty(self):
        result, _, _ = self.google_call('<html>challenge</html>')
        self.assertEqual(result[0]['assessment'], 'incomplete')
        result, _, _ = self.google_call('<html>Your search did not match any documents.</html>')
        self.assertEqual(result, [])

    def test_google_invalid_query_no_http(self):
        for query in ('', None, 'x' * 2049, 'x\ny'):
            result, request, _ = self.google_call(query=query)
            self.assertFalse(request.called)
            self.assertEqual(result[0]['execution_status'], 'invalid_input')

    def test_google_body_budget_and_close(self):
        result, _, response = self.google_call('x' * (1048576 + 1))
        self.assertTrue(response.closed)
        self.assertTrue(result[0]['truncated'])

    def test_edb_both_metadata_paths_stop_stream_at_budget(self):
        class Stream(httpx.AsyncByteStream):
            reads = 0
            closed = False
            async def __aiter__(self):
                for _ in range(100):
                    self.reads += 1
                    yield b'x' * 65536
            async def aclose(self):
                self.closed = True
        for detail in (False, True):
            stream = Stream()
            def client(**options):
                return CLIENT(**options, transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=stream)))
            with patch.object(edb.httpx, 'AsyncClient', side_effect=client):
                result = asyncio.run(edb.exploit_db_detail('12') if detail else edb.exploit_db_search())
            self.assertLessEqual(stream.reads, 17)
            self.assertTrue(stream.closed)
            self.assertTrue(result['truncated'])
            self.assertEqual(result['assessment'], 'incomplete')

    def test_detail_heading_alone_is_not_a_record(self):
        result = self.edb_call(detail=True, exploit_id='12', body='<h1>Access denied</h1>')
        self.assertEqual(result['assessment'], 'incomplete')

    def test_detail_timeout_does_not_echo_secrets(self):
        result = self.edb_call(detail=True, exploit_id='12', failure=httpx.ReadTimeout('password=DO_NOT_EXPOSE'))
        self.assertEqual(result['assessment'], 'incomplete')
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def test_quoted_secrets_are_redacted(self):
        result = self.edb_call({'data': [{'id': 12, 'description': 'password="DO_NOT_EXPOSE"'}]})
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))

    def test_google_six_matches_capped_at_five(self):
        result, _, _ = self.google_call(''.join(f'<a href="/url?q=https://fixture.test/{i}&sa=U">Fixture</a>' for i in range(6)))
        self.assertEqual(len(result), 5)
        self.assertTrue(all(item['truncated'] for item in result))


if __name__ == '__main__':
    unittest.main()
