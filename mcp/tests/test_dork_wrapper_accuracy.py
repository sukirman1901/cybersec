"""Execute the actual wrapper AST offline; MCP decorator/dispatch is not exercised."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import Mock


class DorkWrapperAccuracy(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'server.py'
        tree = ast.parse(path.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'dork_search')
        self.assertEqual([a.arg for a in node.args.args], ['query'])
        self.assertEqual(len(node.decorator_list), 1)
        self.assertEqual(ast.unparse(node.decorator_list[0]), 'mcp.tool()')
        node.decorator_list = []
        self.provider = Mock()
        namespace = {'json': json, 'google_dork': self.provider}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
        self.wrapper = namespace['dork_search']

    def call(self, rows, query='fixture'):
        self.provider.return_value = rows
        result = json.loads(self.wrapper(query))
        self.provider.assert_called_once_with(query)
        self.assertIsInstance(result['results'], list)
        self.assertEqual(result['results'], rows)
        return result

    def test_raw_query_never_echoed(self):
        result = self.call([], 'password=DO_NOT_EXPOSE')
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))
        self.assertEqual(result['query'], '[REDACTED]')

    def test_positive_matches_counted(self):
        result = self.call([{'url': 'https://fixture.test/', 'title': 'Fixture',
                             'record_type': 'search_match', 'coverage_complete': False}])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['diagnostic_count'], 0)
        self.assertEqual(result['assessment'], 'provider_records')
        self.assertFalse(result['coverage_complete'])

    def test_error_row_is_not_a_match(self):
        result = self.call([{'error': 'HTTPError', 'record_type': 'error',
                             'assessment': 'incomplete', 'execution_status': 'partial'}])
        self.assertEqual(result['count'], 0)
        self.assertEqual(result['diagnostic_count'], 1)
        self.assertEqual(result['assessment'], 'incomplete')
        self.assertEqual(result['error'], 'HTTPError')
        self.assertFalse(result['coverage_complete'])

    def test_mixed_legacy_match_and_error(self):
        result = self.call([{'url': 'https://fixture.test/', 'title': 'Fixture'},
                            {'error': 'TimeoutError'}])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['diagnostic_count'], 1)
        self.assertEqual(result['execution_status'], 'partial')
        self.assertEqual(result['assessment'], 'incomplete')

    def test_empty_clean_is_distinct(self):
        result = self.call([])
        self.assertEqual(result['count'], 0)
        self.assertEqual(result['assessment'], 'no_results_in_response')
        self.assertEqual(result['execution_status'], 'completed')
        self.assertFalse(result['coverage_complete'])

    def test_invalid_input_status_propagates(self):
        result = self.call([{'error': 'Invalid query', 'execution_status': 'invalid_input'}], '')
        self.assertEqual(result['execution_status'], 'invalid_input')
        self.assertEqual(result['count'], 0)

    def test_truncation_propagates(self):
        result = self.call([{'url': 'https://fixture.test/', 'title': 'Fixture', 'truncated': True}])
        self.assertTrue(result['truncated'])
        self.assertEqual(result['execution_status'], 'partial')

    def test_unknown_rows_not_counted_as_matches(self):
        result = self.call([{'record_type': 'error'}, {'unexpected': 'value'}])
        self.assertEqual(result['count'], 0)
        self.assertEqual(result['diagnostic_count'], 2)
        self.assertEqual(result['assessment'], 'incomplete')
        self.assertIn('authorization', result['coverage'])


if __name__ == '__main__':
    unittest.main()
