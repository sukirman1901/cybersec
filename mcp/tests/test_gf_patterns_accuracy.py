"""URL classification is an offline hint, with bounded and redacted output."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.gf_patterns import gf_patterns


class GfPatternsAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_query_credentials_fragment_are_not_exported(self):
        result = await gf_patterns('https://user:synthetic-private@fixture.test/api/config.json?token=synthetic-private#synthetic-private')
        self.assertNotIn('synthetic-private', str(result))
        self.assertEqual(result['matches']['files']['count'], 1)
        self.assertEqual(result['assessment'], 'classification_hints_only')

    async def test_query_value_does_not_misclassify_endpoint(self):
        result = await gf_patterns('https://fixture.test/home?message=backup.php')
        self.assertNotIn('files', result['matches'])
        self.assertNotIn('sensitive', result['matches'])

    async def test_invalid_inputs_report_incomplete(self):
        for value in (None, 12, 'x' * 1048577):
            with self.subTest(kind=type(value).__name__):
                result = await gf_patterns(value)
                self.assertIn('error', result)
                self.assertFalse(result['coverage_complete'])

    async def test_malformed_url_skipped_without_losing_valid_neighbor(self):
        result = await gf_patterns('https://[broken/api\nhttps://fixture.test/api/health')
        self.assertEqual(result['total_urls_analyzed'], 1)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['matches']['endpoints']['count'], 1)

    async def test_entry_limit_explicit(self):
        result = await gf_patterns('\n'.join('https://fixture.test/api/' for _ in range(1001)))
        self.assertEqual(result['total_urls_analyzed'], 1000)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(len(result['matches']['endpoints']['urls']), 20)


if __name__ == '__main__':
    unittest.main()
