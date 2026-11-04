"""Static query generation and scope syntax; never contacts a search engine."""
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.dork_gen import dork_gen


class DorkGenerationAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_domain_scope_cannot_contain_search_operators(self):
        for target in ('fixture.test OR site:other.test', 'https://user:secret@fixture.test', '*.fixture.test'):
            with self.subTest(target=target):
                result = await dork_gen(category='admin_panels', target=target)
                self.assertIsNotNone(result['error'])
                self.assertFalse(result['dorks'])

    async def test_query_link_roundtrips_exactly(self):
        result = await dork_gen(category='config_leak', target='fixture.test', limit=5)
        self.assertEqual(result['count'], 5)
        for item in result['dorks']:
            self.assertEqual(parse_qs(urlsplit(item['google_link']).query)['q'], [item['dork']])
            self.assertTrue(item['dork'].startswith('site:fixture.test '))
        self.assertEqual(result['execution_status'], 'generated_only')
        self.assertEqual(result['external_requests'], 0)

    async def test_invalid_limits_and_types_are_structured(self):
        for limit in (-1, 0, 101, True, '5'):
            with self.subTest(limit=limit):
                result = await dork_gen(category='admin_panels', limit=limit)
                self.assertIsNotNone(result['error'])
        result = await dork_gen(category=['admin_panels'])
        self.assertIsNotNone(result['error'])

    async def test_unknown_category_does_not_echo_unbounded_input(self):
        result = await dork_gen(category='synthetic-private-value' * 10000)
        self.assertIsNotNone(result['error'])
        self.assertFalse('synthetic-private-value' in str(result), 'Input value leaked into error')

    async def test_unknown_selector_does_not_echo_supplied_value(self):
        for selector in ('category', 'tech', 'vuln_type'):
            with self.subTest(selector=selector):
                result = await dork_gen(**{selector: 'synthetic-private-value'})
                self.assertNotIn('synthetic-private-value', str(result))


if __name__ == '__main__':
    unittest.main()
