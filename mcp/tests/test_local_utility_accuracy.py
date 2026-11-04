"""Offline utility regressions; all mutable state is isolated."""
import asyncio
import base64
import importlib
import json
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

cm = importlib.import_module('cyber_tools.compliance_map')
ct = importlib.import_module('cyber_tools.cleanup_tracking')
wl = importlib.import_module('cyber_tools.custom_wordlist')
ce = importlib.import_module('cyber_tools.cookie_editor')


class ComplianceTests(unittest.TestCase):
    def test_invalid_input_is_not_compliant(self):
        for value in ('{', 'null', '1', '[null]', '{"findings":{}}', '[{"type":1}]'):
            with self.subTest(value=value):
                self.assertIn('error', json.loads(cm.compliance_map(value)))

    def test_unmapped_and_empty_are_not_certified(self):
        for value in ('[]', '[{"type":"unknown"}]'):
            self.assertNotEqual(json.loads(cm.compliance_map(value))['compliance_status'], 'compliant')

    def test_unknown_framework_rejected(self):
        self.assertIn('error', json.loads(cm.compliance_map('[]', 'typo')))

    def test_mapping_is_advisory(self):
        result = json.loads(cm.compliance_map('[{"type":"sqli"}]', 'soc2'))
        self.assertEqual(result['findings'][0]['compliance']['soc2']['controls'], ['CC7.1', 'CC7.2'])
        self.assertNotEqual(result['compliance_status'], 'non_compliant')


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.log = patch.object(ct, 'LOG', [])
        self.counter = patch.object(ct, 'COUNTER', [0])
        self.log.start()
        self.counter.start()
        self.addCleanup(self.log.stop)
        self.addCleanup(self.counter.stop)

    def call(self, action, **kwargs):
        return json.loads(ct.cleanup_tracking(action, **kwargs))

    def test_update_filters_and_counts_pending(self):
        first = self.call('add', tool='test', target='one')
        self.call('add', tool='test', target='two')
        result = self.call('update', tool='test', target='one', cleanup_status='pending')
        self.assertEqual(result['ids'], [first['id']])

    def test_generated_id_can_be_completed_and_alias_cleared(self):
        entry = self.call('add', tool='test', target='one')
        self.assertEqual(self.call('update', tool=entry['id'], cleanup_status='done')['updated'], 1)
        self.assertEqual(self.call('clear')['cleared'], 1)

    def test_invalid_status_does_not_mutate(self):
        self.call('add', tool='test')
        self.assertIn('error', self.call('update', tool='test', cleanup_status='typo'))
        self.assertEqual(ct.LOG[0]['status'], 'pending')

    def test_generated_path_is_one_literal_argument(self):
        artifact = '-test; echo injected'
        self.call('add', action_type='upload', artifact=artifact, description='line\necho injected')
        result = self.call('generate')
        self.assertEqual(shlex.split(result['commands'][0]['command']), ['rm', '-f', '--', artifact])
        self.assertNotIn('\necho injected', result['script'])

    def test_comment_newline_cannot_become_command(self):
        self.call('add', target='one\necho injected')
        self.assertNotIn('\necho injected', self.call('generate')['script'])


class WordlistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'lists'
        self.root.mkdir()
        self.directory = patch.object(wl, 'WORDLIST_DIR', str(self.root))
        self.directory.start()
        self.addCleanup(self.directory.stop)

    def call(self, action, **kwargs):
        return json.loads(wl.custom_wordlist(action, **kwargs))

    def test_traversal_rejected(self):
        for action in ('create', 'show', 'delete', 'append', 'merge', 'import'):
            with self.subTest(action=action):
                self.assertIn('error', self.call(action, name='../outside', words='alpha'))
        self.assertFalse((self.root.parent / 'outside.txt').exists())

    def test_symlink_cannot_read_or_overwrite_outside(self):
        outside = self.root.parent / 'outside.txt'
        outside.write_text('synthetic-private-marker')
        (self.root / 'link.txt').symlink_to(outside)
        for action in ('show', 'create', 'append', 'delete'):
            self.assertIn('error', self.call(action, name='link', words='alpha'))
        self.assertEqual(outside.read_text(), 'synthetic-private-marker')
        self.assertNotIn('link', str(self.call('list')['custom_wordlists']))

    def test_missing_merge_source_does_not_overwrite(self):
        self.call('create', name='output', words='alpha')
        self.assertIn('error', self.call('merge', name='output', wordlist='missing'))
        self.assertEqual(self.call('show', name='output')['words'], ['alpha'])

    def test_import_budget_preserves_destination(self):
        self.call('create', name='output', words='alpha')
        source = self.root.parent / 'large.txt'
        with source.open('wb') as stream:
            stream.truncate(2 * 1024 * 1024)
        self.assertIn('error', self.call('import', name='output', source=str(source)))
        self.assertEqual(self.call('show', name='output')['words'], ['alpha'])

    def test_normal_roundtrip(self):
        self.call('create', name='one', words='alpha,beta')
        self.call('append', name='one', words='beta,gamma')
        self.call('merge', name='two', wordlist='one')
        self.assertEqual(self.call('show', name='two')['words'], ['alpha', 'beta', 'gamma'])
        self.assertEqual(self.call('delete', name='two')['status'], 'deleted')

    def test_invalid_utf8_import_preserves_destination(self):
        self.call('create', name='output', words='alpha')
        source = self.root.parent / 'binary.txt'
        source.write_bytes(b'\xff\xfe')
        self.assertIn('error', self.call('import', name='output', source=str(source)))
        self.assertEqual(self.call('show', name='output')['words'], ['alpha'])

    def test_valid_import_and_builtin_inventory(self):
        source = self.root.parent / 'source.txt'
        source.write_text('alpha\n\nbeta\n')
        self.assertEqual(self.call('import', name='copy', source=str(source))['word_count'], 2)
        self.assertEqual(self.call('show', name='copy')['words'], ['alpha', 'beta'])
        self.assertIn('common-dirs', self.call('builtin')['builtin_wordlists'])

    def test_merge_source_traversal_cannot_disclose(self):
        (self.root.parent / 'outside.txt').write_text('synthetic-private-marker')
        result = self.call('merge', name='output', wordlist='../outside')
        self.assertIn('error', result)
        self.assertFalse((self.root / 'output.txt').exists())


class CookieTests(unittest.TestCase):
    def test_analysis_redacts_plain_base64_and_json_secrets(self):
        secret = 'synthetic-session-secret-987654'
        values = [secret, base64.b64encode(secret.encode()).decode(),
                  json.dumps({secret: secret, 'token': secret})]
        for value in values:
            with self.subTest(value=value), patch.object(ce.httpx, 'AsyncClient', side_effect=AssertionError('network forbidden')):
                result = asyncio.run(ce.cookie_editor('https://example.invalid', 'session=' + value))
            serialized = json.dumps(result)
            self.assertNotIn(secret, serialized)
            self.assertNotIn(base64.b64encode(secret.encode()).decode(), serialized)
            self.assertEqual(result['original_value'], '[REDACTED]')
            self.assertEqual(result['value_length'], len(value))
        self.assertEqual(result['decoded']['json']['type'], 'object')
        self.assertEqual(result['decoded']['json']['member_count'], 2)

    def test_oversize_cookie_rejected_before_decode_or_network(self):
        with patch.object(ce.httpx, 'AsyncClient', side_effect=AssertionError('network forbidden')), \
             patch.object(ce.base64, 'b64decode', side_effect=AssertionError('decode forbidden')), \
             patch.object(ce.json, 'loads', side_effect=AssertionError('parse forbidden')):
            result = asyncio.run(ce.cookie_editor('https://example.invalid', 'session=' + 'x' * 65536))
        self.assertIn('error', result)
        self.assertLess(len(json.dumps(result)), 500)

    def test_fetched_analysis_redacts_and_bounds_values(self):
        secret = 'synthetic-fetched-secret-987654'
        response = ce.httpx.Response(200, request=ce.httpx.Request('GET', 'https://example.invalid'), headers=[
            ('set-cookie', 'session=' + base64.b64encode(secret.encode()).decode()),
            ('set-cookie', 'large=' + 'x' * 65537)])
        client = AsyncMock()
        client.get.return_value = response
        client.__aenter__.return_value = client
        with patch.object(ce.httpx, 'AsyncClient', return_value=client):
            result = asyncio.run(ce.cookie_editor('https://example.invalid'))
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn(base64.b64encode(secret.encode()).decode(), json.dumps(result))
        self.assertEqual(result['cookies_found'][0]['original_value'], '[REDACTED]')
        self.assertIn('error', result['cookies_found'][1])

    def test_analyze_never_constructs_network_client(self):
        with patch.object(ce.httpx, 'AsyncClient', side_effect=AssertionError('network forbidden')):
            result = asyncio.run(ce.cookie_editor('https://example.invalid', 'role=user'))
        self.assertEqual(result['cookie_name'], 'role')
        self.assertEqual(result['results'], [])

    def test_invalid_action_and_cookie_rejected_before_network(self):
        for cookie, action in [('role=user', 'typo'), ('=value', 'analyze'), ('a=b; c=d', 'analyze')]:
            with patch.object(ce.httpx, 'AsyncClient', side_effect=AssertionError('network forbidden')):
                self.assertIn('error', asyncio.run(ce.cookie_editor('https://example.invalid', cookie, action)))

    def test_invalid_base64_not_reported_as_decoded(self):
        result = asyncio.run(ce.cookie_editor('https://example.invalid', 'sample=%%%'))
        self.assertNotIn('base64', result['decoded'])


if __name__ == '__main__':
    unittest.main()
