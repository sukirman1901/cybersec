"""Offline public-entry regressions, with all persistence redirected to temp storage."""
import importlib
import builtins
import os
import json
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

hl, vd, br, asm = [importlib.import_module('cyber_tools.' + n) for n in
                  ('http_logger', 'vuln_database', 'branded_report', 'attack_surface')]
SECRET = 'synthetic-secret-123'
URL = 'https://user:' + SECRET + '@example.invalid/a?token=' + SECRET + '#' + SECRET


class StoreReportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.log = self.root / 'logs.jsonl'
        self.db = self.root / 'db.json'
        for module, key, value in [(hl, 'LOG_DIR', str(self.root)), (hl, 'LOG_FILE', str(self.log)),
                                    (vd, 'DB_FILE', str(self.db))]:
            p = patch.object(module, key, value)
            p.start()
            self.addCleanup(p.stop)

    def test_logger_empty_and_malformed_structured_input(self):
        for data in ('', 'null', '[]', '{'):
            with self.subTest(data=data):
                self.assertIn('error', json.loads(hl.http_logger('log', data)))
        self.assertFalse(self.log.exists())

    def test_logger_redacts_before_persisting_and_exporting(self):
        request = {'url':URL, 'method':'GET', 'headers':{'Authorization':'Bearer ' + SECRET}, 'body':SECRET}
        self.assertEqual(json.loads(hl.http_logger('log', json.dumps(request), request_id='one'))['status'], 'logged')
        self.assertTrue(self.log.exists())
        self.assertNotIn(SECRET, self.log.read_text())
        for action in ('list', 'search', 'export', 'stats'):
            self.assertNotIn(SECRET, hl.http_logger(action))
        self.assertEqual(json.loads(hl.http_logger('list', request_id='one'))['total'], 1)
        self.assertEqual(json.loads(hl.http_logger('stats'))['total_entries'], 1)
        self.assertEqual(json.loads(hl.http_logger('clear'))['status'], 'cleared')

    def test_logger_raw_http_is_stored_as_redacted_metadata(self):
        result = json.loads(hl.http_logger('log', 'GET / HTTP/1.1\r\nAuthorization: ' + SECRET))
        self.assertEqual(result['status'], 'logged')
        self.assertNotIn(SECRET, self.log.read_text())
        self.assertIn('redacted', self.log.read_text().lower())

    def test_logger_corrupt_store_not_silently_clean(self):
        for content in ('{broken\n', 'null\n', '{"request":[]}\n'):
            self.log.write_text(content)
            for action in ('list', 'search', 'stats', 'export', 'log'):
                with self.subTest(content=content, action=action):
                    self.assertIn('error', json.loads(hl.http_logger(action, '{"method":"GET"}')))
            self.assertEqual(self.log.read_text(), content)

    def test_legacy_store_secrets_are_redacted_on_read(self):
        self.log.write_text(json.dumps({'id':'legacy','request':{'url':URL,'headers':{'Cookie':SECRET}}}) + '\n')
        self.db.write_text(json.dumps({'entries':[{'id':'VD-0001','token':SECRET,'url':URL}], 'next_id':2}))
        self.assertNotIn(SECRET, hl.http_logger('export'))
        self.assertNotIn(SECRET, vd.vuln_database('export'))

    def test_database_rejects_bad_entries_without_writing(self):
        for data in ('null', '[]', '{}', '{"tags":"wrong"}', '{"severity":[]}'):
            with self.subTest(data=data):
                self.assertIn('error', json.loads(vd.vuln_database('add', data)))
        self.assertFalse(self.db.exists())

    def test_database_corrupt_store_never_overwritten(self):
        for content in ('{broken', 'null', '{"entries":[null]}', '{"entries":[]} garbage'):
            self.db.write_text(content)
            for action in ('stats', 'export', 'add'):
                with self.subTest(content=content, action=action):
                    self.assertIn('error', json.loads(vd.vuln_database(action, '{"title":"fixture"}')))
            self.assertEqual(self.db.read_text(), content)

    def test_database_import_roundtrip_update_and_tags(self):
        result = json.loads(vd.vuln_database('import', '[{"title":"fixture","tags":["lab"],"severity":"low"}]'))
        self.assertEqual(result['added'], 1)
        self.assertTrue(self.db.exists())
        self.assertEqual(json.loads(vd.vuln_database('get', vuln_id='VD-0001'))['title'], 'fixture')
        self.assertEqual(json.loads(vd.vuln_database('search', search_query='fixture'))['total'], 1)
        self.assertEqual(json.loads(vd.vuln_database('tags'))['tags'], {'lab':1})
        self.assertEqual(json.loads(vd.vuln_database('update', '{"status":"candidate"}', 'VD-0001'))['status'], 'updated')
        self.assertEqual(json.loads(vd.vuln_database('list'))['total'], 1)
        self.assertEqual(json.loads(vd.vuln_database('delete', vuln_id='VD-0001'))['removed'], 1)
        self.assertEqual(json.loads(vd.vuln_database('clear'))['status'], 'cleared')

    def test_database_import_atomic_and_identity_immutable(self):
        vd.vuln_database('add', '{"title":"fixture"}')
        before = self.db.read_bytes()
        self.assertIn('error', json.loads(vd.vuln_database('import', '[{"title":"valid"},null]')))
        self.assertEqual(self.db.read_bytes(), before)
        self.assertIn('error', json.loads(vd.vuln_database('update', '{"id":"replacement"}', 'VD-0001')))
        self.assertEqual(self.db.read_bytes(), before)

    def test_persistence_failures_are_errors_not_success(self):
        with patch.object(hl, 'LOG_FILE', str(self.root)):
            self.assertIn('error', json.loads(hl.http_logger('log', '{"method":"GET"}')))
        with patch.object(vd, 'DB_FILE', str(self.root)):
            self.assertIn('error', json.loads(vd.vuln_database('add', '{"title":"fixture"}')))

    def test_oversize_inputs_and_stores_are_bounded(self):
        large = 'x' * (1024 * 1024 + 1)
        calls = [lambda: hl.http_logger('log', large), lambda: vd.vuln_database('add', large),
                 lambda: br.branded_report('fixture', large), lambda: asm.attack_surface_map(large)]
        for call in calls:
            with patch.object(json, 'loads', side_effect=AssertionError('parse forbidden')):
                result = call()
            self.assertIn('error', json.loads(result))
        for path, call in [(self.log, lambda:hl.http_logger('export')), (self.db, lambda:vd.vuln_database('export'))]:
            with path.open('wb') as stream:
                stream.truncate(4 * 1024 * 1024 + 1)
            self.assertIn('error', json.loads(call()))

    def test_branded_invalid_input_and_no_fake_assessment(self):
        for data in ('{', 'null', '[null]', '[{"severity":null}]'):
            self.assertIn('error', json.loads(br.branded_report('fixture', data)))
        self.assertNotIn('A security assessment was performed', br.branded_report('fixture', '[]'))

    def test_branded_escapes_redacts_and_preserves_candidate(self):
        data = json.dumps([{'title':'<script>bad()</script>','target':URL,'severity':'high','status':'candidate','token':SECRET}])
        for fmt in ('html', 'markdown', 'json'):
            result = br.branded_report(URL, data, format=fmt)
            self.assertNotIn(SECRET, result)
            self.assertIn('candidate', result)
            if fmt == 'html':
                self.assertNotIn('<script>', result)

    def test_branded_logo_rejects_arbitrary_file_and_oversize(self):
        logo = self.root / 'logo.png'
        logo.write_text(SECRET)
        self.assertIn('error', json.loads(br.branded_report('fixture', '[]', company_logo=str(logo))))
        with logo.open('wb') as stream:
            stream.truncate(2 * 1024 * 1024)
        self.assertIn('error', json.loads(br.branded_report('fixture', '[]', company_logo=str(logo))))

    def test_surface_invalid_and_empty_unknown(self):
        for data in ('null', '[null]', '{"open_ports":[1]}', '{"vulnerabilities":{}}'):
            self.assertIn('error', json.loads(asm.attack_surface_map(data)))
        for data in ('[]', '{}'):
            self.assertEqual(json.loads(asm.attack_surface_map(data))['exposure_level'], 'unknown')

    def test_surface_registers_vulnerability_host_and_redacts(self):
        data = json.dumps({'target':URL,'vulnerabilities':[{'severity':'high','status':'candidate','token':SECRET}]})
        result = json.loads(asm.attack_surface_map(data))
        self.assertEqual(result['stats']['total_hosts'], 1)
        self.assertEqual(result['vulnerabilities'][0]['status'], 'candidate')
        self.assertNotIn(SECRET, json.dumps(result))

    def test_database_persists_redacted_data_and_replace_failure_preserves_old(self):
        result = json.loads(vd.vuln_database('add', json.dumps({'title':'fixture','url':URL,'token':SECRET})))
        self.assertEqual(result['status'], 'added')
        self.assertNotIn(SECRET, self.db.read_text())
        before = self.db.read_bytes()
        with patch.object(vd.os, 'replace', side_effect=OSError('synthetic disk failure')):
            self.assertIn('error', json.loads(vd.vuln_database('update', '{"title":"changed"}', result['id'])))
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['db.json'])

    def test_collection_and_store_record_limits(self):
        many = json.dumps([{'severity':'low'}] * 1001)
        self.assertIn('error', json.loads(br.branded_report('fixture', many)))
        self.assertIn('error', json.loads(asm.attack_surface_map(many)))
        self.assertIn('error', json.loads(vd.vuln_database('import', many)))
        self.log.write_text('\n'.join(json.dumps({'id':str(i),'request':{}}) for i in range(1001)))
        self.assertIn('error', json.loads(hl.http_logger('export')))
        self.db.write_text(json.dumps({'entries':[{'id':str(i)} for i in range(1001)]}))
        self.assertIn('error', json.loads(vd.vuln_database('export')))

    def test_surface_all_supported_observation_families(self):
        data = [{'target':'example.invalid','open_ports':[{'port':443,'service':'https'}],
                 'records':{'A':['192.0.2.1']}, 'technologies':['fixture-web'], 'ssl':{'issuer':'fixture'}},
                {'subdomains':['sub.example.invalid']},
                {'target':'example.invalid','vulnerabilities':[{'severity':'medium','status':'confirmed'}]}]
        result = json.loads(asm.attack_surface_map(json.dumps(data)))
        self.assertEqual(result['stats']['total_hosts'], 2)
        self.assertEqual(result['stats']['total_ports'], 1)
        self.assertEqual(result['hosts']['example.invalid']['ip'], '192.0.2.1')
        self.assertEqual(result['technologies'], ['fixture-web'])
        self.assertEqual(result['vulnerabilities'][0]['status'], 'confirmed')

    def test_logger_response_status_and_search(self):
        hl.http_logger('log', '{"method":"POST","url":"https://example.invalid/path"}', '{"status_code":403}', 'fixture')
        stats = json.loads(hl.http_logger('stats'))
        self.assertEqual(stats['by_status'], {'403':1})
        self.assertEqual(stats['by_method'], {'POST':1})
        self.assertEqual(json.loads(hl.http_logger('search', 'example.invalid'))['total'], 1)

    def _swap_on_open(self, path, replacement, call, append=False, symlink=True):
        """Replace the checked leaf immediately before its actual open."""
        real_open, real_os_open = builtins.open, os.open
        swapped = False

        def swap():
            nonlocal swapped
            if not swapped:
                swapped = True
                path.unlink()
                if symlink:
                    path.symlink_to(replacement)
                else:
                    replacement.rename(path)

        def file_open(file, mode='r', *args, **kwargs):
            if str(file) == str(path) and (('a' in mode) == append):
                swap()
            return real_open(file, mode, *args, **kwargs)

        def fd_open(file, flags, *args, **kwargs):
            if str(file) == str(path) and (bool(flags & os.O_APPEND) == append):
                swap()
            return real_os_open(file, flags, *args, **kwargs)

        with patch('builtins.open', side_effect=file_open), patch.object(os, 'open', side_effect=fd_open):
            result = call()
        self.assertTrue(swapped)
        self.assertIn('error', json.loads(result))

    def test_logger_read_rejects_symlink_and_identity_swap(self):
        for symlink in (True, False):
            if self.log.exists() or self.log.is_symlink():
                self.log.unlink()
            self.log.write_text('{"id":"original","request":{}}\n')
            other = self.root / 'replacement'
            other.write_text('{"id":"replacement","request":{}}\n')
            self._swap_on_open(self.log, other, lambda:hl.http_logger('export'), symlink=symlink)

    def test_logger_append_rejects_symlink_swap_without_writing_target(self):
        self.log.write_text('{"id":"original","request":{}}\n')
        other = self.root / 'replacement'
        other.write_text('synthetic-protected-content')
        self._swap_on_open(self.log, other, lambda:hl.http_logger('log', '{"method":"GET"}'), append=True)
        self.assertEqual(other.read_text(), 'synthetic-protected-content')

    def test_database_read_rejects_symlink_and_identity_swap(self):
        for symlink in (True, False):
            if self.db.exists() or self.db.is_symlink():
                self.db.unlink()
            self.db.write_text('{"entries":[]}')
            other = self.root / 'replacement'
            other.write_text('{"entries":[{"id":"VD-0001","title":"replacement"}]}')
            self._swap_on_open(self.db, other, lambda:vd.vuln_database('export'), symlink=symlink)

    def test_logo_read_rejects_symlink_and_identity_swap(self):
        logo = self.root / 'logo.png'
        for symlink in (True, False):
            if logo.exists() or logo.is_symlink():
                logo.unlink()
            png = b'\x89PNG\r\n\x1a\nfixtureIEND\xaeB`\x82'
            logo.write_bytes(png)
            other = self.root / 'replacement'
            other.write_bytes(png)
            self._swap_on_open(logo, other, lambda:br.branded_report('fixture', '[]', company_logo=str(logo)), symlink=symlink)


if __name__ == '__main__':
    unittest.main()
