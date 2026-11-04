"""Synthetic, offline tests of report utility public entry points."""
import importlib
import csv
import io
import json
import unittest
from unittest.mock import patch

hi, em, es, rexp, rs = [importlib.import_module('cyber_tools.' + n) for n in
    ('http_ingest', 'evidence_manifest', 'executive_summary', 'report_export', 'risk_score')]


class ReportUtilityTests(unittest.TestCase):
    def setUp(self):
        for module, name, value in [(hi, 'INGESTED', []), (em, 'MANIFESTS', {}),
                                    (em, 'EVIDENCE_STORE', []), (em, 'CHAIN', []), (em, 'COUNTER', [0])]:
            p = patch.object(module, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_ingest_invalid_url_does_not_mutate(self):
        for data in ('', 'not a url', 'https://example.invalid:bad'):
            with self.subTest(data=data):
                result = json.loads(hi.http_ingest('ingest', data))
                self.assertIn('error', result)
        self.assertEqual(hi.INGESTED, [])

    def test_ingest_credentials_redacted_in_output_and_store(self):
        secret = 'synthetic-secret-abc'
        result = hi.http_ingest('ingest', f'https://user:{secret}@example.invalid/a?token={secret}')
        self.assertNotIn(secret, result)
        self.assertNotIn(secret, json.dumps(hi.INGESTED))

    def test_batch_auto_recognizes_har_not_fake_url(self):
        data = json.dumps({'log': {'entries': [{'request': {'method': 'GET', 'url': 'https://example.invalid/a'}}]}})
        result = json.loads(hi.http_ingest('batch', data, 'auto'))
        self.assertIn('har', result['results'][0])

    def test_dedup_keeps_distinct_hosts_and_accepts_list(self):
        hi.http_ingest('ingest', 'https://a.invalid/x https://b.invalid/x')
        result = json.loads(hi.http_ingest('deduplicate', '[{"url":"https://c.invalid/x","path":"/x"}]'))
        self.assertEqual(result['total'], 3)
        self.assertEqual(result['deduplicated'], 0)

    def test_invalid_har_rolls_back_partial_ingest(self):
        data = json.dumps({'log': {'entries': [{'request': {'url': 'https://a.invalid'}}, None]}})
        self.assertIn('error', json.loads(hi.http_ingest('ingest', data, 'har')))
        self.assertEqual(hi.INGESTED, [])

    def test_manifest_invalid_add_is_not_recorded(self):
        for data in ('{', 'null', '[]', '{}'):
            with self.subTest(data=data):
                self.assertIn('error', json.loads(em.evidence_manifest('add', data)))
        self.assertEqual(em.CHAIN, [])

    def test_empty_and_unknown_manifest_not_verified(self):
        self.assertFalse(json.loads(em.evidence_manifest('verify'))['valid'])
        em.evidence_manifest('add', '{"type":"http","source":"synthetic"}')
        self.assertIn('error', json.loads(em.evidence_manifest('verify', manifest_id='missing')))

    def test_manifest_verifies_stored_content_and_expected_hash(self):
        added = json.loads(em.evidence_manifest('add', '{"type":"http","source":"synthetic","body":"one"}'))
        self.assertTrue(json.loads(em.evidence_manifest('verify', verify_hash=added['chain_hash']))['valid'])
        self.assertFalse(json.loads(em.evidence_manifest('verify', verify_hash='0'*64))['valid'])
        em.EVIDENCE_STORE[0]['body'] = 'tampered'
        self.assertFalse(json.loads(em.evidence_manifest('verify'))['valid'])

    def test_manifest_snapshot_filter_summary_and_diff(self):
        first = json.loads(em.evidence_manifest('add', '{"type":"http","source":"synthetic"}'))['manifest_id']
        second = json.loads(em.evidence_manifest('add', '{"type":"file","source":"fixture"}'))['manifest_id']
        exported = json.loads(em.evidence_manifest('export', manifest_id=first))
        self.assertEqual(exported['total_evidence'], 1)
        self.assertEqual(json.loads(em.evidence_manifest('export', filter_type='http'))['total_evidence'], 1)
        self.assertEqual(json.loads(em.evidence_manifest('summary'))['by_type'], {'http': 1, 'file': 1})
        diff = json.loads(em.evidence_manifest('diff', manifest_id=first, filter_type=second))
        self.assertEqual(diff['added'], ['EV-0002'])

    def test_summary_malformed_and_empty_not_safe(self):
        for data in ('{', 'null', '[null]', '[{"severity":null}]'):
            with self.subTest(data=data):
                self.assertIn('error', json.loads(es.executive_summary('fixture', data)))
        result = json.loads(es.executive_summary('fixture', '[]'))
        self.assertIn('not assessed', result['risk_posture']['rating'].lower())

    def test_summary_preserves_candidate_and_confirmed(self):
        result = json.loads(es.executive_summary('fixture', json.dumps([
            {'title':'candidate','severity':'high','status':'candidate'},
            {'title':'verified','severity':'low','status':'confirmed'}])))
        self.assertEqual(result['status_breakdown']['candidate'], 1)
        self.assertEqual(result['top_5_findings'][0]['status'], 'candidate')
        self.assertEqual(result['top_5_findings'][1]['status'], 'confirmed')

    def test_exports_validate_input(self):
        for fmt in ('json', 'html', 'markdown', 'csv'):
            for data in ('null', '[null]', '{"vulnerabilities":{}}'):
                with self.subTest(fmt=fmt, data=data):
                    self.assertIn('error', json.loads(rexp.report_export('fixture', data, fmt)))

    def test_export_html_escapes_and_preserves_status(self):
        result = rexp.report_export('<script>bad()</script>', json.dumps({'vulnerabilities':[
            {'severity':'high','status':'candidate','description':'<img src=x onerror=bad()>','type':'xss'}]}))
        self.assertNotIn('<script>', result)
        self.assertNotIn('<img ', result)
        self.assertIn('candidate', result)

    def test_empty_markdown_not_clean_bill(self):
        result = rexp.report_export('fixture', '{}', 'markdown')
        self.assertNotIn('No vulnerabilities found.', result)

    def test_risk_invalid_input_and_boolean_types(self):
        for data in ('null', '[]', '{}', '{"severity":"typo"}', '{"severity":"high","has_public_exploit":"false"}'):
            with self.subTest(data=data):
                self.assertIn('error', json.loads(rs.risk_score(data)))

    def test_risk_public_exploit_counted_once_no_exploit_claim(self):
        result = json.loads(rs.risk_score('{"type":"rce","severity":"critical","status":"candidate","has_public_exploit":true}', 'high'))
        self.assertEqual(result['scores']['likelihood'], 3)
        self.assertNotIn('is exploitable', result['recommendation'])
        self.assertEqual(result['finding']['status'], 'candidate')

    def test_report_urls_do_not_disclose_credentials(self):
        url = 'https://user:synthetic-secret-abc@example.invalid/'
        for fmt in ('html', 'markdown', 'csv', 'json'):
            self.assertNotIn('synthetic-secret-abc', rexp.report_export(url, json.dumps({'vulnerabilities':[{'host':url}]}), fmt))
        self.assertNotIn('synthetic-secret-abc', es.executive_summary(url, json.dumps([{'severity':'high','target':url}])))
        self.assertNotIn('synthetic-secret-abc', rs.risk_score(json.dumps({'severity':'high','host':url})))

    def test_csv_roundtrips_quotes_and_neutralizes_formula(self):
        result = rexp.report_export('fixture', json.dumps({'vulnerabilities':[
            {'type':'=1+1','description':'one, "two"\nthree','status':'candidate'}]}), 'csv')
        rows = list(csv.reader(io.StringIO(result)))
        self.assertEqual(rows[1][2], "'=1+1")
        self.assertEqual(rows[1][3], 'one, "two"\nthree')

    def test_ingest_empty_formats_and_batch_report_error(self):
        for fmt in ('curl', 'raw', 'har', 'burp', 'openapi', 'list'):
            self.assertIn('error', json.loads(hi.http_ingest('ingest', '', fmt)))
        self.assertIn('error', json.loads(hi.http_ingest('batch', 'unrecognized input', 'auto')))

    def test_chain_detects_link_and_content_tampering(self):
        em.evidence_manifest('add', '{"type":"http","body":"one"}')
        em.evidence_manifest('add', '{"type":"http","body":"two"}')
        em.EVIDENCE_STORE[0]['body'] = 'changed'
        self.assertNotEqual(json.loads(em.evidence_manifest('chain'))['integrity'], 'INTACT')

    def test_curl_redacts_authorization_in_original(self):
        result = hi.http_ingest('ingest', "curl https://example.invalid -H 'Authorization: Bearer synthetic-secret-abc'", 'curl')
        self.assertNotIn('synthetic-secret-abc', result)
        self.assertNotIn('synthetic-secret-abc', json.dumps(hi.INGESTED))

    def test_oversize_inputs_rejected_before_json_parse(self):
        oversized = 'x' * (1024 * 1024 + 1)
        calls = [lambda: hi.http_ingest('ingest', oversized, 'har'),
                 lambda: em.evidence_manifest('add', oversized),
                 lambda: es.executive_summary('fixture', oversized),
                 lambda: rexp.report_export('fixture', oversized),
                 lambda: rs.risk_score(oversized)]
        for call in calls:
            with patch.object(json, 'loads', side_effect=AssertionError('parse forbidden')):
                result = call()
            self.assertIn('error', json.loads(result))
        self.assertEqual(hi.INGESTED, [])
        self.assertEqual(em.CHAIN, [])

    def test_collection_limits_reject_without_partial_ingest(self):
        urls = '\n'.join('https://example.invalid/' + str(i) for i in range(1001))
        self.assertIn('error', json.loads(hi.http_ingest('ingest', urls, 'url')))
        self.assertEqual(hi.INGESTED, [])
        findings = json.dumps([{'severity': 'low'}] * 1001)
        self.assertIn('error', json.loads(es.executive_summary('fixture', findings)))
        self.assertIn('error', json.loads(rexp.report_export('fixture', findings)))

    def test_report_url_query_and_fragment_redacted(self):
        url = 'https://user:synthetic-pass@example.invalid/path?token=synthetic-query#synthetic-fragment'
        outputs = [rexp.report_export(url, json.dumps({'vulnerabilities':[{'host':url}]}), fmt)
                   for fmt in ('html', 'markdown', 'csv', 'json')]
        outputs += [es.executive_summary(url, json.dumps([{'severity':'high','target':url}])),
                    rs.risk_score(json.dumps({'severity':'high','host':url}))]
        for output in outputs:
            for secret in ('synthetic-pass', 'synthetic-query', 'synthetic-fragment'):
                self.assertNotIn(secret, output)

    def test_ingest_list_rejects_invalid_port(self):
        for fmt in ('url', 'list'):
            self.assertIn('error', json.loads(hi.http_ingest('ingest', 'https://example.invalid:99999/a', fmt)))
        self.assertEqual(hi.INGESTED, [])


if __name__ == '__main__':
    unittest.main()
