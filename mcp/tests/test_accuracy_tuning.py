"""Controlled response regressions from the production smoke review; no network."""
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class HeaderAccuracy(unittest.IsolatedAsyncioTestCase):
    async def scan(self, module, headers, status=200):
        mod = importlib.import_module('cyber_tools.' + module)
        client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: httpx.Response(status, headers=headers)))
        with patch.object(mod.httpx, 'AsyncClient', return_value=client):
            return await getattr(mod, module)('https://fixture.test/')

    async def test_csp_host_sources_are_not_scheme_wildcards(self):
        r = await self.scan('csp_analyze', {'Content-Security-Policy':
            "default-src 'self'; script-src 'self' https://cdn.example; img-src https://*.example"})
        self.assertFalse(r['findings'][0]['issues'])

    async def test_csp_scheme_and_wildcard_sources_identify_directive(self):
        r = await self.scan('csp_analyze', {'Content-Security-Policy':
            "default-src 'self'; script-src https:; img-src * data:"})
        issues = r['findings'][0]['issues']
        self.assertTrue(any(i['directive'] == 'script-src' and 'scheme' in i['issue'].lower() for i in issues))
        self.assertTrue(any(i['directive'] == 'img-src' and 'wildcard' in i['issue'].lower() for i in issues))

    async def test_nonce_suppresses_inline_script_warning_but_not_style(self):
        r = await self.scan('csp_analyze', {'Content-Security-Policy':
            "script-src 'self' 'nonce-YWJjZA==' 'unsafe-inline'; style-src 'unsafe-inline'"})
        issues = r['findings'][0]['issues']
        self.assertFalse(any(i['directive'] == 'script-src' for i in issues))
        self.assertTrue(any(i['directive'] == 'style-src' for i in issues))

    async def test_csp_first_duplicate_directive_wins(self):
        r = await self.scan('csp_analyze', {'Content-Security-Policy':
            "script-src 'none'; script-src *"})
        self.assertEqual(r['findings'][0]['directives']['script-src'], "'none'")
        self.assertFalse(r['findings'][0]['issues'])

    async def test_csp_multiple_policies_are_not_reported_as_confirmed_weakness(self):
        r = await self.scan('csp_analyze', [('Content-Security-Policy', "script-src *"),
                                         ('Content-Security-Policy', "script-src 'none'")])
        self.assertFalse(r['coverage_complete'])
        self.assertEqual(r['assessment'], 'inconclusive')

    async def test_csp_blocked_response_is_incomplete(self):
        r = await self.scan('csp_analyze', {}, status=403)
        self.assertFalse(r['coverage_complete'])
        self.assertFalse(r['findings'])

    async def test_cookie_expires_comma_and_no_secret_output(self):
        r = await self.scan('cookie_audit', [('Set-Cookie',
            'sid=synthetic-secret; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Path=/; Secure; HttpOnly; SameSite=Lax')])
        self.assertEqual(r['cookie_count'], 1)
        self.assertEqual(r['total_issues'], 0)
        self.assertNotIn('synthetic-secret', str(r))
        self.assertIn('2027', r['cookies'][0]['flags']['expires'])

    async def test_cookie_deletion_is_not_infinite_session(self):
        r = await self.scan('cookie_audit', {'Set-Cookie': 'sid=; Max-Age=0; Path=/'})
        self.assertTrue(r['cookies'][0]['deleted'])
        self.assertEqual(r['total_issues'], 0)

    async def test_cookie_attribute_names_not_values_determine_flags(self):
        r = await self.scan('cookie_audit', {'Set-Cookie': 'sid=secure-httponly; Path=/; SameSite=None'})
        self.assertFalse(r['cookies'][0]['flags']['secure'])
        self.assertFalse(r['cookies'][0]['flags']['httponly'])
        self.assertGreater(r['total_issues'], 0)

    async def test_cookie_blocked_response_is_incomplete(self):
        r = await self.scan('cookie_audit', {}, status=429)
        self.assertFalse(r['coverage_complete'])


class ProbeAndReportAccuracy(unittest.TestCase):
    def test_inventory_distinguishes_static_references_from_execution(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from scripts.tool_coverage_inventory import build_inventory
        r = build_inventory(Path(__file__).resolve().parents[2])
        self.assertEqual(len(r['tools']), 209)
        self.assertEqual(len({t['name'] for t in r['tools']}), 209)
        probe = next(t for t in r['tools'] if t['name'] == 'http_probe_target')
        self.assertIn('mcp/cyber_tools/http_probe.py', probe['implementation_files'])
        self.assertTrue(probe['static_test_references'])
        self.assertEqual(probe['accuracy'], 'not_measured_by_inventory')
        self.assertTrue(all(t['implementation_files'] for t in r['tools']))

    def probe(self, headers):
        m = importlib.import_module('cyber_tools.http_probe')
        resp = Mock(status=200, headers=headers)
        resp.getheader.side_effect = lambda key, default='': headers.get(key, default)
        conn = Mock()
        conn.getresponse.return_value = resp
        with patch.object(m.http.client, 'HTTPSConnection', return_value=conn):
            return m._probe('fixture.test', 443, True)

    def test_tracking_policy_does_not_imply_ruby(self):
        r = self.probe({'Server':'cloudflare', 'Permissions-Policy':'xr-spatial-tracking=()', 'x-nextjs-cache':'HIT'})
        self.assertNotIn('Ruby', r['technologies'])
        self.assertIn('Cloudflare', r['technologies'])
        self.assertIn('Next.js', r['technologies'])

    def test_actual_ruby_banner_is_preserved(self):
        r = self.probe({'Server':'nginx', 'X-Powered-By':'Phusion Passenger (Ruby/Rack)'})
        self.assertIn('Ruby', r['technologies'])

    def test_report_preserves_unknown_scope_and_observation(self):
        from cyber_tools.report import gen_report
        r = gen_report('fixture.test', {'summary':'Anonymous homepage only', 'findings':[
            {'name':'CSP observation', 'description':'Inline permitted', 'assessment':'observed', 'severity':'low'}]})
        self.assertIn('Open Ports Found:** Not assessed', r)
        self.assertNotIn('Vulnerabilities Found:** 1', r)
        self.assertIn('Observations / Findings:** 1', r)
        self.assertIn('Anonymous homepage only', r)


if __name__ == '__main__':
    unittest.main()
