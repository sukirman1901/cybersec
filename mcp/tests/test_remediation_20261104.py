"""Audit regressions: real adapters and HTTPX transport, no external targets."""
import asyncio
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def mod(name):
    return importlib.import_module('cyber_tools.' + name)


class AuditRegression(unittest.IsolatedAsyncioTestCase):
    async def test_xss_transport_failure_is_incomplete(self):
        x = mod('xss_detect')
        def fail(req):
            raise httpx.ConnectError('offline', request=req)
        client = httpx.AsyncClient(transport=httpx.MockTransport(fail))
        with patch.object(x.httpx, 'AsyncClient', return_value=client):
            result = await x.xss_detect('https://fixture.test/?q=x', param='q')
        self.assertFalse(result['coverage_complete'])
        self.assertGreater(result['requests_failed'], 0)
        self.assertIn('error', result)

    async def test_cli_json_output_channels(self):
        c = mod('cli_tools')
        with patch.object(c, '_check', return_value=True), patch.object(c, '_run_cli', new=AsyncMock(
                return_value={'exit_code':0, 'stdout':'[{"RuleID":"demo"}]', 'stderr':''})) as run:
            r = await c.gitleaks_check('/synthetic')
            self.assertIn('--report-path', run.call_args.args[0])
            self.assertIn('--redact', run.call_args.args[0])
            self.assertEqual(r['count'], 1)
        with patch.object(c, '_check', return_value=True), patch.object(c, '_run_cli', new=AsyncMock(
                return_value={'exit_code':0,'stdout':'{"url":"https://fixture.test/a","status":200}\n', 'stderr':''})) as run:
            r = await c.ffuf_fuzz('https://fixture.test', wordlist=__file__)
            self.assertEqual(r['count'], 1)
            self.assertIn('-json', run.call_args.args[0])

    async def test_real_subprocess_timeout_keeps_partial_output(self):
        c = mod('cli_tools')
        r = await c._run_cli([sys.executable, '-c', 'import time; print("partial", flush=True); time.sleep(5)'], timeout=.15)
        self.assertNotEqual(r['exit_code'], 0)
        self.assertIn('partial', r['stdout'])

    async def test_workflow_execution_gated_and_preserves_findings(self):
        runner = mod('workflow_runner')
        gate = mod('engagement_gate')
        plan = {'steps':[{'tool':'sqli_detect', 'params':{'target':'https://fixture.test/?id=1'}}]}
        detector = AsyncMock(return_value={'findings':[{'type':'sqli', 'target':'https://fixture.test',
            'severity':'high', 'confidence':'HIGH', 'coverage':'controlled', 'evidence':'synthetic'}],
            'coverage_complete':True})
        with gate.engagement_context(gate.new_engagement()):
            with patch.dict(runner.EXECUTORS, {'sqli_detect':detector}):
                with self.assertRaises(Exception):
                    await runner.execute_plan(plan)
                detector.assert_not_awaited()
                gate.engagement_gate('init', target='fixture.test')
                gate.engagement_gate('authorize', confirmation='yes')
                r = await runner.execute_plan(plan)
                self.assertTrue(r['executed'])
                self.assertEqual(len(r['findings']), 1)
                self.assertEqual(r['steps'][0]['status'], 'completed')

    async def test_bandit_severity_and_metrics(self):
        b = mod('bandit_scan')
        proc = unittest.mock.Mock(returncode=1, stderr='', stdout=json.dumps({
            'results':[{'issue_severity':'HIGH','issue_confidence':'HIGH','issue_text':'sample'}],
            'metrics':{'_totals':{'SEVERITY.HIGH':1, 'SEVERITY.MEDIUM':0, 'SEVERITY.LOW':0}}}))
        with patch.object(b.shutil, 'which', return_value='/fake/bandit'), patch.object(b.subprocess, 'run', return_value=proc) as run:
            result = await b.bandit_scan(str(Path(__file__).parent), severity='high')
        self.assertIn('--severity-level', run.call_args.args[0])
        self.assertEqual(result['summary']['high'], 1)
        self.assertTrue(result['coverage_complete'])

    async def test_semgrep_errors_not_empty_success(self):
        s = mod('semgrep_scan')
        proc = unittest.mock.Mock(returncode=2, stderr='invalid config', stdout='{"results":[],"errors":[{"message":"invalid config"}]}')
        with patch.object(s.shutil, 'which', return_value='/fake/semgrep'), patch.object(s.subprocess, 'run', return_value=proc):
            result = await s.semgrep_scan(str(Path(__file__).parent))
        self.assertIn('error', result)
        self.assertFalse(result['coverage_complete'])

    async def test_xss_json_and_session_preserved(self):
        x = mod('xss_detect'); seen = []
        def handler(req):
            if req.method == 'POST':
                body = json.loads(req.content)
                seen.append((body, req.headers.get('authorization')))
                return httpx.Response(200, headers={'content-type':'text/html'}, text='<html>' + body['q'] + '</html>')
            return httpx.Response(200, text='constant')
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with patch.object(x.httpx, 'AsyncClient', return_value=client):
            r = await x.xss_detect('https://fixture.test/search', param='q', request_json=json.dumps({
                'method':'POST','json':{'q':'original','tenant':'demo'},'headers':{'Authorization':'Bearer synthetic'}}))
        self.assertGreater(len(seen), 1)
        self.assertTrue(all(b['tenant']=='demo' and h=='Bearer synthetic' for b,h in seen))
        self.assertNotIn('Bearer synthetic', json.dumps(r))

    async def test_sqli_authenticated_json_preserves_context_and_detects(self):
        s = mod('sqli_detect'); seen = []
        def handler(req):
            body = json.loads(req.content)
            seen.append((req.method, body, req.headers.get('authorization')))
            if "'" in str(body['id']):
                return httpx.Response(500, text='SQLite.Exception: syntax error near injected quote')
            return httpx.Response(200, text='original row with stable response')
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with patch.object(s.httpx, 'AsyncClient', return_value=client):
            r = await s.sqli_detect('https://fixture.test/api?tenant=fixed', param='id', request_json=json.dumps({
                'method':'POST', 'json':{'id':'1','tenant':'demo'}, 'headers':{'Authorization':'Bearer synthetic'}}))
        self.assertTrue(seen)
        self.assertTrue(all(m == 'POST' and b['tenant'] == 'demo' and h == 'Bearer synthetic' for m,b,h in seen))
        self.assertTrue(r['vulnerable'])
        self.assertEqual(r['findings'][0]['replay']['method'], 'POST')
        self.assertNotIn('Bearer synthetic', json.dumps(r))

    async def test_cli_failures_are_incomplete(self):
        cli = mod('cli_tools')
        with patch.object(cli, '_check', return_value=True), patch.object(cli, '_run_cli', new=AsyncMock(
            return_value={'exit_code': -1, 'stdout': '', 'stderr': 'timed out'})):
            for call in (cli.sqlmap_check, cli.nikto_scan, cli.amass_enum):
                r = await call('https://fixture.test/?id=1')
                self.assertIn('error', r)
                self.assertFalse(r['coverage_complete'])

    async def test_wpscan_keeps_nested_findings(self):
        cli = mod('cli_tools')
        data = {'version': {'vulnerabilities': [{'title': 'core'}]}, 'plugins': {
            'demo': {'vulnerabilities': [{'title': 'plugin'}]}}, 'themes': {
            'demo': {'vulnerabilities': [{'title': 'theme'}]}}}
        with patch.object(cli, '_check', return_value=True), patch.object(cli, '_run_cli', new=AsyncMock(
            return_value={'exit_code': 0, 'stdout': json.dumps(data), 'stderr': ''})):
            r = await cli.wpscan_check('https://fixture.test')
        self.assertEqual(r['count'], 3)
        self.assertEqual({f['title'] for f in r['vulnerabilities']}, {'core', 'plugin', 'theme'})

    async def test_nuclei_failure_is_not_clean(self):
        n = mod('nuclei_scan')
        proc = AsyncMock(); proc.returncode = 1
        proc.communicate.return_value = (b'', b'no templates provided for scan')
        with patch.object(n.asyncio, 'create_subprocess_exec', return_value=proc):
            r = await n.nuclei_scan('https://fixture.test')
        self.assertIn('error', r)
        self.assertFalse(r['coverage_complete'])

    async def test_total_transport_failure_preserved(self):
        s = mod('vuln_scanner')
        def fail(req):
            raise httpx.ConnectError('offline', request=req)
        with patch.object(s, 'GuardedAsyncClient', return_value=httpx.AsyncClient(transport=httpx.MockTransport(fail))):
            r = await s.vuln_scanner('https://fixture.test')
        self.assertIn('error', r)
        self.assertFalse(r['coverage_complete'])
        self.assertGreater(r['requests_failed'], 0)

    async def test_laravel_catchall_is_not_verified(self):
        s = mod('vuln_scanner')
        def landing(req):
            return httpx.Response(200, text='<html>Laravel public page</html>' + 'x' * 250)
        with patch.object(s, 'GuardedAsyncClient', return_value=httpx.AsyncClient(transport=httpx.MockTransport(landing))):
            r = await s.vuln_scanner('https://fixture.test')
        self.assertFalse([f for f in r['vulnerabilities'] if f['confidence'] == 'verified'])

    async def test_query_discovery_preserves_existing_query(self):
        p = mod('param_discovery'); seen = []
        def handler(req):
            seen.append(req.url)
            return httpx.Response(200, text='constant')
        with patch('cyber_tools.http_guard.GuardedAsyncClient', return_value=httpx.AsyncClient(transport=httpx.MockTransport(handler))):
            await p.discover_params('https://fixture.test/search?tenant=1')
        self.assertEqual(seen[1].params['tenant'], '1')
        self.assertIn('id', seen[1].params)

    async def test_subprocess_timeout_reaps_child(self):
        cli = mod('cli_tools')
        proc = AsyncMock(); proc.returncode = None
        proc.kill = unittest.mock.Mock()
        async def communicate():
            await asyncio.sleep(.02)
            return (b'partial', b'')
        proc.communicate.side_effect = communicate
        with patch.object(cli.asyncio, 'create_subprocess_exec', return_value=proc):
            r = await cli._run_cli(['fake'], timeout=.001)
        proc.kill.assert_called_once()
        self.assertEqual(proc.communicate.await_count, 1)
        self.assertIn('partial', r['stdout'])


class AuditSync(unittest.TestCase):
    def test_health_smoke_detects_missing_engine(self):
        h = mod('tool_health')
        with patch.object(h, '_which_cli', return_value='/fake/semgrep'), patch('subprocess.run', return_value=unittest.mock.Mock(
                returncode=2, stdout='', stderr='semgrep-core missing')):
            result = h.check_cli_runtime('semgrep')
        self.assertFalse(result['execution_verified'])
        self.assertEqual(result['exit_code'], 2)

    def test_oast_unconfigured_never_fabricates_domain(self):
        o = mod('oast_callback_server')
        r = json.loads(o.oast_callback_server('generate'))
        self.assertEqual(r.get('status'), 'not_configured')
        self.assertNotIn('oob_urls', r)

    def test_offline_session_format_is_not_authentication(self):
        s = mod('session_verification')
        r = json.loads(s.session_verification('verify', 'sid=abcdefghijklmnopqrstuvwxyz', target='fixture.test'))
        self.assertIsNone(r['valid'])
        self.assertFalse(r['authenticated'])
        refresh = json.loads(s.session_verification('refresh', 'sid=abc'))
        self.assertEqual(refresh['status'], 'unsupported')

    def test_health_lists_sast_capabilities(self):
        h = mod('tool_health')
        with patch.object(h, '_which_cli', return_value=None):
            r = h.check_tool_health(False)
        missing = {x['tool'] for x in r['missing']}
        self.assertTrue({'bandit', 'semgrep', 'sslyze'} <= missing)
        self.assertFalse(r['ready_for_bug_bounty'])

    def test_cookie_sent_without_false_auth_or_idor(self):
        a = mod('authenticated_scan'); seen = []
        def handler(req):
            seen.append(req.headers.get('cookie'))
            return httpx.Response(200, text='<html>Public</html>' + 'x' * 250)
        with patch.object(a, 'GuardedClient', return_value=httpx.Client(transport=httpx.MockTransport(handler))):
            r = json.loads(a.authenticated_scan('https://fixture.test', auth_type='cookie', cookies='{"sid":"synthetic"}'))
        self.assertIn('sid=synthetic', seen[0] or '')
        self.assertFalse(r['authenticated'])
        self.assertFalse([f for f in r['findings'] if f['type'] == 'idor'])

    def test_bulk_nested_error(self):
        r = json.loads(mod('bulk_scan').bulk_scan('fixture.test', tool='unknown'))
        self.assertEqual(r['successful'], 0)
        self.assertEqual(r['failed'], 1)

    def test_report_preserves_vuln_envelope(self):
        f = {'name':'Config exposure', 'type':'exposure', 'severity':'high', 'matched_at':'https://fixture.test/.env',
             'evidence':'synthetic config', 'confidence':'HIGH', 'coverage':'GET config'}
        r = json.loads(mod('report_schema_v2')._convert_v1_to_v2({'vulnerabilities':[f]}))
        self.assertEqual(r['findings'][0]['target'], f['matched_at'])
        self.assertEqual(r['findings'][0]['title'], f['name'])
        self.assertEqual(r['findings'][0]['evidence'], f['evidence'])

    def test_retest_static_script_not_exploitable(self):
        rt = mod('retest_vuln')
        with patch.object(rt.httpx, 'get', return_value=httpx.Response(200, text='<script>/* static */</script>')):
            r = json.loads(rt.retest_vuln('https://fixture.test/?q=x', 'xss', param='q'))
        self.assertNotEqual(r['status'], 'still_vulnerable')

    def test_retest_controlled_redirect(self):
        rt = mod('retest_vuln')
        def get(url, **kw):
            value = httpx.URL(url).params.get('next','')
            return httpx.Response(302, headers={'Location': value}) if 'evil.com' in value else httpx.Response(200, text='safe')
        with patch.object(rt.httpx, 'get', side_effect=get):
            r = json.loads(rt.retest_vuln('https://fixture.test/?next=home', 'open_redirect', param='next'))
        self.assertEqual(r['status'], 'still_vulnerable')

    def test_staging_deep_forwards_sqli_preset(self):
        for module, fn in [('scan_template','scan_template'), ('pentest_workflow','pentest_workflow')]:
            r = json.loads(getattr(mod(module),fn)('https://fixture.test', template='staging-deep'))
            step = next(x for x in r['steps'] if x['tool']=='sqli_detect')
            self.assertEqual(step['params'].get('preset'), 'staging-deep')

    def test_report_generator_accepts_array_and_quality(self):
        r = mod('report').gen_report('fixture.test', [{'name':'Observed', 'description':'sample', 'severity':'low',
            'confidence':'LOW','coverage':'one request','evidence':'synthetic'}])
        self.assertIn('one request', r)
        self.assertIn('synthetic', r)


if __name__ == '__main__':
    unittest.main()
