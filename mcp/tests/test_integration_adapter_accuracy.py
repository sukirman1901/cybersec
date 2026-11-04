"""Synthetic receipts and HTTP responses only; no external writes or scans."""
import asyncio
import importlib
import json
import os
import tempfile
import unittest
import urllib.error
import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

gh, jira, hook, monitor, ci = [importlib.import_module('cyber_tools.' + n) for n in
    ('github_issue', 'jira_create', 'notify_webhook', 'continuous_monitor', 'ci_cd_scan')]
SECRET = 'synthetic-private-marker'
FINDING = {'title':'fixture','severity':'high','status':'candidate'}


class Receipt:
    def __init__(self, status=201, body=b'{}'):
        self.status, self.body = status, body
        self.read_sizes = []
    def read(self, size=-1):
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]
    def close(self):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


class AdapterTests(unittest.TestCase):
    def setUp(self):
        # Both legacy and hardened urllib paths are mocked for every test.
        self.send = Mock(return_value=Receipt())
        opener = Mock()
        opener.open = self.send
        for p in (patch('urllib.request.urlopen', self.send), patch('urllib.request.build_opener', return_value=opener)):
            p.start()
            self.addCleanup(p.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.db = self.root / 'monitor.json'
        p = patch.object(monitor, 'MONITOR_DB', str(self.db))
        p.start()
        self.addCleanup(p.stop)

    def issue(self, which, data=None):
        data = json.dumps(FINDING) if data is None else data
        if which == 'github':
            return json.loads(gh.github_issue(data, 'owner/repo', SECRET))
        return json.loads(jira.jira_create(data, 'https://fixture.invalid', 'test@example.invalid', SECRET))

    def test_issue_missing_and_malformed_inputs_make_no_write(self):
        for which in ('github','jira'):
            for data in ('null','[]','{}','{"severity":null}'):
                with self.subTest(which=which, data=data):
                    self.assertIn('error', self.issue(which, data))
        self.assertFalse(self.send.called)
        self.assertIn('error', json.loads(gh.github_issue(json.dumps(FINDING))))
        self.assertIn('error', json.loads(jira.jira_create(json.dumps(FINDING))))

    def test_issue_receipts_required_for_created(self):
        for which in ('github','jira'):
            for status, body in ((201,b'{}'),(201,b'[]'),(201,b'not-json'),(429,b'{}'),(500,b'{}')):
                with self.subTest(which=which, status=status, body=body):
                    self.send.return_value = Receipt(status, body)
                    self.assertIn('error', self.issue(which))

    def test_issue_positive_mock_receipts_and_bounded_read(self):
        for which, body in [('github', {'number':7,'html_url':'https://github.com/owner/repo/issues/7'}),
                            ('jira', {'id':'100','key':'SEC-7','self':'https://fixture.invalid/rest/api/3/issue/100'})]:
            receipt = Receipt(201,json.dumps(body).encode())
            self.send.return_value = receipt
            self.assertEqual(self.issue(which)['status'], 'created')
            self.assertTrue(all(0 < n <= 65537 for n in receipt.read_sizes))
            payload = json.loads(self.send.call_args.args[0].data)
            self.assertIn('candidate', json.dumps(payload))
            if which == 'jira':
                self.assertIsInstance(payload['fields']['description'], dict)

    def test_issue_timeouts_and_http_errors_do_not_export_secrets(self):
        for which in ('github','jira'):
            for error in (TimeoutError(SECRET), urllib.error.HTTPError('https://fixture.invalid',429,SECRET,{},None)):
                self.send.side_effect = error
                result = self.issue(which)
                self.assertIn('error', result)
                self.assertNotIn(SECRET, json.dumps(result))

    def test_issue_outgoing_evidence_and_url_redacted(self):
        finding = dict(FINDING, target=f'https://u:{SECRET}@fixture.invalid/?token={SECRET}#{SECRET}', evidence=SECRET)
        for which in ('github','jira'):
            self.issue(which, json.dumps(finding))
            self.assertNotIn(SECRET, self.send.call_args.args[0].data.decode())

    def test_issue_paths_are_validated(self):
        self.assertIn('error', json.loads(gh.github_issue(json.dumps(FINDING), '../bad/repo?x', SECRET)))
        self.assertIn('error', json.loads(jira.jira_create(json.dumps(FINDING), 'http://fixture.invalid', 'x', SECRET)))
        self.assertFalse(self.send.called)

    def test_webhook_validates_severity_and_receipt(self):
        for body in ('null','[null]','[{"severity":"typo"}]'):
            self.assertIn('error', json.loads(hook.notify_webhook('https://fixture.invalid/hook', body)))
        self.assertFalse(self.send.called)
        for status, body in ((200,b'not_ok'),(429,b'rate limited'),(500,b'failed')):
            self.send.return_value = Receipt(status,body)
            self.assertNotEqual(json.loads(hook.notify_webhook('https://fixture.invalid/hook',json.dumps([FINDING]),platform='slack'))['status'],'sent')

    def test_webhook_positive_receipts_filter_and_count(self):
        for platform, status, body in [('slack',200,b'ok'),('discord',204,b''),('teams',200,b'1')]:
            receipt = Receipt(status, body)
            self.send.return_value = receipt
            result = json.loads(hook.notify_webhook('https://fixture.invalid/hook', json.dumps([FINDING]*12), platform, 'HIGH'))
            self.assertEqual(result['status'], 'sent')
            self.assertEqual(result['findings_sent'], 10)
            self.assertEqual(result['findings_omitted'], 2)
            self.assertTrue(all(0 < n <= 65537 for n in receipt.read_sizes))
        self.send.reset_mock()
        self.assertFalse(json.loads(hook.notify_webhook('https://fixture.invalid/hook','[]'))['sent'])
        self.assertFalse(self.send.called)

    def test_webhook_failure_hides_url_secret(self):
        self.send.side_effect = TimeoutError(SECRET)
        result = hook.notify_webhook('https://fixture.invalid/' + SECRET,json.dumps([FINDING]))
        self.assertNotIn(SECRET,result)

    def test_monitor_rejects_invalid_empty_and_corrupt_state(self):
        for data in ('null','[]','{}','{"open_ports":[1]}'):
            self.assertIn('error',json.loads(monitor.continuous_monitor('fixture',data)))
        self.assertFalse(self.db.exists())
        self.db.write_text('{broken')
        self.assertIn('error',json.loads(monitor.continuous_monitor('fixture','{"open_ports":[]}')))
        self.assertEqual(self.db.read_text(),'{broken')

    def test_monitor_persists_and_does_not_claim_remediation(self):
        monitor.continuous_monitor('fixture',json.dumps({'vulnerabilities':[FINDING]}))
        self.assertTrue(self.db.exists())
        result = monitor.continuous_monitor('fixture','{"vulnerabilities":[]}')
        self.assertNotIn('Resolved vulnerabilities', result)
        self.assertEqual(json.loads(monitor.continuous_monitor('fixture',action='history'))['total_snapshots'],2)
        self.assertIn('diff',json.loads(monitor.continuous_monitor('fixture',action='diff')))
        self.assertEqual(json.loads(monitor.continuous_monitor('',action='stats'))['targets_monitored'],1)
        self.assertEqual(json.loads(monitor.continuous_monitor('fixture','{"vulnerabilities":[]}'))['status'],'no_change')
        self.assertEqual(json.loads(monitor.continuous_monitor('fixture',action='clear'))['action'],'clear')

    def test_monitor_same_count_change_not_empty_diff(self):
        monitor.continuous_monitor('fixture','{"vulnerabilities":[{"title":"one"}]}')
        result=json.loads(monitor.continuous_monitor('fixture','{"vulnerabilities":[{"title":"two"}]}'))
        self.assertTrue(result['changes_detected']['changed'])

    def test_monitor_symlink_and_secrets(self):
        data = json.dumps({'vulnerabilities':[dict(FINDING,token=SECRET,evidence=SECRET)]})
        monitor.continuous_monitor('fixture',data)
        self.assertNotIn(SECRET,self.db.read_text())
        original = self.db.read_bytes()
        other=self.root/'other.json'
        other.write_bytes(original)
        self.db.unlink()
        self.db.symlink_to(other)
        self.assertIn('error',json.loads(monitor.continuous_monitor('fixture',action='stats')))
        self.assertEqual(other.read_bytes(),original)

    def test_input_and_store_budgets(self):
        large='x'*(1024*1024+1)
        for call in (lambda:gh.github_issue(large),lambda:jira.jira_create(large),
                     lambda:hook.notify_webhook('https://fixture.invalid/hook',large),lambda:monitor.continuous_monitor('fixture',large)):
            with patch.object(json,'loads',side_effect=AssertionError('parse forbidden')) as parse:
                result=call()
                parse.assert_not_called()
            self.assertIn('error',json.loads(result))
        self.assertFalse(self.send.called)
        with self.db.open('wb') as stream:
            stream.truncate(4*1024*1024+1)
        self.assertIn('error',json.loads(monitor.continuous_monitor('fixture',action='stats')))

    def test_monitor_url_target_roundtrip_and_atomic_failure(self):
        target=f'https://fixture.invalid/?token={SECRET}'
        result=json.loads(monitor.continuous_monitor(target,'{"open_ports":[]}'))
        self.assertNotIn('error',result)
        self.assertNotIn(SECRET,self.db.read_text())
        self.assertEqual(json.loads(monitor.continuous_monitor(target,action='history'))['total_snapshots'],1)
        before=self.db.read_bytes()
        with patch.object(monitor.os,'replace',side_effect=OSError('synthetic write failure')):
            self.assertIn('error',json.loads(monitor.continuous_monitor(target,'{"open_ports":[{"port":443}]}')))
        self.assertEqual(self.db.read_bytes(),before)

    def test_monitor_rejects_swap_after_stat(self):
        monitor.continuous_monitor('fixture','{"open_ports":[]}')
        other=self.root/'replacement'
        other.write_text('{"targets":{}}')
        real_open=os.open
        def swap(path,flags,*args,**kwargs):
            if str(path)==str(self.db):
                self.db.unlink()
                self.db.symlink_to(other)
            return real_open(path,flags,*args,**kwargs)
        with patch.object(monitor.os,'open',side_effect=swap):
            self.assertIn('error',json.loads(monitor.continuous_monitor('fixture',action='stats')))
        self.assertEqual(other.read_text(),'{"targets":{}}')

    def test_monitor_target_name_is_not_a_credential_field(self):
        monitor.continuous_monitor('token.fixture.invalid','{"open_ports":[]}')
        result=json.loads(monitor.continuous_monitor('token.fixture.invalid',action='history'))
        self.assertEqual(result['total_snapshots'],1)

    def test_receipt_size_limit_and_single_attempt(self):
        for which in ('github','jira'):
            self.send.reset_mock()
            self.send.return_value=Receipt(201,b'x'*65537)
            self.assertIn('error',self.issue(which))
            self.assertEqual(self.send.call_count,1)
        self.send.reset_mock()
        self.send.return_value=Receipt(200,b'x'*65537)
        self.assertFalse(json.loads(hook.notify_webhook('https://fixture.invalid/hook',json.dumps([FINDING])))['sent'])
        self.assertEqual(self.send.call_count,1)


class FakeResponse:
    def __init__(self, code=404, text=''):
        self.status_code,self.text=code,text
        self.headers={'content-type':'text/plain'}
    async def aiter_bytes(self):
        for i in range(0,len(self.text),8192):
            yield self.text[i:i+8192].encode()
    async def aiter_raw(self,chunk_size=8192):
        async for chunk in self.aiter_bytes():
            yield chunk


class FakeClient:
    def __init__(self,responses):
        self.responses=iter(responses)
        self.calls=[]
    async def __aenter__(self): return self
    async def __aexit__(self,*args): pass
    async def get(self,url):
        self.calls.append(url)
        result=next(self.responses)
        if isinstance(result,Exception): raise result
        return result
    def stream(self,method,url):
        client=self
        class Stream:
            async def __aenter__(self): return await client.get(url)
            async def __aexit__(self,*args): pass
        return Stream()


class CITests(unittest.TestCase):
    def run_scan(self,responses):
        client=FakeClient(responses)
        with patch.object(ci.httpx,'AsyncClient',return_value=client):
            result=asyncio.run(ci.ci_cd_scan('https://fixture.invalid'))
        return result,client

    def test_rate_limit_stops_and_marks_incomplete(self):
        result,client=self.run_scan([FakeResponse(429)]*12)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(len(client.calls),1)

    def test_root_timeout_is_structured(self):
        result,_=self.run_scan([ci.httpx.ReadTimeout(SECRET)]+[FakeResponse()]*11)
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn(SECRET,json.dumps(result))

    def test_soft404_is_not_accessible_config(self):
        result,_=self.run_scan([FakeResponse(200,'<html>fixture login page</html>')]*12)
        self.assertFalse(any(f.get('note')=='CI/CD file accessible' for f in result['findings']))

    def test_secret_candidate_redacted_and_requests_bounded(self):
        secret='ghp_'+'A'*36
        result,client=self.run_scan([FakeResponse(),FakeResponse(),FakeResponse(200,'name: fixture\non: push\njobs:\n  build:\n    env:\n      TOKEN: '+secret)]+[FakeResponse()]*9)
        self.assertNotIn(secret[:20],json.dumps(result))
        self.assertIn('candidate',json.dumps(result))
        self.assertLessEqual(len(client.calls),12)

    def test_oversize_response_incomplete(self):
        result,_=self.run_scan([FakeResponse(200,'x'*(1024*1024+1))]+[FakeResponse()]*11)
        self.assertFalse(result['coverage_complete'])

    def test_compressed_content_not_decoded_without_budget(self):
        response=FakeResponse(200,'name: fixture\non: push\njobs:\n  TOKEN: ghp_'+'A'*36)
        response.headers['content-encoding']='gzip'
        result,_=self.run_scan([FakeResponse(),FakeResponse(),response]+[FakeResponse()]*9)
        self.assertFalse(result['coverage_complete'])
        self.assertFalse(result['findings'])

    def test_observation_only_mock_positive_and_invalid_target(self):
        result,client=self.run_scan([FakeResponse(),FakeResponse(),FakeResponse(200,'name: fixture\non: push\njobs:\n  build: {}')]+[FakeResponse()]*9)
        self.assertEqual(result['findings'][0]['status'],'candidate')
        self.assertEqual(len(client.calls),12)
        with patch.object(ci.httpx,'AsyncClient',side_effect=AssertionError('no request')):
            invalid=asyncio.run(ci.ci_cd_scan('https://user:pass@fixture.invalid/?token=x'))
        self.assertFalse(invalid['coverage_complete'])


if __name__=='__main__': unittest.main()
