"""Synthetic cloud adapter evidence checks; no accounts, commands or network."""
import asyncio
import importlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class CloudAccuracy(unittest.IsolatedAsyncioTestCase):
    async def http(self, name, status=200, body=b'<html>login</html>', target='https://fixture.invalid'):
        module = importlib.import_module('cyber_tools.' + name)
        client_type = httpx.AsyncClient
        def respond(request):
            if status == 0:
                raise httpx.ReadTimeout('token=SECRET')
            return httpx.Response(status, content=body)
        transport = httpx.MockTransport(respond)
        with patch.object(module.httpx, 'AsyncClient', side_effect=lambda **kw: client_type(transport=transport)), \
             patch('socket.socket', side_effect=OSError('local socket forbidden')) as sock:
            result = await getattr(module, name)(target)
        return result, sock

    async def test_http_generic_pages_do_not_confirm_exposure(self):
        for name in ('docker_scan', 'k8s_scan'):
            result, sock = await self.http(name)
            self.assertEqual(result['count'], 0, name)
            self.assertFalse(result['coverage_complete'])
            sock.assert_not_called()

    async def test_http_failures_are_incomplete(self):
        for name in ('docker_scan', 'k8s_scan', 'cloud_enum'):
            for status in (0, 403, 500):
                result, _ = await self.http(name, status, target='fixture' if name == 'cloud_enum' else 'https://fixture.invalid')
                self.assertEqual(result['count'], 0, (name, status))
                self.assertFalse(result['coverage_complete'])
                self.assertNotIn('SECRET', json.dumps(result))

    async def test_k8s_discovery_is_not_full_access(self):
        result, _ = await self.http('k8s_scan', body=json.dumps({'kind': 'APIResourceList', 'groupVersion': 'v1', 'resources': []}).encode())
        self.assertFalse(any(f['severity'] == 'critical' for f in result['findings']))
        self.assertNotIn('Full API access', json.dumps(result))

    async def test_k8s_secret_list_positive_without_secret_values(self):
        body = json.dumps({'kind': 'SecretList', 'apiVersion': 'v1', 'items': [{'kind': 'Secret', 'data': {'token': 'SECRET'}}]}).encode()
        result, _ = await self.http('k8s_scan', body=body)
        self.assertTrue(any(f['endpoint'] == '/api/v1/secrets' for f in result['findings']))
        self.assertNotIn('SECRET', json.dumps(result))

    async def cli(self, name, body, code=0, installed=('aws', 'az', 'gcloud'), **kwargs):
        module = importlib.import_module('cyber_tools.' + name)
        proc = AsyncMock()
        proc.returncode = code
        proc.communicate.return_value = (body, b'token=SECRET')
        for stream, data in [('stdout', body), ('stderr', b'token=SECRET')]:
            reader = asyncio.StreamReader()
            reader.feed_data(data)
            reader.feed_eof()
            setattr(proc, stream, reader)
        proc.wait.return_value = code
        with patch('shutil.which', side_effect=lambda tool: '/mock/' + tool if tool in installed else None), \
             patch('asyncio.create_subprocess_exec', return_value=proc):
            return await getattr(module, name)(**kwargs)

    async def test_cli_bad_outputs_not_empty_success(self):
        for name in ('cloud_iam_audit', 'cloud_infra'):
            for body, code in [(b'not json', 0), (b'{}', 0), (b'[]', 1)]:
                result = await self.cli(name, body, code)
                self.assertFalse(result.get('coverage_complete', True), (name, body, code))
                self.assertIn('error', result)
                self.assertNotIn('SECRET', json.dumps(result))

    async def test_cli_inventory_positive_is_not_policy_audit(self):
        result = await self.cli('cloud_iam_audit', b'{"Roles":[{"RoleName":"fixture", "token":"SECRET"}]}')
        self.assertEqual(result['count'], 1)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertIn('inventory', result['coverage'])
        self.assertFalse(result.get('audit_complete', True))

    async def test_adapter_findings_include_evidence_scope(self):
        cases = [('docker_scan', b'PATH=/bin\x00', 'https://fixture.invalid', 'findings'),
                 ('k8s_scan', b'{"kind":"SecretList","items":[{}]}', 'https://fixture.invalid', 'findings'),
                 ('cloud_enum', b'<ListBucketResult><Name>fixture</Name></ListBucketResult>', 'fixture', 'resources_found')]
        for name, body, target, key in cases:
            result, _ = await self.http(name, body=body, target=target)
            self.assertTrue(result[key])
            for finding in result[key]:
                self.assertIn(finding.get('confidence'), ('LOW', 'MEDIUM', 'HIGH'))
                self.assertTrue(finding.get('coverage'))
        result = await self.cli('cloud_iam_audit', b'[{"Status":"FAIL","Severity":"HIGH"}]', installed=('prowler',))
        self.assertTrue(result['findings'])
        self.assertEqual(result['findings'][0].get('confidence'), 'MEDIUM')
        self.assertIn('external', result['findings'][0].get('coverage', '').lower())
        result = await self.cli('cloud_infra', b'[]')
        self.assertFalse(result.get('audit_complete', True))

    async def test_inventory_schema_and_empty_controls(self):
        cases = [('cloud_iam_audit', b'{"Roles":[]}', {}, 'roles'),
                 ('cloud_iam_audit', b'[{"name":"roles/viewer","token":"SECRET"}]', {'provider': 'gcp'}, 'roles'),
                 ('cloud_infra', b'[{"GroupId":"sg-fixture","UserData":"SECRET"}]', {}, 'open_security_groups'),
                 ('cloud_infra', b'{"Buckets":[{"Name":"fixture", "token":"SECRET"}]}', {'service': 's3'}, 'buckets'),
                 ('cloud_infra', b'[{"name":"fixture","adminPassword":"SECRET"}]', {'provider': 'azure'}, 'virtual_machines')]
        for name, body, kwargs, key in cases:
            result = await self.cli(name, body, **kwargs)
            self.assertTrue(result['coverage_complete'], result)
            self.assertIn(key, result)
            self.assertNotIn('SECRET', json.dumps(result))

    async def test_inventory_limits_and_pagination(self):
        for name, body in [('cloud_iam_audit', json.dumps({'Roles': [{'RoleName': 'role'}] * 101}).encode()),
                           ('cloud_infra', json.dumps([{'GroupId': 'sg-fixture'}] * 101).encode()),
                           ('cloud_iam_audit', b'{"Roles":[],"IsTruncated":true}'),
                           ('cloud_infra', b'{"Buckets":[],"ContinuationToken":"SECRET"}')]:
            result = await self.cli(name, body, **({'service': 's3'} if b'Buckets' in body else {}))
            self.assertFalse(result['coverage_complete'])
            self.assertLessEqual(result['count'], 100)
            self.assertNotIn('SECRET', json.dumps(result))

    async def test_prowler_fail_pass_manual_and_malformed(self):
        for records, count, complete in [([{'Status': 'FAIL', 'Severity': 'HIGH', 'StatusExtended': 'SECRET'}], 1, True),
                                          ([{'Status': 'PASS'}], 0, True),
                                          ([{'Status': 'MANUAL'}], 0, False),
                                          ([{'Status': 'ERROR'}], 0, False)]:
            result = await self.cli('cloud_iam_audit', json.dumps(records).encode(), installed=('prowler',))
            self.assertEqual(result['count'], count)
            self.assertEqual(result['coverage_complete'], complete)
            self.assertNotIn('SECRET', json.dumps(result))

    async def test_scout_logs_are_not_an_audit(self):
        result = await self.cli('cloud_infra', b'All done token=SECRET', installed=('scoutsuite',))
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('SECRET', json.dumps(result))

    async def test_runner_errors_and_missing_tools(self):
        for name in ('cloud_iam_audit', 'cloud_infra'):
            module = importlib.import_module('cyber_tools.' + name)
            for error in ('timeout', 'output_limit', 'spawn_error'):
                with patch('shutil.which', side_effect=lambda tool: '/mock/aws' if tool == 'aws' else None), \
                     patch.object(module, '_run_cli', new=AsyncMock(return_value={'exit_code': -1, 'error_kind': error, 'stdout': 'token=SECRET'})):
                    result = await getattr(module, name)()
                    self.assertFalse(result['coverage_complete'])
                    self.assertNotIn('SECRET', json.dumps(result))
            with patch('shutil.which', return_value=None), patch.object(module, '_run_cli', new=AsyncMock()) as run:
                self.assertFalse((await getattr(module, name)())['coverage_complete'])
                run.assert_not_called()

    async def test_http_limits_invalid_inputs_and_not_found(self):
        for name in ('docker_scan', 'k8s_scan', 'cloud_enum'):
            result, _ = await self.http(name, body=b'x' * 70000, target='fixture' if name == 'cloud_enum' else 'https://fixture.invalid')
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(result['count'], 0)
            result, _ = await self.http(name, status=404, target='fixture' if name == 'cloud_enum' else 'https://fixture.invalid')
            self.assertTrue(result['coverage_complete'])
            result, _ = await self.http(name, target='https://user:SECRET@fixture.invalid/?token=SECRET')
            self.assertFalse(result['coverage_complete'])
            self.assertNotIn('SECRET', json.dumps(result))

    async def test_http_positive_file_and_bucket_evidence(self):
        result, sock = await self.http('docker_scan', body=b'PATH=/usr/bin\x00TOKEN=SECRET\x00')
        self.assertEqual([f['path'] for f in result['findings']], ['/proc/1/environ'])
        self.assertNotIn('SECRET', json.dumps(result))
        sock.assert_not_called()
        result, _ = await self.http('cloud_enum', body=b'<ListBucketResult><Name>fixture</Name></ListBucketResult>', target='fixture')
        self.assertEqual(result['count'], 2)  # AWS and GCP base-name candidates only.
        self.assertFalse(result['coverage_complete'])

    async def test_recursive_json_is_incomplete(self):
        result, _ = await self.http('k8s_scan', body=b'[' * 2000 + b']' * 2000)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['count'], 0)

    async def test_empty_k8s_list_does_not_claim_secret_exposure(self):
        result, _ = await self.http('k8s_scan', body=b'{"kind":"SecretList","items":[]}')
        self.assertFalse(any(f['severity'] == 'critical' for f in result['findings']))

    async def test_invalid_port_is_rejected_before_http(self):
        for name in ('k8s_scan', 'docker_scan'):
            module = importlib.import_module('cyber_tools.' + name)
            with patch.object(module.httpx, 'AsyncClient', side_effect=AssertionError('HTTP must not start for invalid port')) as client:
                result = await getattr(module, name)('https://fixture.invalid:bad')
                self.assertFalse(result['coverage_complete'])
                client.assert_not_called()

    async def test_aggregate_empty_secret_list_is_informational(self):
        from cyber_tools import cloud_audit as module
        with patch.object(module, '_read', return_value=(200, b'{"kind":"SecretList","items":[]}')):
            result = module._k8s_check('fixture.invalid')
        self.assertFalse(any(f['severity'] == 'critical' for f in result['findings']))


class AggregateAccuracy(unittest.TestCase):
    def test_aggregate_transport_does_not_follow_redirects(self):
        from cyber_tools import cloud_audit as module
        from cyber_tools.http_guard import NoRedirectHandler
        with patch('urllib.request.build_opener') as build:
            module.guarded_urlopen('https://fixture.invalid', timeout=2)
        self.assertTrue(any(h is NoRedirectHandler or isinstance(h, NoRedirectHandler) for h in build.call_args.args))
        self.assertEqual(build.return_value.open.call_args.kwargs['timeout'], 2)

    def test_shared_request_cap_and_fresh_budget_per_call(self):
        from cyber_tools import cloud_audit as module
        def response(*args, **kwargs):
            resp = io.BytesIO(b'')
            resp.status = 404
            return resp
        kwargs = {'company': 'fixture', 'buckets': ','.join(['fixture'] * 20),
                  'targets': ','.join(['fixture.invalid'] * 20)}
        with patch('time.monotonic', return_value=100), patch.object(module, 'guarded_urlopen', side_effect=response) as request:
            for expected in (40, 80):
                result = json.loads(module.cloud_audit(**kwargs))
                self.assertEqual(request.call_count, expected)
                self.assertEqual(result['budget']['requests'], 40)
                self.assertEqual(result['budget']['skipped'], 121)
                self.assertFalse(result['coverage_complete'])
                skipped = [a['result'] for a in result['audits'] if any(o.get('outcome') == 'skipped_budget' for o in a['result'].get('observations', []))]
                self.assertTrue(skipped)
                self.assertTrue(all(not r['coverage_complete'] for r in skipped))

    def test_deadline_clamps_open_and_read_timeout(self):
        from cyber_tools import cloud_audit as module
        now = [100.0]
        seen = []
        class Response(io.BytesIO):
            status = 404
            def __init__(self):
                super().__init__(b'')
                self.fp = Mock()
                self.fp.raw._sock.settimeout.side_effect = lambda value: seen.append(('read', value))
            def read(self, size):
                now[0] += 1
                return super().read(size)
        def response(*args, timeout):
            seen.append(('open', timeout))
            now[0] += 6
            return Response()
        with patch('time.monotonic', side_effect=lambda: now[0]), patch.object(module, 'guarded_urlopen', side_effect=response) as request:
            result = json.loads(module.cloud_audit(company='fixture', targets='fixture.invalid'))
        self.assertEqual(request.call_count, 5)
        self.assertEqual(seen[-1], ('open', 2.0))  # open crossed deadline; body not read.
        self.assertIn(('read', 3.0), seen)
        self.assertFalse(result['coverage_complete'])
        self.assertGreater(result['budget']['skipped'], 0)
        self.assertIn('not a hard interrupt', result['budget']['limitation'])

    def test_all_emitted_findings_have_confidence_and_coverage(self):
        from cyber_tools import cloud_audit as module
        responses = [(module._s3_check, b'<ListBucketResult><Name>fixture</Name></ListBucketResult>'),
                     (module._k8s_check, b'{"kind":"SecretList","items":[{}]}'),
                     (module._docker_check, json.dumps([{'Id': 'a' * 64, 'Image': 'fixture', 'Names': []}]).encode())]
        for func, body in responses:
            with patch.object(module, '_read', return_value=(200, body)):
                result = func('fixture')
            self.assertTrue(result['findings'])
            for finding in result['findings']:
                self.assertIn(finding.get('confidence'), ('LOW', 'MEDIUM', 'HIGH'))
                self.assertTrue(finding.get('coverage'))

    def test_generic_pages_and_no_local_socket(self):
        from cyber_tools import cloud_audit as module
        def response(*args, **kwargs):
            resp = io.BytesIO(b'<html>login</html>')
            resp.status = 200
            return resp
        with patch.object(module, 'guarded_urlopen', side_effect=response), patch('socket.socket', side_effect=OSError('forbidden')) as sock:
            for func in (module._s3_check, module._k8s_check, module._docker_check):
                result = func('fixture.invalid')
                self.assertEqual(result['findings'], [])
                self.assertFalse(result['coverage_complete'])
            sock.assert_not_called()

    def test_skipped_audits_are_not_findings(self):
        from cyber_tools.cloud_audit import cloud_audit
        result = json.loads(cloud_audit())
        self.assertEqual(result['total_findings'], 0)
        self.assertFalse(result['coverage_complete'])
        self.assertIn('incomplete', result['overall'].lower())

    def test_aggregate_positive_and_limits(self):
        from cyber_tools import cloud_audit as module
        def response(request, **kwargs):
            url = request.full_url
            if '.amazonaws.com' in url:
                body = b'<ListBucketResult><Name>fixture</Name></ListBucketResult>'
            elif '/containers/json' in url:
                body = json.dumps([{'Id': 'a' * 64, 'Image': 'fixture', 'Names': [], 'token': 'SECRET'}]).encode()
            elif url.endswith('/secrets'):
                body = b'{"kind":"SecretList","items":[{"data":{"token":"SECRET"}}]}'
            else:
                body = b'{"kind":"APIResourceList","resources":[]}'
            resp = io.BytesIO(body)
            resp.status = 200
            return resp
        with patch.object(module, 'guarded_urlopen', side_effect=response), patch('socket.socket') as sock:
            result = json.loads(module.cloud_audit(targets='fixture.invalid', buckets='fixture'))
            self.assertEqual(result['total_findings'], 7)
            self.assertNotIn('SECRET', json.dumps(result))
            sock.assert_not_called()
        with patch.object(module, 'guarded_urlopen') as request:
            for kwargs in ({'targets': ','.join(['fixture.invalid'] * 21)}, {'targets': 'https://user:SECRET@fixture.invalid'}, {'buckets': 'x/SECRET'}):
                result = json.loads(module.cloud_audit(**kwargs))
                self.assertIn('error', result)
                self.assertNotIn('SECRET', json.dumps(result))
            request.assert_not_called()

    def test_aggregate_errors_and_malformed_are_incomplete(self):
        from cyber_tools import cloud_audit as module
        import urllib.error
        for effect in (TimeoutError('SECRET'), urllib.error.HTTPError('https://fixture.invalid', 403, 'SECRET', {}, None)):
            with patch.object(module, 'guarded_urlopen', side_effect=effect):
                for func in (module._s3_check, module._k8s_check, module._docker_check):
                    result = func('fixture')
                    self.assertFalse(result['coverage_complete'])
                    self.assertEqual(result['findings'], [])
                    self.assertNotIn('SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
