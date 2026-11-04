"""API/backup/log response fixtures: accuracy, bounded work, evidence privacy."""
import importlib
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TOOLS = ('api_fuzz', 'exposed_backup', 'log_exposure')
CASES = ('positive', 'catchall', 'negative', 'blocked', 'transport', 'incidental', 'json_catchall')


async def run_case(tool, case):
    module = importlib.import_module('cyber_tools.' + tool)
    seen = []
    def handler(req):
        seen.append(str(req.url))
        path = req.url.path
        if case == 'transport':
            raise httpx.ConnectError('fixture offline', request=req)
        if case == 'blocked':
            return httpx.Response(429, text='slow down')
        if case == 'catchall':
            return httpx.Response(200, text='<html>Welcome. View API docs, debug error or backup help.</html>')
        if case == 'json_catchall':
            return httpx.Response(200, json={'message':'not found','error':'no route'})
        if case == 'positive':
            if tool == 'api_fuzz' and path == '/openapi.json':
                return httpx.Response(200, json={'openapi':'3.0.3','info':{'title':'Fixture','version':'1'},'paths':{}})
            if tool == 'exposed_backup' and path == '/.env.bak':
                return httpx.Response(200, text='APP_ENV=production\nDB_PASSWORD=synthetic-do-not-export\n')
            if tool == 'log_exposure' and path == '/app.log':
                return httpx.Response(200, text='[2026-11-04 10:11:12] production.ERROR: password=synthetic-do-not-export\n[2026-11-04 10:11:13] production.INFO: started\n')
        if case == 'incidental':
            return httpx.Response(200, text='Documentation: an error or token may appear in logs. Back up your database regularly.')
        return httpx.Response(404, text='not found')
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    start = time.perf_counter()
    error = None
    try:
        with patch.object(module.httpx, 'AsyncClient', return_value=client):
            result = await getattr(module, tool)('https://fixture.test')
    except Exception as exc:
        result = {}
        error = type(exc).__name__
    detected = bool(result.get('found')) if tool == 'api_fuzz' else bool(result.get('backup_exposed')) if tool == 'exposed_backup' else bool(result.get('exposed_logs'))
    return {'tool':tool, 'case':case, 'expected_positive':case=='positive', 'detected':detected,
            'elapsed_ms':(time.perf_counter()-start)*1000, 'requests':len(seen), 'urls':seen,
            'result':result, 'exception':error}


class DiscoveryAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_priority_backup_variants_and_signature_formats(self):
        module = importlib.import_module('cyber_tools.exposed_backup')
        cases = [('/config.php.backup', b'<?php $db_password = "synthetic-private-value";'),
                 ('/dump.sql.old', b'-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);'),
                 ('/config.json~', b'{"database":{"password":"synthetic-private-value"}}')]
        for path, content in cases:
            with self.subTest(path=path):
                client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req:
                    httpx.Response(200, content=content) if req.url.path==path else httpx.Response(404)))
                with patch.object(module.httpx, 'AsyncClient', return_value=client):
                    result = await module.exposed_backup('https://fixture.test')
                self.assertTrue(result['backup_exposed'])
                self.assertNotIn('synthetic-private-value', json.dumps(result))

    async def test_json_log_secret_is_candidate_without_value(self):
        module = importlib.import_module('cyber_tools.log_exposure')
        body = '\n'.join(json.dumps({'timestamp':'2026-11-04T10:00:00Z','level':'info',
                                    'message':'login','password':'synthetic-private-value'}) for _ in range(2))
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req:
            httpx.Response(200,text=body) if req.url.path=='/app.log' else httpx.Response(404)))
        with patch.object(module.httpx, 'AsyncClient', return_value=client):
            result = await module.log_exposure('https://fixture.test')
        self.assertEqual(result['sensitive_exposure'], 1)
        self.assertNotIn('synthetic-private-value', json.dumps(result))

    async def test_realistic_positive_and_redacted_evidence(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'positive')
                self.assertIsNone(row['exception'])
                self.assertTrue(row['detected'])
                self.assertNotIn('synthetic-do-not-export', json.dumps(row['result']))

    async def test_html_json_catchalls_and_prose_not_findings(self):
        for tool in TOOLS:
            for case in ('catchall','json_catchall','incidental','negative'):
                with self.subTest(tool=tool, case=case):
                    row = await run_case(tool, case)
                    self.assertIsNone(row['exception'])
                    self.assertFalse(row['detected'])

    async def test_rate_limit_stops_immediately(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'blocked')
                self.assertEqual(row['requests'], 1)
                self.assertFalse(row['result'].get('coverage_complete', True))
                self.assertFalse(row['detected'])

    async def test_transport_error_is_structured_and_incomplete(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                row = await run_case(tool, 'transport')
                self.assertIsNone(row['exception'])
                self.assertFalse(row['result'].get('coverage_complete', True))
                self.assertIn('error', row['result'])

    async def test_backup_budget_deterministic_and_deferred_explicit(self):
        a = await run_case('exposed_backup', 'negative')
        b = await run_case('exposed_backup', 'negative')
        self.assertLessEqual(a['requests'], 25)
        # The random soft-404 control differs; selected candidate paths must not.
        self.assertEqual(a['urls'][1:], b['urls'][1:])
        self.assertGreater(a['result']['candidates_deferred'], 0)
        self.assertFalse(a['result']['coverage_complete'])


if __name__ == '__main__':
    unittest.main()
