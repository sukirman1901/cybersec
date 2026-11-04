"""Offline Rails recognition, read-only behavior and failure accounting."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools import rails_scan as module


async def scan(handler):
    seen = []
    def respond(request):
        seen.append((request.method, request.url.path))
        return handler(request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    with patch.object(module.httpx, 'AsyncClient', return_value=client):
        result = await module.rails_scan('https://fixture.test')
    return result, seen


class RailsAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_default_scan_never_writes(self):
        result, seen = await scan(lambda r: httpx.Response(201 if r.method == 'POST' else 404))
        self.assertEqual({method for method, _ in seen}, {'GET'})
        self.assertFalse(result['vulnerable'])
        self.assertIn('mass_assignment', result['checks_not_performed'])

    async def test_dynamic_catchall_is_not_exposure(self):
        result, _ = await scan(lambda r: httpx.Response(200, text=f'<html>Rails password secret help: {r.url.path}</html>'))
        self.assertFalse(result['vulnerable'])
        self.assertEqual(result['findings'], [])

    async def test_fingerprint_is_not_vulnerability(self):
        result, _ = await scan(lambda r: httpx.Response(200, headers={'x-powered-by':'Phusion Passenger (Ruby on Rails)', 'set-cookie':'site_session=private-value'}, text='hello'))
        self.assertFalse(result['vulnerable'])
        self.assertTrue(result['framework_detected'])
        self.assertNotIn('private-value', json.dumps(result))

    async def test_positive_source_signatures_are_retained_and_redacted(self):
        fixtures = {
            '/config/database.yml':'production:\n  adapter: postgresql\n  database: app\n  password: private-value\n',
            '/config/secrets.yml':'production:\n  secret_key_base: private-value\n',
            '/Gemfile':'source "https://rubygems.org"\ngem "rails", "7.0"\n',
            '/db/schema.rb':'ActiveRecord::Schema[7.0].define(version: 2026) do\n  create_table "users" do |t|\n  end\nend',
        }
        for path, body in fixtures.items():
            with self.subTest(path=path):
                result, _ = await scan(lambda r: httpx.Response(200, text=body) if r.url.path == path else httpx.Response(404))
                self.assertTrue(result['findings'])
                self.assertEqual(result['findings'][0]['path'], path)
                self.assertNotIn('private-value', json.dumps(result))

    async def test_denial_stops_and_remains_incomplete(self):
        for code in (401,403,429,503):
            with self.subTest(code=code):
                result, seen = await scan(lambda r: httpx.Response(code))
                self.assertEqual(len(seen), 1)
                self.assertFalse(result['coverage_complete'])
                self.assertFalse(result['vulnerable'])

    async def test_transport_failure_is_structured(self):
        def offline(request):
            raise httpx.ConnectError('private-value', request=request)
        result, seen = await scan(offline)
        self.assertEqual(len(seen), 1)
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('private-value', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
