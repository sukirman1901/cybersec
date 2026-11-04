"""Offline framework recognition and response-quality regressions."""
import importlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TOOLS = ('django_scan', 'express_scan', 'spring_scan', 'tech_detect')


async def run(tool, handler):
    module = importlib.import_module('cyber_tools.' + tool)
    seen = []
    def respond(request):
        seen.append((request.method, request.url.path))
        return handler(request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    factory = 'cyber_tools.http_guard.GuardedAsyncClient' if tool == 'tech_detect' else 'cyber_tools.' + tool + '.httpx.AsyncClient'
    with patch(factory, return_value=client):
        result = await getattr(module, 'detect_technologies' if tool == 'tech_detect' else tool)('https://fixture.test')
    return result, seen


class FrameworkAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_malformed_boolean_meta_attributes_do_not_crash(self):
        result, _ = await run('tech_detect', lambda r: httpx.Response(200,
            text='<meta name><meta name="generator" content><script src></script>'))
        self.assertIsNone(result['cms'])
        self.assertTrue(result['coverage_complete'])

    async def test_other_positive_signature_formats(self):
        cases = (
            ('django_scan','/manage.py', 'from django.core.management import execute_from_command_line\nDJANGO_SETTINGS_MODULE = "app.settings"'),
            ('django_scan','/.env', 'DJANGO_SECRET_KEY=private-value\nDJANGO_SETTINGS_MODULE=app.settings'),
            ('express_scan','/.git/HEAD', 'ref: refs/heads/main\n'),
            ('express_scan','/%s', 'TypeError: bad request\n    at handler (/app/index.js:12:7)\n'),
            ('express_scan','/static/', '<html><title>Index of /static/</title><a href="../">Parent directory</a></html>'),
            ('spring_scan','/actuator/beans', '{"contexts":{"app":{"beans":{"controller":{"type":"app.Controller"}}}}}'),
            ('spring_scan','/actuator/mappings', '{"contexts":{"app":{"mappings":{"dispatcherServlets":{}}}}}'),
            ('spring_scan','/actuator/configprops', '{"contexts":{"app":{"beans":{"config":{"properties":{}}}}}}'),
            ('spring_scan','/actuator/threaddump', '{"threads":[{"threadName":"main","stackTrace":[]}]}'),
            ('spring_scan','/actuator/loggers', '{"levels":["INFO"],"loggers":{"ROOT":{"effectiveLevel":"INFO"}}}'),
        )
        for tool, path, body in cases:
            with self.subTest(tool=tool, path=path):
                result, _ = await run(tool, lambda r: httpx.Response(200,text=body) if r.url.path == path else httpx.Response(404))
                self.assertEqual(len(result['findings']), 1)
                self.assertNotIn('private-value', json.dumps(result))

    async def test_tech_cookie_values_links_comments_and_queries_not_hints(self):
        result, _ = await run('tech_detect', lambda r: httpx.Response(200,
            headers={'set-cookie':'ordinary=PHPSESSID; Path=/'},
            text='<!-- <script src="/jquery.js"></script> --><a href="https://cdn.shopify.com/">article</a><script src="/app.js?framework=/_next/static/"></script>'))
        self.assertFalse(result['programming_languages'])
        self.assertFalse(result['javascript_frameworks'])
        self.assertIsNone(result['cms'])

    async def test_failed_response_after_positive_retains_evidence(self):
        def handler(r):
            if r.url.path == '/actuator/env':
                return httpx.Response(200,json={'activeProfiles':[], 'propertySources':[{'name':'env','properties':{}}]})
            if r.url.path == '/actuator/beans':
                return httpx.Response(403)
            return httpx.Response(404)
        result, _ = await run('spring_scan', handler)
        self.assertEqual(len(result['findings']), 1)
        self.assertFalse(result['coverage_complete'])

    async def test_dynamic_prose_and_generic_headers_are_not_detection(self):
        for tool in TOOLS:
            with self.subTest(tool=tool):
                result, _ = await run(tool, lambda r: httpx.Response(200,
                    headers={'x-frame-options':'DENY','x-powered-by':'unrelated'},
                    text=f'<html>Learn django csrf debug: true spring actuator express error: at WordPress React cloudflare gtag {r.url.path}</html>'))
                self.assertFalse(result.get('findings'))
                self.assertFalse(result.get('django_detected'))
                self.assertFalse(result.get('spring_detected'))
                self.assertFalse(result.get('cms'))
                self.assertFalse(result.get('javascript_frameworks'))
                self.assertFalse(result.get('cdn'))
                self.assertFalse(result.get('analytics'))

    async def test_blocked_and_transport_stop_incomplete(self):
        def offline(request):
            raise httpx.ConnectError('private-value', request=request)
        for tool in TOOLS:
            for handler in (lambda r: httpx.Response(403), lambda r: httpx.Response(429), offline):
                with self.subTest(tool=tool, handler=handler):
                    result, seen = await run(tool, handler)
                    self.assertEqual(len(seen), 1)
                    self.assertFalse(result['coverage_complete'])
                    self.assertFalse(result.get('findings'))
                    self.assertNotIn('private-value', json.dumps(result))

    async def test_distinctive_positive_source_and_actuator_data(self):
        cases = (
            ('django_scan','/settings.py', "SECRET_KEY = 'private-value'\nDATABASES = {'default': {}}\nINSTALLED_APPS = ['django.contrib.admin']"),
            ('express_scan','/.env','NODE_ENV=production\nDB_PASSWORD=private-value\n'),
            ('spring_scan','/actuator/env',json.dumps({'activeProfiles':[], 'propertySources':[{'name':'systemProperties','properties':{'secret':{'value':'private-value'}}}]})),
        )
        for tool, path, body in cases:
            with self.subTest(tool=tool):
                result, seen = await run(tool, lambda r: httpx.Response(200, text=body) if r.url.path == path else httpx.Response(404))
                self.assertTrue(result['findings'])
                self.assertNotIn('private-value', json.dumps(result))
                self.assertEqual({method for method, _ in seen}, {'GET'})
                self.assertTrue(result['coverage_complete'])

    async def test_admin_and_health_are_observations_not_vulnerabilities(self):
        cases = (
            ('django_scan','/admin/', '<html><title>Log in | Django site admin</title><input name="csrfmiddlewaretoken"></html>'),
            ('spring_scan','/actuator/health','{"status":"UP"}'),
            ('express_scan','/', 'Hello'),
        )
        for tool, path, body in cases:
            with self.subTest(tool=tool):
                result, _ = await run(tool, lambda r: httpx.Response(200, text=body, headers={'x-powered-by':'Express'}) if r.url.path == path else httpx.Response(404))
                self.assertFalse(result.get('vulnerable'))
                self.assertFalse(result['findings'])
                self.assertTrue(result['observations'])

    async def test_tech_assets_and_headers_without_secret_values(self):
        result, _ = await run('tech_detect', lambda r: httpx.Response(200,
            headers={'server':'nginx','cf-ray':'private-value', 'set-cookie':'PHPSESSID=private-value', 'x-custom-token':'private-value'},
            text='<script src="/_next/static/chunks/main.js"></script><link href="/wp-content/themes/site/style.css" rel="stylesheet">'))
        self.assertEqual(result['cms'], 'WordPress')
        self.assertIn('Next.js', result['javascript_frameworks'])
        self.assertIn('PHP', result['programming_languages'])
        self.assertIn('Cloudflare', result['cdn'])
        self.assertNotIn('private-value', json.dumps(result))

    async def test_spring_does_not_download_heap_dumps(self):
        _, seen = await run('spring_scan', lambda r: httpx.Response(404))
        self.assertFalse(any('heapdump' in path for _, path in seen))


if __name__ == '__main__':
    unittest.main()
