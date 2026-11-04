"""Offline HTTP/protocol fixtures. No website or real WebSocket connections."""
import asyncio
import base64
import hashlib
import importlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
SECRET = 'synthetic-token-do-not-export'
ASYNC = ('host_header', 'sharepoint_scan', 'oauth_scan', 'websocket_test')


async def run_async(name, handler):
    module = importlib.import_module('cyber_tools.' + name)
    seen = []
    def offline(request):
        seen.append(request)
        return handler(request)
    original = httpx.AsyncClient
    def factory(**kwargs):
        return original(**{**kwargs,'transport':httpx.MockTransport(offline)})
    with patch.object(httpx, 'AsyncClient', side_effect=factory):
        result = await getattr(module, name)('https://fixture.test')
    return result, seen


def run_csrf(handler, **kwargs):
    module = importlib.import_module('cyber_tools.csrf_extract')
    seen = []
    def offline(request):
        seen.append(request)
        return handler(request)
    client = httpx.Client(transport=httpx.MockTransport(offline))
    def legacy(request, **options):
        response = client.get(request.full_url)
        stream = io.BytesIO(response.content)
        stream.status, stream.headers = response.status_code, response.headers
        return stream
    try:
        with patch.object(module,'guarded_urlopen',side_effect=legacy), patch.object(httpx,'Client',return_value=client):
            result = json.loads(module.csrf_extract('https://fixture.test/?token=' + SECRET, **kwargs))
    finally:
        client.close()
    return result, seen


class WebObservationAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_status_prose_and_catchalls_are_not_vulnerabilities(self):
        for name in ASYNC:
            with self.subTest(tool=name):
                body = '<html>Documentation: password reset log metadata _layouts access_token authorization_endpoint evil.com</html>'
                result, _ = await run_async(name, lambda r: httpx.Response(200,text=body,headers={'x-cache':'HIT'}))
                self.assertFalse(result.get('host_header_vulnerable',result.get('vulnerable',False)))
                self.assertFalse(result.get('findings', []))
                self.assertFalse(result.get('candidates', []))

    async def test_only_get_requests_and_small_request_budgets(self):
        for name, cap in [('host_header',3),('sharepoint_scan',6),('oauth_scan',5),('websocket_test',5)]:
            with self.subTest(tool=name):
                result, seen = await run_async(name, lambda r: httpx.Response(200,text='<html>ordinary page</html>'))
                self.assertTrue(all(r.method=='GET' for r in seen))
                self.assertLessEqual(len(seen), cap)
                self.assertTrue(result.get('unsupported_detection'))

    async def test_blocking_redirect_server_failure_and_body_cap(self):
        for name in ASYNC:
            for status in (403,429,302,503,200):
                with self.subTest(tool=name,status=status):
                    result, seen = await run_async(name, lambda r: httpx.Response(status, content=b'x'*262145 if status==200 else b'blocked',headers={'location':'https://outside.test/'}))
                    self.assertEqual(len(seen),1)
                    self.assertFalse(result.get('coverage_complete',True))
                    self.assertTrue(result.get('error'))

    async def test_transport_failure_redacted(self):
        def fail(request):
            raise httpx.ReadTimeout(SECRET,request=request)
        for name in ASYNC:
            with self.subTest(tool=name):
                result, seen = await run_async(name, fail)
                self.assertEqual(len(seen),1)
                self.assertFalse(result.get('coverage_complete',True))
                self.assertNotIn(SECRET,json.dumps(result))

    async def test_host_reflection_is_observation_not_poisoning(self):
        def handler(request):
            value = request.headers.get('x-forwarded-host') or request.headers.get('host')
            return httpx.Response(200,text='<html>'+value+' password reset log</html>',headers={'x-cache':SECRET})
        result, seen = await run_async('host_header',handler)
        self.assertFalse(result['host_header_vulnerable'])
        self.assertTrue(result.get('observations'))
        self.assertTrue(all(x.get('confidence') and x.get('coverage') for x in result['observations']))
        self.assertEqual(result['total_findings'],0)
        self.assertNotIn(SECRET,json.dumps(result))
        self.assertTrue(all(r.url.host=='fixture.test' for r in seen))

    async def test_sharepoint_config_and_api_are_structural_observations(self):
        def handler(request):
            if request.url.path=='/':
                return httpx.Response(200,headers={'microsoftsharepointteamservices':'16.0.0.123'},text='<html>SharePoint</html>')
            if request.url.path=='/web.config':
                return httpx.Response(200,text='<configuration><connectionStrings><add name="db" connectionString="Password='+SECRET+'"/></connectionStrings></configuration>')
            if request.url.path=='/_api/':
                return httpx.Response(200,json={'d':{'__metadata':{'type':'SP.Web'},'Title':SECRET}})
            return httpx.Response(404)
        result, _ = await run_async('sharepoint_scan',handler)
        self.assertTrue(result['is_sharepoint'])
        self.assertTrue(all(x.get('confidence') and x.get('coverage') for x in result['observations']))
        self.assertTrue(any(x.get('path')=='/web.config' for x in result.get('observations',[])))
        self.assertFalse(result.get('vulnerable'))
        self.assertNotIn(SECRET,json.dumps(result))

    async def test_sharepoint_denied_and_catchall_paths_not_exposure(self):
        for mode in ('denied','catchall'):
            def handler(request):
                if request.url.path=='/':
                    return httpx.Response(200,headers={'microsoftsharepointteamservices':'16.0.0'},text='root')
                return httpx.Response(403 if mode=='denied' else 200,text='<html>login</html>')
            with self.subTest(mode=mode):
                result, _ = await run_async('sharepoint_scan',handler)
                self.assertFalse(result.get('vulnerable'))
                self.assertFalse(result['findings'])

    async def test_narrowed_path_coverage_and_missing_sharepoint_hint(self):
        for name in ('sharepoint_scan','oauth_scan'):
            with self.subTest(tool=name):
                result, _ = await run_async(name,lambda r: httpx.Response(404))
                self.assertTrue(result.get('paths_not_checked'))
        result, seen = await run_async('sharepoint_scan',lambda r: httpx.Response(200,text='ordinary page'))
        self.assertEqual(len(seen),1)
        self.assertEqual(len(result.get('paths_skipped',[])),4)
        self.assertFalse(result['coverage_complete'])

    async def test_oauth_metadata_and_error_are_observations(self):
        def handler(request):
            if request.url.path=='/.well-known/openid-configuration':
                return httpx.Response(200,json={'issuer':'https://fixture.test','authorization_endpoint':'https://fixture.test/auth?token='+SECRET,'token_endpoint':'https://fixture.test/token'})
            if request.url.path=='/oauth/authorize':
                return httpx.Response(400,json={'error':'invalid_request','error_description':SECRET})
            return httpx.Response(404)
        result, _ = await run_async('oauth_scan',handler)
        self.assertEqual(result['findings'],[])
        self.assertGreaterEqual(len(result.get('observations',[])),2)
        self.assertTrue(all(x.get('confidence') and x.get('coverage') for x in result['observations']))
        self.assertNotIn(SECRET,json.dumps(result))

    async def test_oauth_malformed_json_not_discovery(self):
        for value in ({'authorization_endpoint':True}, ['authorization_endpoint'], None):
            with self.subTest(value=type(value).__name__):
                result, _ = await run_async('oauth_scan',lambda r: httpx.Response(404) if '.missing-' in r.url.path else httpx.Response(200,json=value))
                self.assertFalse(result['findings'])
                self.assertFalse(result.get('observations'))
                self.assertFalse(result.get('coverage_complete',True))

    async def test_async_deadline_cancels_inflight_mock(self):
        from cyber_tools.surface_probe import SurfaceProbe
        for name in ASYNC:
            with self.subTest(tool=name):
                module = importlib.import_module('cyber_tools.' + name)
                cancelled = []
                async def stall(request):
                    try:
                        await asyncio.Event().wait()
                    finally:
                        cancelled.append(True)
                def short(client, **kwargs):
                    return SurfaceProbe(client,seconds=0.01,**kwargs)
                with patch.object(module,'SurfaceProbe',side_effect=short):
                    result, seen = await run_async(name,stall)
                self.assertEqual(cancelled,[True])
                self.assertEqual(len(seen),1)
                self.assertFalse(result['coverage_complete'])
                self.assertIn('TimeoutError',result.get('errors',[]))

    async def test_websocket_valid_upgrade_is_not_auth_exploit(self):
        def handler(request):
            key = request.headers.get('sec-websocket-key')
            if key:
                accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                return httpx.Response(101,headers={'upgrade':'websocket','connection':'Upgrade','sec-websocket-accept':accept})
            return httpx.Response(200,text='<html>wss://fixture.test/ws?token='+SECRET+'</html>') if request.url.path=='/' else httpx.Response(404)
        result, seen = await run_async('websocket_test',handler)
        self.assertFalse(result['vulnerable'])
        self.assertTrue(any(x.get('type')=='websocket_handshake' for x in result.get('observations',[])))
        self.assertTrue(all(x.get('confidence') and x.get('coverage') for x in result['observations']))
        self.assertNotIn(SECRET,json.dumps(result))
        self.assertTrue(all('origin' not in r.headers for r in seen))

    async def test_bad_upgrade_and_external_links_are_not_trusted(self):
        def handler(request):
            if request.url.path=='/':
                return httpx.Response(200,text='wss://outside.test/ws wss://fixture.test/ws')
            return httpx.Response(200,headers={'connection':'upgrade'},text='ordinary page')
        result, seen = await run_async('websocket_test',handler)
        self.assertFalse(result['vulnerable'])
        self.assertFalse(result.get('observations'))
        self.assertTrue(all(r.url.host=='fixture.test' for r in seen))

    async def test_engine_io_structure_without_session_id_output(self):
        def handler(request):
            if request.url.path=='/socket.io/' and 'EIO' in request.url.params:
                if dict(request.url.params) != {'EIO':'4','transport':'polling'}:
                    return httpx.Response(400,json={'code':0,'message':'Transport unknown'})
                return httpx.Response(200,text='0'+json.dumps({'sid':SECRET,'upgrades':['websocket'],'pingInterval':25000,'pingTimeout':20000}))
            return httpx.Response(200,text='<html>home</html>') if request.url.path=='/' else httpx.Response(404)
        for query in ('EIO=4','EIO=4&transport=websocket','EIO=3&transport=polling'):
            self.assertEqual(handler(httpx.Request('GET','https://fixture.test/socket.io/?'+query)).status_code,400)
        result, seen = await run_async('websocket_test',handler)
        self.assertTrue(any(x.get('type')=='engine_io_open_packet' for x in result.get('observations',[])))
        self.assertTrue(all(x.get('confidence') and x.get('coverage') for x in result['observations']))
        self.assertEqual(len(seen),5)
        polling = [r for r in seen if 'EIO' in r.url.params]
        self.assertEqual(len(polling),1)
        self.assertEqual(polling[0].url.query,b'EIO=4&transport=polling')
        self.assertTrue(all(r.method=='GET' and not r.content for r in seen))
        self.assertTrue(all(not any(h in r.headers for h in ('origin','authorization','cookie')) for r in seen))
        self.assertFalse(result['vulnerable'])
        self.assertNotIn(SECRET,json.dumps(result))

    async def test_malformed_upgrade_and_engine_packet_incomplete(self):
        def handler(request):
            if request.url.path=='/':
                return httpx.Response(200,text='wss://fixture.test/ws')
            if 'EIO' in request.url.params:
                return httpx.Response(200,text='0{"sid":null}')
            return httpx.Response(101,headers={'connection':'Upgrade','upgrade':'websocket','sec-websocket-accept':'wrong'})
        result, _ = await run_async('websocket_test',handler)
        self.assertFalse(result['vulnerable'])
        self.assertFalse(result['observations'])
        self.assertFalse(result['coverage_complete'])
        self.assertTrue(result.get('error'))

    async def test_websocket_discovery_cap_and_source_path_privacy(self):
        def handler(request):
            if request.url.path=='/':
                return httpx.Response(200,text=' '.join('wss://fixture.test/'+SECRET+str(i) for i in range(100)))
            key = request.headers.get('sec-websocket-key')
            if key:
                accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                return httpx.Response(101,headers={'upgrade':'websocket','connection':'Upgrade','sec-websocket-accept':accept})
            return httpx.Response(404)
        result, seen = await run_async('websocket_test',handler)
        self.assertLessEqual(len(seen),5)
        self.assertTrue(result.get('links_truncated'))
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn(SECRET,json.dumps(result))


class CsrfExtractionAccuracy(unittest.TestCase):
    def test_structural_tokens_redacted_and_not_protection_proof(self):
        body = '<meta content="'+SECRET+'" name="csrf-token"><input value="'+SECRET+'" name="csrfmiddlewaretoken" type="hidden">'
        result, seen = run_csrf(lambda r: httpx.Response(200,text=body,headers=[('content-type','text/html'),('x-csrf-token',SECRET),('set-cookie','csrftoken='+SECRET+'; Secure')]))
        self.assertEqual(result['total_tokens'],4)
        self.assertNotIn(SECRET,json.dumps(result))
        self.assertIsNot(result.get('csrf_protected'),True)
        self.assertTrue(all('value_length' in t for t in result['tokens_found']))
        self.assertTrue(all(t.get('confidence') and t.get('coverage') for t in result['tokens_found']))
        self.assertEqual(len(seen),1)

    def test_arbitrary_hidden_fields_meta_param_and_comments_not_tokens(self):
        body = '<input type="hidden" name="password" value="'+SECRET+'"><meta name="csrf-param" content="authenticity_token"><!-- <input type="hidden" name="csrf_token" value="'+SECRET+'"> -->'
        result, _ = run_csrf(lambda r: httpx.Response(200,text=body,headers={'content-type':'text/html'}))
        self.assertEqual(result['total_tokens'],0)
        self.assertNotIn(SECRET,json.dumps(result))

    def test_explicit_hint_and_boolean_attributes(self):
        result, _ = run_csrf(lambda r: httpx.Response(200,text='<input hidden type=hidden name=custom_guard value="'+SECRET+'">',headers={'content-type':'text/html'}),param_hint='custom_guard')
        self.assertEqual(result['total_tokens'],1)
        self.assertNotIn(SECRET,json.dumps(result))

    def test_blocked_failure_oversize_and_unsupported_method(self):
        for status in (403,429,302,503,200):
            with self.subTest(status=status):
                result, seen = run_csrf(lambda r: httpx.Response(status,content=b'x'*262145 if status==200 else SECRET.encode(),headers={'location':'https://outside.test/'}))
                self.assertFalse(result.get('coverage_complete',True))
                self.assertTrue(result.get('error'))
                self.assertNotIn(SECRET,json.dumps(result))
                self.assertEqual(len(seen),1)
        result, seen = run_csrf(lambda r: httpx.Response(200),method='post')
        self.assertEqual(seen,[])
        self.assertTrue(result.get('error'))

    def test_token_cap_repeated_cookie_headers_and_no_value_previews(self):
        body = '<input type=hidden name=csrf_token value="'+SECRET+'">'
        result, _ = run_csrf(lambda r: httpx.Response(200,text=body*101,headers={'content-type':'text/html'}))
        self.assertEqual(result['total_tokens'],100)
        self.assertFalse(result['coverage_complete'])
        self.assertTrue(result.get('token_limit_reached'))
        self.assertNotIn(SECRET,json.dumps(result))
        result, _ = run_csrf(lambda r: httpx.Response(200,text='<html></html>',headers=[('content-type','text/html'),('set-cookie','csrftoken='+SECRET+'; Expires=Wed, 01 Jan 2030 00:00:00 GMT'),('set-cookie','XSRF-TOKEN='+SECRET+'; Secure')]))
        self.assertEqual(result['total_tokens'],2)
        self.assertNotIn(SECRET,json.dumps(result))

    def test_transport_failure_and_processing_deadline_redacted(self):
        def fail(request):
            raise httpx.ReadTimeout(SECRET,request=request)
        result, seen = run_csrf(fail)
        self.assertEqual(len(seen),1)
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn(SECRET,json.dumps(result))
        module = importlib.import_module('cyber_tools.csrf_extract')
        with patch.object(module.time,'monotonic',side_effect=[0,11]):
            result, _ = run_csrf(lambda r: httpx.Response(200,text='body',headers={'content-type':'text/html'}))
        self.assertFalse(result['coverage_complete'])
        self.assertTrue(result.get('error'))


if __name__ == '__main__':
    unittest.main()
