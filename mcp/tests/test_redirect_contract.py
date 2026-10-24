"""Offline redirect behavior and Python transport inventory (never opens sockets)."""
import asyncio
import ast
import io
import json
from email.message import Message
from pathlib import Path
import socket
import sys
import unittest
import urllib.request
import urllib.response
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools import http_guard
from cyber_tools.engagement_gate import engagement_context, engagement_gate, new_engagement

ROOT = Path(__file__).resolve().parents[1] / "cyber_tools"
# Fixed public intelligence/search/identity services, not active target clients.
INTELLIGENCE = {
    "exploit_db.py", "ghdb_search.py", "dork_scan.py", "social_osint.py",
    "telegram_osint.py", "subdomain_enum.py",
}
# Fixed intelligence APIs and explicitly configured reporting integrations.
# The generated fixture's vulnerable SSRF server is a string, not a client call
# in this AST; its self-test client's redirects are disabled and tested below.
RAW_URLLIB = {
    "google_dork.py", "people_osint.py", "vuln_db.py",
    "github_issue.py", "jira_create.py", "notify_webhook.py",
}


class RedirectContract(unittest.TestCase):
    def setUp(self):
        self.context = engagement_context(new_engagement())
        self.context.__enter__()
        engagement_gate("init", target="fixture.test")
        engagement_gate("authorize", confirmation="yes")
        self.network = patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden"))
        self.network.start()
        self.network_ex = patch.object(socket.socket, "connect_ex", side_effect=AssertionError("network forbidden"))
        self.network_ex.start()
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden"))
        self.dns.start()

    def tearDown(self):
        self.network.stop()
        self.network_ex.stop()
        self.dns.stop()
        self.context.__exit__(None, None, None)

    def clients(self):
        self.assertTrue(hasattr(http_guard, "GuardedClient"), "missing guarded sync HTTPX client")
        self.assertTrue(hasattr(http_guard, "GuardedAsyncClient"), "missing guarded async HTTPX client")
        return http_guard.GuardedClient, http_guard.GuardedAsyncClient

    def run_clients(self, handler, exercise, **options):
        sync, async_ = self.clients()
        with sync(transport=httpx.MockTransport(handler), **options) as client:
            exercise(client)
        async def run():
            async with async_(transport=httpx.MockTransport(handler), **options) as client:
                await exercise(client, asynchronous=True)
        asyncio.run(run())

    def test_external_redirect_never_sends_credentials_or_body(self):
        for code in (301, 302, 303, 307, 308):
            for destination in ("https://outside.test/stolen", "//outside.test/stolen",
                                "https://fixture.test@outside.test/stolen"):
                with self.subTest(code=code, destination=destination):
                    seen = []
                    def handler(request):
                        seen.append(request)
                        return httpx.Response(code, headers={"location": destination})
                    def exercise(client, asynchronous=False):
                        async def async_run():
                            with self.assertRaises(httpx.RequestError):
                                await client.post("https://fixture.test/start", content=b"password=secret",
                                                  headers={"Authorization": "Bearer secret", "Cookie": "sid=secret"})
                        if asynchronous:
                            return async_run()
                        with self.assertRaises(httpx.RequestError):
                            client.post("https://fixture.test/start", content=b"password=secret",
                                        headers={"Authorization": "Bearer secret", "Cookie": "sid=secret"})
                    self.run_clients(handler, exercise, follow_redirects=True)
                    self.assertEqual([str(r.url.host) for r in seen], ["fixture.test", "fixture.test"])

    def test_307_308_preserve_same_origin_body_headers_and_history(self):
        for code in (307, 308):
            with self.subTest(code=code):
                def handler(request):
                    if request.url.path == "/start":
                        return httpx.Response(code, headers={"location": "/finish"})
                    self.assertEqual(request.method, "POST")
                    self.assertEqual(request.content, b"secret=body")
                    self.assertEqual(request.headers["authorization"], "Bearer token")
                    self.assertEqual(request.headers["x-test"], "retained")
                    return httpx.Response(200)
                def check(response):
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(len(response.history), 1)
                def exercise(client, asynchronous=False):
                    kwargs = dict(content=b"secret=body", headers={"Authorization": "Bearer token", "X-Test": "retained"})
                    async def async_run():
                        check(await client.post("https://fixture.test/start", **kwargs))
                    if asynchronous:
                        return async_run()
                    check(client.post("https://fixture.test/start", **kwargs))
                self.run_clients(handler, exercise, follow_redirects=True)

    def test_multihop_checks_every_destination_with_per_request_override(self):
        seen = []
        def handler(request):
            seen.append(str(request.url))
            location = "/second" if request.url.path == "/start" else "https://outside.test/third"
            return httpx.Response(302, headers={"location": location})
        def exercise(client, asynchronous=False):
            async def async_run():
                with self.assertRaises(httpx.RequestError):
                    await client.get("https://fixture.test/start", follow_redirects=True)
            if asynchronous:
                return async_run()
            with self.assertRaises(httpx.RequestError):
                client.get("https://fixture.test/start", follow_redirects=True)
        self.run_clients(handler, exercise)
        self.assertEqual(seen, ["https://fixture.test/start", "https://fixture.test/second"] * 2)

    def test_disabled_redirect_is_observable_but_next_request_is_guarded(self):
        seen = []
        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(302, headers={"location": "https://outside.test/"})
        def exercise(client, asynchronous=False):
            async def async_run():
                response = await client.get("https://fixture.test/")
                self.assertEqual(response.status_code, 302)
                with self.assertRaises(httpx.RequestError):
                    await client.send(response.next_request)
            if asynchronous:
                return async_run()
            response = client.get("https://fixture.test/")
            self.assertEqual(response.status_code, 302)
            with self.assertRaises(httpx.RequestError):
                client.send(response.next_request)
        self.run_clients(handler, exercise)
        self.assertEqual(len(seen), 2)

    def test_revoked_authorization_blocks_same_host_redirect(self):
        seen = []
        def handler(request):
            seen.append(request)
            engagement_gate("init", target="fixture.test")
            return httpx.Response(302, headers={"location": "/next"})
        def exercise(client, asynchronous=False):
            async def async_run():
                with self.assertRaises(httpx.RequestError):
                    await client.get("https://fixture.test/")
            if asynchronous:
                return async_run()
            with self.assertRaises(httpx.RequestError):
                client.get("https://fixture.test/")
        self.run_clients(handler, exercise, follow_redirects=True)
        self.assertEqual(len(seen), 2)

    def test_auto_exploit_all_retained_phases_use_redirect_guard(self):
        import importlib
        module = importlib.import_module("cyber_tools.auto_exploit")
        seen = []
        def synthetic_open(handler, request):
            seen.append(request.full_url)
            headers = Message()
            headers["Location"] = "http://outside.test/stolen"
            response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "Found"
            return response
        with patch.object(urllib.request.HTTPHandler, "http_open", synthetic_open):
            module._detect("http://fixture.test/", "q")
            for kind in ("sqli", "xss", "lfi", "ssrf", "open_redirect"):
                module._legacy_verify("http://fixture.test/", kind, "q")
                module._exploit("http://fixture.test/", kind, "q")
        self.assertTrue(seen)
        self.assertTrue(all(url.startswith("http://fixture.test/") for url in seen), seen)

    def test_bulk_workers_retain_session_scope_for_allowed_redirects(self):
        import importlib
        module = importlib.import_module("cyber_tools.bulk_scan")
        real_client = httpx.Client
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/finish"})
            return httpx.Response(200, text="<title>allowed</title>")
        with patch("cyber_tools.http_guard.httpx.Client", side_effect=lambda **kw:
                   real_client(transport=httpx.MockTransport(handler), **kw)):
            result = json.loads(module.bulk_scan("fixture.test", "http_probe"))
        self.assertEqual(result["results"][0]["result"].get("https", {}).get("status"), 200)

    def test_manual_open_redirect_chain_does_not_contact_external_location(self):
        import importlib
        module = importlib.import_module("cyber_tools.open_redirect")
        real_client = httpx.AsyncClient
        seen = []
        def handler(request):
            seen.append(str(request.url.host))
            return httpx.Response(302, headers={"location": "https://evil.com/stolen"})
        with patch.object(module, "REDIRECT_PARAMS", ["url"]), patch.object(module, "PAYLOADS", ["https://evil.com"]), patch.object(
            module.httpx, "AsyncClient", side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)
        ):
            result = asyncio.run(module.open_redirect("https://fixture.test/"))
        self.assertTrue(seen)
        self.assertNotIn("evil.com", seen)
        self.assertTrue(result["findings"])

    def test_stored_xss_manual_redirect_does_not_contact_external_location(self):
        import importlib
        module = importlib.import_module("cyber_tools.xss_detect")
        real_client = httpx.AsyncClient
        seen = []
        def handler(request):
            seen.append(str(request.url.host))
            if request.method == "POST":
                return httpx.Response(302, headers={"location": "https://outside.test/stolen"})
            return httpx.Response(200, text="nothing stored")
        with patch.object(module, "STORED_PATHS", ["/comment"]), patch.object(
            module.httpx, "AsyncClient", side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)
        ):
            asyncio.run(module.xss_detect("https://fixture.test/", preset="staging-deep"))
        self.assertTrue(seen)
        self.assertNotIn("outside.test", seen)

    def test_fixture_e2e_observes_redirect_without_following_it(self):
        import importlib
        module = importlib.import_module("cyber_tools.vulnerable_fixture")
        seen = []
        def synthetic_open(handler, request):
            seen.append(request.full_url)
            headers = Message()
            code = 302 if "/redirect?" in request.full_url else 200
            if code == 302:
                headers["Location"] = "https://evil.com"
            response = urllib.response.addinfourl(io.BytesIO(b"ok"), headers, request.full_url, code)
            response.msg = "Synthetic"
            return response
        with patch.object(urllib.request.HTTPHandler, "http_open", synthetic_open), patch.object(
            urllib.request.HTTPSHandler, "https_open", synthetic_open
        ):
            result = json.loads(module._run_e2e("fixture.test", 9999, "open_redirect", False))
        self.assertEqual(len(seen), 2)
        self.assertEqual(result["results"]["open_redirect"]["location"], "https://evil.com")
        self.assertTrue(result["results"]["open_redirect"]["detected"])

    def test_httpx_cross_origin_auth_stripping_and_user_hooks_retained(self):
        events = []
        def handler(request):
            if request.url.host == "fixture.test":
                return httpx.Response(302, headers={"location": "https://sub.fixture.test/"})
            self.assertNotIn("authorization", request.headers)
            self.assertNotIn("cookie", request.headers)
            return httpx.Response(200)
        sync, async_ = self.clients()
        def hook(request):
            events.append(request.url.host)
        async def async_hook(request):
            hook(request)
        with sync(transport=httpx.MockTransport(handler), event_hooks={"request": [hook]}, follow_redirects=True) as client:
            self.assertEqual(client.get("https://fixture.test/", headers={"Authorization": "secret", "Cookie": "sid=secret"}).status_code, 200)
        async def run():
            async with async_(transport=httpx.MockTransport(handler), event_hooks={"request": [async_hook]}, follow_redirects=True) as client:
                self.assertEqual((await client.get("https://fixture.test/", headers={"Authorization": "secret", "Cookie": "sid=secret"})).status_code, 200)
        asyncio.run(run())
        self.assertEqual(events, ["fixture.test", "sub.fixture.test"] * 2)

    def test_urllib_multihop_rejects_external_without_sending_auth(self):
        seen = []
        def synthetic_open(handler, request):
            seen.append(request)
            headers = Message()
            headers["Location"] = "/next" if request.full_url.endswith("/start") else "http://outside.test/stolen"
            response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, 302)
            response.msg = "Found"
            return response
        with patch.object(urllib.request.HTTPHandler, "http_open", synthetic_open):
            with self.assertRaises(urllib.error.HTTPError) as error:
                http_guard.guarded_urlopen(urllib.request.Request("http://fixture.test/start", headers={"Authorization": "secret", "Cookie": "sid=secret"}))
        self.assertIn(http_guard.REASON, str(error.exception))
        self.assertEqual([r.full_url for r in seen], ["http://fixture.test/start", "http://fixture.test/next"])

    def test_urllib_307_308_outside_scope_post_never_replays_body(self):
        for code in (307, 308):
            with self.subTest(code=code):
                seen = []
                def synthetic_open(handler, request):
                    seen.append(request)
                    headers = Message()
                    headers["Location"] = "http://outside.test/stolen"
                    response = urllib.response.addinfourl(io.BytesIO(b""), headers, request.full_url, code)
                    response.msg = "Redirect"
                    return response
                with patch.object(urllib.request.HTTPHandler, "http_open", synthetic_open):
                    with self.assertRaises(urllib.error.HTTPError):
                        http_guard.guarded_urlopen(urllib.request.Request("http://fixture.test/", data=b"password=secret"))
                self.assertEqual(len(seen), 1)

    def test_inventory_no_unclassified_redirect_capable_python_clients(self):
        violations = []
        for path in ROOT.glob("*.py"):
            if path.name == "http_guard.py":
                continue
            tree = ast.parse(path.read_text())
            parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = ast.unparse(node.func)
                if name == "urllib.request.urlopen" and path.name not in RAW_URLLIB:
                    violations.append(f"{path.name}:{node.lineno}: raw urlopen")
                if name == "urllib.request.build_opener" and path.name not in RAW_URLLIB:
                    if not any(handler in ast.unparse(node) for handler in
                               ("ScopeClampedRedirectHandler", "_NoRedirect()", "NoRedirectHandler")):
                        violations.append(f"{path.name}:{node.lineno}: unguarded opener")
                if path.name not in INTELLIGENCE:
                    for keyword in node.keywords:
                        if keyword.arg == "follow_redirects" and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False):
                            guarded = name in {"GuardedAsyncClient", "GuardedClient", "guarded_httpx_get"}
                            ancestor = parents.get(node)
                            while ancestor is not None and not guarded:
                                if isinstance(ancestor, (ast.With, ast.AsyncWith)):
                                    for item in ancestor.items:
                                        if (isinstance(item.context_expr, ast.Call) and
                                            ast.unparse(item.context_expr.func) in {"GuardedAsyncClient", "GuardedClient"} and
                                            item.optional_vars is not None and
                                            name.startswith(ast.unparse(item.optional_vars) + ".")):
                                            guarded = True
                                ancestor = parents.get(ancestor)
                            if not guarded:
                                violations.append(f"{path.name}:{node.lineno}: unguarded HTTPX redirects")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
