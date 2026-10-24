"""Bounded remote PHP2SHELL identification: offline fixtures, never load probes."""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PHPINFO = '''<html><h1 class="p">PHP Version 8.4.26</h1><table>
<tr><td class="e">Server API</td><td class="v">FPM/FastCGI</td></tr>
<tr><td class="e">memory_limit</td><td class="v">128M</td><td class="v">256M</td></tr>
<tr><td>session.upload_progress.enabled</td><td>On</td><td>On</td></tr>
<tr><td>post_max_size</td><td>8M</td><td>8M</td></tr>
<tr><td>SECRET_TOKEN</td><td>do-not-export-this</td></tr>
</table></html>'''


class TestPhp2ShellRemote(unittest.IsolatedAsyncioTestCase):
    async def run_scan(self, handler, **kwargs):
        # Delayed import allows explicit assertions on the missing feature first.
        from importlib.util import find_spec
        self.assertIsNotNone(find_spec("cyber_tools.php2shell_remote"),
                             "Dedicated bounded remote scanner is not implemented")
        from cyber_tools.php2shell_remote import scan_php2shell
        seen = []

        def record(request):
            seen.append(request)
            return handler(request)

        real_client = httpx.AsyncClient
        with patch("cyber_tools.php2shell_remote.httpx.AsyncClient", side_effect=lambda **kw:
                   real_client(transport=httpx.MockTransport(record), **kw)):
            result = await scan_php2shell("https://example.test/", **kwargs)
        json.dumps(result)
        return result, seen

    async def test_phpinfo_after_hidden_banner_with_allowlisted_config(self):
        def handler(request):
            if request.url.path == "/info.php":
                return httpx.Response(200, text=PHPINFO)
            return httpx.Response(404, text="Missing")
        result, seen = await self.run_scan(handler)
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")
        self.assertEqual(result["php2shell"]["version"], "8.4.26")
        self.assertEqual(result["php2shell"]["confidence"], "HIGH")
        self.assertEqual(result["php2shell"]["sapi"], "FPM/FastCGI")
        self.assertTrue(result["php2shell"]["worker_persistent"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(all(f["confidence"] == "HIGH" for f in result["findings"]))
        config = result["configuration"][0]
        self.assertEqual(config["source"], "https://example.test/info.php")
        self.assertEqual(config["values"]["session.upload_progress.enabled"], ["On", "On"])
        self.assertEqual(config["values"]["Server API"], ["FPM/FastCGI"])
        self.assertNotIn("do-not-export-this", json.dumps(result))
        self.assertNotIn("SECRET_TOKEN", json.dumps(result))
        self.assertTrue(all(r.method in ("GET", "HEAD", "OPTIONS") and not r.content for r in seen))
        self.assertLessEqual(len(seen), 8)

    async def test_multiple_banner_formats(self):
        for headers in ({"X-PHP-Version": "8.4.26"},
                        {"X-Powered-By": "PHP 8.4.26"},
                        {"Server": "Apache PHP/8.4.26"}):
            with self.subTest(headers=headers):
                result, _ = await self.run_scan(lambda r: httpx.Response(200, headers=headers), phpinfo_paths=False)
                self.assertEqual(result["php2shell"]["status"], "potentially_affected")
                self.assertEqual(result["php2shell"]["confidence"], "MEDIUM")

    async def test_head_and_options_can_fill_banner_gap(self):
        for method in ("HEAD", "OPTIONS"):
            with self.subTest(method=method):
                def handler(request):
                    return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.27"} if request.method == method else {})
                result, seen = await self.run_scan(handler, phpinfo_paths=False)
                self.assertEqual(result["php2shell"]["status"], "not_affected_by_version")
                self.assertIn(method, [r.method for r in seen])

    async def test_php_presence_is_not_exact_version_or_safe(self):
        result, _ = await self.run_scan(lambda r: httpx.Response(200,
            headers={"Set-Cookie": "PHPSESSID=private-session"}, text='<a href="index.php">Go</a>'))
        self.assertTrue(result["php_detected"])
        self.assertEqual(result["coverage"], "php_detected_version_hidden")
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertNotIn("private-session", json.dumps(result))

    async def test_arbitrary_version_text_and_composer_are_not_runtime_evidence(self):
        body = '<h1>Documentation</h1><p>PHP Version 8.4.26</p>{"require":{"php":"^8.4"}}'
        result, _ = await self.run_scan(lambda r: httpx.Response(200, text=body))
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertFalse(result["php2shell"]["observed_versions"])

    async def test_conflicting_phpinfo_and_header_remain_unknown(self):
        def handler(request):
            return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.27"},
                                  text=PHPINFO if request.url.path == "/phpinfo.php" else "Home")
        result, _ = await self.run_scan(handler)
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertEqual(result["coverage"], "conflicting_evidence")
        self.assertEqual(set(result["php2shell"]["observed_versions"]), {"8.4.26", "8.4.27"})
        self.assertEqual(result["php2shell"]["confidence"], "LOW")
        self.assertEqual(result["findings"], [])

    async def test_disabled_upload_progress_does_not_mean_fixed(self):
        result, _ = await self.run_scan(lambda r: httpx.Response(200, text=PHPINFO.replace(">On<", ">Off<")))
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")

    async def test_serialize_handler_collected_for_session_runtime_switch_cve(self):
        info = PHPINFO.replace(
            "<tr><td>post_max_size</td>",
            '<tr><td>session.serialize_handler</td><td>php</td><td>php</td></tr>\n<tr><td>post_max_size</td>')
        def handler(request):
            if request.url.path == "/info.php":
                return httpx.Response(200, text=info)
            return httpx.Response(404, text="Missing")
        result, _ = await self.run_scan(handler)
        config = result["configuration"][0]
        self.assertEqual(config["values"]["session.serialize_handler"], ["php", "php"])
        self.assertEqual(config["values"]["session.upload_progress.enabled"], ["On", "On"])
        # PHP2SHELL verdict is driven by version only; the session switch cannot be
        # observed remotely and must not change the CVE-2026-109618/109619 assessment.
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")

    async def test_limitations_flag_runtime_serialize_switch_context(self):
        result, _ = await self.run_scan(
            lambda r: httpx.Response(200, headers={"X-Powered-By": "PHP/8.3.35"}), phpinfo_paths=False)
        text = " ".join(result["limitations"])
        self.assertIn("session.serialize_handler", text)
        self.assertIn("ini_set", text)
        self.assertIn("2026-10-23", text)

    async def test_access_blocked_reported_after_bounded_checks(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(403, headers={"Server": "hcdn"}))
        self.assertEqual(result["coverage"], "access_blocked")
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertGreater(len(seen), 1)
        self.assertLessEqual(len(seen), 8)

    async def test_external_redirect_never_followed(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(302, headers={"Location": "https://outside.test/"}))
        self.assertTrue(all(r.url.host == "example.test" for r in seen))
        self.assertEqual(result["coverage"], "redirect_out_of_scope")
        self.assertTrue(result["redirects_not_followed"])

    async def test_same_origin_redirect_consumes_budget(self):
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={"Location": "/home"})
            return httpx.Response(200, headers={"X-PHP-Version": "8.4.27"})
        result, seen = await self.run_scan(handler, max_requests=2, phpinfo_paths=False)
        self.assertEqual(len(seen), 2)
        self.assertEqual(result["php2shell"]["status"], "not_affected_by_version")

    async def test_rate_limit_stops_immediately(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(429))
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["coverage"], "rate_limited")

    async def test_request_budget_and_missing_evidence(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(404), max_requests=2)
        self.assertEqual(len(seen), 2)
        self.assertEqual(result["coverage"], "budget_exhausted")

    async def test_network_error_is_unknown(self):
        def handler(request):
            raise httpx.ConnectError("offline", request=request)
        result, seen = await self.run_scan(handler)
        self.assertEqual(result["coverage"], "network_error")
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertEqual(len(seen), 1)

    async def test_large_response_is_truncated_and_never_exported(self):
        result, _ = await self.run_scan(lambda r: httpx.Response(200, text="x" * 400_000), max_requests=1)
        self.assertTrue(result["requests"][0]["body_truncated"])
        self.assertLess(len(json.dumps(result)), 15_000)

    async def test_invalid_target_and_limits_send_nothing(self):
        from cyber_tools.php2shell_remote import scan_php2shell
        for target, kwargs in (("https://user:password@example.test/", {}),
                               ("ftp://example.test/", {}),
                               ("https://example.test:0/", {}),
                               ("https://example.test/", {"max_requests": 13}),
                               ("https://example.test/", {"timeout": 0}),
                               ("https://example.test/#fragment", {})):
            with patch("cyber_tools.php2shell_remote.httpx.AsyncClient") as client:
                result = await scan_php2shell(target, **kwargs)
            self.assertEqual(result["coverage"], "invalid_target")
            client.assert_not_called()

    async def test_eol_version_is_unclassified_not_hidden(self):
        result, _ = await self.run_scan(lambda r: httpx.Response(200,
            headers={"X-Powered-By": "PHP/7.4.33"}), phpinfo_paths=False)
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertEqual(result["coverage"], "version_unclassified")
        self.assertEqual(result["php2shell"]["observed_versions"], ["7.4.33"])

    async def test_redirect_loop_is_bounded(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(302, headers={"Location": "/"}), max_requests=5)
        self.assertLessEqual(len(seen), 5)
        self.assertTrue(result["redirects_not_followed"])

    async def test_whole_scan_deadline(self):
        real_wait_for = asyncio.wait_for
        async def short_deadline(coro, timeout):
            # Shorten only the scan deadline, leaving request deadlines intact.
            return await real_wait_for(coro, 0.05 if timeout == 30 else timeout)
        with patch("cyber_tools.php2shell_remote.asyncio.wait_for", new=short_deadline):
            import cyber_tools.php2shell_remote as module
            real_client = httpx.AsyncClient
            async def slow(request):
                await asyncio.sleep(0.03)
                return httpx.Response(200)
            with patch.object(module.httpx, "AsyncClient", side_effect=lambda **kw:
                              real_client(transport=httpx.MockTransport(slow), **kw)):
                result = await module.scan_php2shell("https://example.test/", phpinfo_paths=False)
        self.assertEqual(result["coverage"], "timeout")
        self.assertEqual(result["php2shell"]["status"], "unknown")
        self.assertGreaterEqual(len(result["requests"]), 2)
        self.assertFalse(any(r.get("error") == "request_timeout" for r in result["requests"]))

    async def test_dedicated_mcp_tool_registration_and_invocation(self):
        from fastmcp import Client
        from server import mcp
        real_client = httpx.AsyncClient
        async with Client(mcp) as client:
            await client.call_tool("engagement_gate", {"action": "init", "target": "example.test"})
            await client.call_tool("engagement_gate", {"action": "authorize", "confirmation": "yes"})
            tools = {tool.name: tool for tool in await client.list_tools()}
            self.assertTrue("php2shell_scan" in tools, "Dedicated identification MCP tool is missing")
            with patch("cyber_tools.php2shell_remote.httpx.AsyncClient", side_effect=lambda **kw:
                       real_client(transport=httpx.MockTransport(lambda r: httpx.Response(403)), **kw)):
                response = await client.call_tool("php2shell_scan", {"target": "https://example.test/"})
            result = json.loads(response.content[0].text)
            self.assertEqual(result["coverage"], "access_blocked")
            self.assertLessEqual(len(result["requests"]), 8)

    async def test_unexpected_compression_is_not_decompressed(self):
        import gzip
        compressed = gzip.compress(b"x" * 1_000_000)
        def handler(request):
            return httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(compressed))
        with patch("httpx._decoders.GZipDecoder.decode", side_effect=AssertionError("must not decompress")):
            result, seen = await self.run_scan(handler, max_requests=1)
        self.assertEqual(seen[0].headers["accept-encoding"], "identity")
        self.assertEqual(result["requests"][0].get("body_skipped"), "unsupported_content_encoding")
        self.assertEqual(result["php2shell"]["status"], "unknown")

    async def test_report_urls_do_not_export_redirect_credentials_or_tokens(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(302, headers={
            "Location": "https://alice:private-password@example.test/reset?token=private-token#private-fragment"}))
        report = json.dumps(result)
        for secret in ("private-password", "private-token", "private-fragment", "alice"):
            self.assertNotIn(secret, report)
        self.assertFalse(any(r.url.path == "/reset" for r in seen))

    async def test_same_origin_redirect_queries_used_but_not_published(self):
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={"Location": "/home?token=private-token"})
            return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"})
        result, seen = await self.run_scan(handler, max_requests=2, phpinfo_paths=False)
        self.assertTrue(any(r.url.query for r in seen))
        self.assertNotIn("private-token", json.dumps(result))

    async def test_explicit_zero_port_redirect_is_not_same_origin(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(302, headers={"Location": "https://example.test:0/"}))
        self.assertTrue(all(r.url.port != 0 for r in seen))
        self.assertTrue(result["redirects_not_followed"])

    async def test_timeout_bounds_complete_slow_stream_not_just_network_waits(self):
        from cyber_tools.php2shell_remote import scan_php2shell
        class SlowStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(10):
                    await asyncio.sleep(0.03)
                    yield b"x"
        real_client = httpx.AsyncClient
        with patch("cyber_tools.php2shell_remote.httpx.AsyncClient", side_effect=lambda **kw:
                   real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=SlowStream())), **kw)):
            started = asyncio.get_running_loop().time()
            result = await scan_php2shell("https://example.test/", timeout=0.1, max_requests=1)
            elapsed = asyncio.get_running_loop().time() - started
        self.assertLess(elapsed, 0.25)
        self.assertEqual(result["coverage"], "timeout")
        self.assertEqual(result["requests"][0]["error"], "request_timeout")

    async def test_error_page_disclosure_is_high_confidence(self):
        body = "PHP Fatal error:  Uncaught Error in /var/www/app.php on line 12\nPHP/8.4.26"
        result, _ = await self.run_scan(lambda r: httpx.Response(200, text=body), phpinfo_paths=False)
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")
        self.assertEqual(result["php2shell"]["version"], "8.4.26")
        self.assertEqual(result["php2shell"]["confidence"], "HIGH")
        self.assertTrue(any(e["source"] == "body:errorpage" for e in result["php2shell"]["evidence"]))

    async def test_proxy_lowers_header_confidence(self):
        result, _ = await self.run_scan(
            lambda r: httpx.Response(200, headers={
                "X-Powered-By": "PHP/8.4.26", "Server": "cloudflare", "CF-Ray": "abc-SJC",
            }), phpinfo_paths=False)
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")
        self.assertEqual(result["php2shell"]["confidence"], "LOW")
        self.assertIn("Cloudflare", result["php2shell"]["proxy"])
        self.assertTrue(all(f["confidence"] == "LOW" for f in result["findings"]))

    async def test_deep_version_reaches_expanded_phpinfo_path(self):
        def handler(request):
            if request.url.path == "/test.php":
                return httpx.Response(200, text=PHPINFO)
            return httpx.Response(404, text="Missing")
        result, seen = await self.run_scan(handler, deep_version=True, max_requests=12)
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")
        self.assertEqual(result["php2shell"]["confidence"], "HIGH")
        self.assertTrue(any(r.url.path == "/test.php" for r in seen))
        # Default allowlist must not request deep-only paths when flag is off.
        shallow, shallow_seen = await self.run_scan(handler, deep_version=False, max_requests=12)
        self.assertFalse(any(r.url.path == "/test.php" for r in shallow_seen))
        self.assertEqual(shallow["php2shell"]["status"], "unknown")

    async def test_rate_limit_preserves_unknown_not_safe(self):
        result, seen = await self.run_scan(lambda r: httpx.Response(429, headers={"X-Powered-By": "PHP/8.4.26"}))
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["coverage"], "rate_limited")
        # First response still contributes evidence, but 429 stops further discovery.
        self.assertEqual(result["php2shell"]["status"], "potentially_affected")
        self.assertEqual(result["php2shell"]["confidence"], "MEDIUM")

    async def test_local_flag_default_off_and_optional_host_probe(self):
        result, _ = await self.run_scan(lambda r: httpx.Response(404), max_requests=1)
        self.assertIsNone(result["local"])
        with patch("cyber_tools.php2shell.shutil.which", return_value="/usr/bin/php"), \
             patch("cyber_tools.php2shell.subprocess.run") as run:
            run.side_effect = [
                type("P", (), {"stdout": "PHP 8.4.26 (cli)\n", "stderr": ""})(),
                type("P", (), {"stdout": "Server API => Command Line Interface\nmemory_limit => 128M => 128M\npost_max_size => 8M => 8M\n", "stderr": ""})(),
            ]
            local_result, _ = await self.run_scan(lambda r: httpx.Response(404), max_requests=1, local=True)
        self.assertFalse(local_result["local"]["skipped"])
        self.assertEqual(local_result["local"]["php_version"], "8.4.26")
        self.assertEqual(local_result["local"]["php2shell"]["status"], "potentially_affected")

    async def test_local_sandbox_block_is_skipped_with_todo(self):
        with patch("cyber_tools.php2shell.shutil.which", return_value="/usr/bin/php"), \
             patch("cyber_tools.php2shell.subprocess.run", side_effect=PermissionError("blocked")):
            result, _ = await self.run_scan(lambda r: httpx.Response(404), max_requests=1, local=True)
        self.assertTrue(result["local"]["skipped"])
        self.assertIn("TODO", result["local"]["reason"])


if __name__ == "__main__":
    unittest.main()
