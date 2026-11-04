"""Offline transport/workflow boundary regressions; no external fixtures."""
import asyncio
import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def module(name):
    return importlib.import_module("cyber_tools." + name)


class TransportWorkflowBoundaries(unittest.TestCase):
    def test_raw_invalid_types_and_sizes_do_not_encode_or_send(self):
        m = module("raw_replay")
        with patch.object(m.socket, "socket") as sock:
            for name in ("action", "raw_request", "target", "url", "method", "headers_json", "body"):
                args = {"action": "send", name: None}
                self.assertIn("error", json.loads(m.raw_replay(**args)))
            for args in ({"headers_json": "sensitive" * 150000}, {"raw_request": "\ud800"},
                         {"headers_json": '{"secret":'}, {"headers_json": "[" * 2000}):
                result = m.raw_replay("send", **args)
                self.assertIn("error", json.loads(result))
                self.assertNotIn("sensitive", result)
                self.assertNotIn("secret", result)
        sock.assert_not_called()

    def test_raw_response_secrets_withheld_without_changing_wire_bytes(self):
        m = module("raw_replay")
        secrets = ("cookie-secret", "body-secret", "query-secret", "fragment-secret", "user-secret", "pass-secret", "header-secret", "reason-secret")
        wire = b"GET /?query-secret HTTP/1.1\r\nHost: example.test\r\nAuthorization: header-secret\r\n\r\n"
        response = ("HTTP/1.1 302 reason-secret\r\nSet-Cookie: cookie-secret\r\nX-Token: header-secret\r\n"
                    "Location: https://user-secret:pass-secret@example.test/next?q=query-secret#fragment-secret\r\n"
                    "Content-Length: 11\r\n\r\nbody-secret").encode()
        sock = MagicMock()
        sock.recv.return_value = response
        with patch.object(m.socket, "socket", return_value=sock):
            output = m._do_send("example.test", 80, False, wire, True, 1)
        result = json.loads(output)
        sock.sendall.assert_called_once_with(wire)
        for secret in secrets:
            self.assertNotIn(secret, output)
        self.assertEqual(result["body_preview"], "")
        self.assertEqual(result["body_b64"], "")
        self.assertTrue(result["withheld"]["response_body"])
        self.assertEqual(result["redirect_location"], "https://example.test/next")

    def test_raw_previews_templates_and_errors_do_not_echo_secrets(self):
        m = module("raw_replay")
        target = "https://user-secret:pass-secret@example.test/path?q=query-secret#fragment-secret"
        with patch.object(m.socket, "socket", side_effect=OSError("transport-secret")):
            outputs = [m.raw_replay("preview", target=target),
                       m.raw_replay("preview", raw_request="GET /?query-secret HTTP/1.1\r\nCookie: cookie-secret\r\n\r\nbody-secret"),
                       m.raw_replay("template", target=target, headers_json='{"Authorization":"header-secret"}', body="body-secret"),
                       m.raw_replay("send", target=target, raw_request="x")]
        for output in outputs:
            self.assertNotIn("-secret", output)

    def test_raw_receive_total_deadline_is_cooperative(self):
        m = module("raw_replay")
        sock = MagicMock()
        sock.recv.return_value = b"partial"
        with patch.object(m.socket, "socket", return_value=sock), patch.object(m.time, "monotonic", side_effect=[0, .2, .8, 1.1]):
            result = json.loads(m._do_send("example.test", 80, False, b"x", False, 1))
        self.assertEqual(sock.recv.call_count, 1)
        self.assertIn("error", result)
        self.assertFalse(result["coverage_complete"])
        self.assertAlmostEqual(sock.settimeout.call_args.args[0], .8)
        sock.close.assert_called()

    def test_raw_invalid_timeout_never_opens_socket(self):
        m = module("raw_replay")
        with patch.object(m.socket, "socket") as sock:
            result = json.loads(m.raw_replay("send", "x", "example.test", timeout=0))
        self.assertIn("error", result)
        sock.assert_not_called()

    def test_raw_empty_response_is_error_and_socket_closed(self):
        m = module("raw_replay")
        sock = MagicMock()
        sock.recv.return_value = b""
        with patch.object(m.socket, "socket", return_value=sock):
            result = json.loads(m._do_send("example.test", 80, False, b"x", False, 1))
        self.assertIn("error", result)
        sock.close.assert_called()

    def test_raw_invalid_url_and_headers_never_send(self):
        m = module("raw_replay")
        with patch.object(m.socket, "socket") as sock:
            for kwargs in ({"url": "https://example.test:bad"}, {"url": "file:///etc/passwd"}, {"headers_json": "[]"}):
                self.assertIn("error", json.loads(m.raw_replay("replay", **kwargs)))
        sock.assert_not_called()

    def test_raw_read_budget_and_truncation(self):
        m = module("raw_replay")
        sock = MagicMock()
        sock.recv.return_value = b"x" * 4096
        with patch.object(m.socket, "socket", return_value=sock):
            result = json.loads(m._do_send("example.test", 80, False, b"x", False, 1))
        self.assertIn("error", result)
        self.assertEqual(sock.recv.call_count, 256)
        sock.close.assert_called()

    def test_raw_redirect_is_not_claimed_followed(self):
        m = module("raw_replay")
        sock = MagicMock()
        sock.recv.return_value = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
        with patch.object(m.socket, "socket", return_value=sock):
            result = json.loads(m._do_send("example.test", 80, False, b"x", True, 1))
        self.assertFalse(result.get("redirect_followed"))
        self.assertFalse(result["remote_effects_verified"])

    def test_cmd_delay_does_not_confirm_execution(self):
        m = module("cmd_oast_helper")
        with patch.object(m, "_send_payload", return_value={"error": "timeout"}), patch.object(m.time, "time", side_effect=[0, 6] * 5):
            result = json.loads(m.cmd_oast_helper("example.test", test_type="time"))
        self.assertFalse(result["verified"])
        self.assertFalse(result["exploitable"])

    def test_injection_generic_content_not_verified(self):
        m = module("injection_validator")
        for kind in ("nosql", "ldap", "cmd", "ssti"):
            with self.subTest(kind=kind):
                resp = MagicMock(status=200)
                resp.read.return_value = b"admin config self 49 ordinary welcome page"
                with patch.object(m, "guarded_urlopen", return_value=resp):
                    result = m._test_payload("http://example.test", "q", "test", "get", kind, "basic")
                self.assertFalse(result["verified"])
                self.assertLessEqual(resp.read.call_args.args[0], 1048577)
                resp.close.assert_called()

    def test_injection_public_entry_generic_and_blocked_responses_unverified(self):
        m = module("injection_validator")
        import io
        import urllib.error

        for blocked in (False, True):
            with self.subTest(blocked=blocked):
                responses = []

                def respond(request, **kwargs):
                    self.assertEqual(request.host, "example.test")
                    self.assertEqual(kwargs["timeout"], 15)
                    if blocked:
                        response = urllib.error.HTTPError(
                            request.full_url, 403, "private-error-secret", {},
                            io.BytesIO(b"admin config 49 private-body-secret"))
                        responses.append(response)
                        raise response
                    response = MagicMock(status=200)
                    response.read.return_value = b"admin config 49 ordinary content private-body-secret"
                    responses.append(response)
                    return response

                with patch.object(m, "guarded_urlopen", side_effect=respond) as request:
                    output = m.injection_validator("http://example.test", types="nosql,ldap")
                result = json.loads(output)
                expected = sum(len(payloads) for kind in ("nosql", "ldap")
                               for payloads in m.INJECTION_PAYLOADS[kind].values())
                self.assertEqual(request.call_count, expected)
                self.assertEqual(result["injection_types_tested"], ["nosql", "ldap"])
                self.assertEqual(result["vulnerable"], [])
                self.assertEqual(result["total_vulnerable"], 0)
                findings = [finding for techniques in result["results"].values()
                            for group in techniques.values() for finding in group]
                self.assertEqual(len(findings), expected)
                self.assertTrue(all(not f["verified"] and not f["remote_effects_verified"] for f in findings))
                if blocked:
                    self.assertTrue(all(f["http_status"] == 403 for f in findings))
                    self.assertTrue(all(response.closed for response in responses))
                else:
                    self.assertTrue(all(f["potential_indicator"] for f in findings))
                    for response in responses:
                        response.close.assert_called_once()
                self.assertNotIn("private-body-secret", output)
                self.assertNotIn("private-error-secret", output)

    def test_scanner_public_entry_failed_or_blocked_transport_is_incomplete(self):
        m = module("vuln_scanner")
        target = "https://example.test"
        for blocked in (False, True):
            with self.subTest(blocked=blocked):
                client = AsyncMock()
                if blocked:
                    client.get.return_value = m.httpx.Response(
                        403, text="private-body-secret", headers={"Set-Cookie": "private-cookie-secret"},
                        request=m.httpx.Request("GET", target))
                else:
                    client.get.side_effect = m.httpx.ConnectError("private-transport-secret")
                context = MagicMock()
                context.__aenter__ = AsyncMock(return_value=client)
                context.__aexit__ = AsyncMock(return_value=False)
                with patch.object(m, "GuardedAsyncClient", return_value=context) as factory, \
                        patch.object(m, "_epss_lookup", new=AsyncMock()) as intel, \
                        patch.object(m, "assess_headers", return_value={"status": "unknown"}) as assess, \
                        patch.object(m, "cve_records", return_value=[]) as records:
                    result = asyncio.run(m.scan_vulnerabilities(target))
                factory.assert_called_once_with(timeout=30.0, follow_redirects=True, verify=False)
                context.__aexit__.assert_awaited_once()
                intel.assert_not_awaited()
                self.assertEqual(assess.call_count, 2 if blocked else 1)
                self.assertEqual(records.call_count, 1 if blocked else 0)
                expected = 1 + len(m.PATH_CHECKS)
                for check in m.DEFAULT_CRED_CHECKS:
                    if check.get("protocol") != "redis":
                        expected += 1 + int(blocked and bool(check["username"]))
                self.assertEqual(client.get.await_count, expected)
                self.assertEqual(client.get.await_args_list[0].args, (target,))
                self.assertTrue(all(call.args[0].startswith(target) for call in client.get.await_args_list))
                self.assertEqual(result["requests_attempted"], expected)
                self.assertEqual(result["requests_failed"], 0 if blocked else expected)
                self.assertEqual(result["requests_succeeded"], expected if blocked else 0)
                self.assertEqual(result["execution_status"], "partial" if blocked else "error")
                self.assertFalse(result["coverage_complete"])
                self.assertIn("error", result)
                self.assertEqual(len(result["errors"]), expected)
                self.assertEqual(result["verified_count"], 0)
                self.assertNotIn("private-", json.dumps(result))

    def test_cache_body_difference_not_poisoning_proof(self):
        m = module("cache_poison_check")
        baseline = dict(success=True, status=200, headers={}, body_size=10)
        changed = dict(baseline, body_size=20, content_type="text/html")
        with patch.object(m, "_fetch", side_effect=[baseline] + [changed] * 7):
            result = json.loads(m.cache_poison_check("example.test", test_headers="X-Test"))
        self.assertFalse(result["poisonable"])
        self.assertTrue(result["potential_indicators"])

    def test_race_parallel_budget_rejected_before_client(self):
        m = module("race_condition")
        with patch.object(m.httpx, "AsyncClient") as client:
            result = asyncio.run(m.race_condition("example.test", parallel=0))
        self.assertIn("error", result)
        client.assert_not_called()

    def test_race_responses_cannot_confirm_remote_state(self):
        m = module("race_condition")
        result = m._analyze_race_responses([{"status": 200, "body": "ok"}] * 2 + [{"error": "timeout"}])
        self.assertFalse(result["race_detected"])
        self.assertEqual(result["error_count"], 1)

    def test_dork_budget_rejected_before_client(self):
        m = module("dork_scan")
        with patch.object(m.httpx, "AsyncClient") as client:
            result = asyncio.run(m.dork_scan("test", max_results=-1))
        self.assertIn("error", result[0])
        client.assert_not_called()

    def test_dork_blocked_and_failed_search_are_explicit(self):
        m = module("dork_scan")
        client = AsyncMock()
        client.post.return_value = MagicMock(status_code=429)
        result = asyncio.run(m._scan_ddg("test", 5, client))
        self.assertEqual(result[0]["status"], 429)
        client.get.side_effect = OSError("secret-token")
        result = asyncio.run(m._scan_bing("test", 5, client))
        self.assertFalse(result[0]["coverage_complete"])
        self.assertNotIn("secret-token", json.dumps(result))

    def test_fixture_ssl_rejected_before_start(self):
        with patch("tempfile.mkdtemp", return_value="/unused-mocked-fixture"):
            m = module("vulnerable_fixture")
        with patch.object(m, "_start_fixture") as start:
            result = json.loads(m.vulnerable_fixture("start", ssl=True))
        self.assertIn("error", result)
        start.assert_not_called()

    def test_fixture_error_result_is_not_e2e_pass(self):
        with patch("tempfile.mkdtemp", return_value="/unused-mocked-fixture"):
            m = module("vulnerable_fixture")
        opener = MagicMock()
        opener.open.side_effect = [MagicMock(status=200), OSError("failed")]
        with patch("urllib.request.build_opener", return_value=opener):
            result = json.loads(m._run_e2e("127.0.0.1", 9999, "xss", False))
        self.assertFalse(result["all_detected"])

    def test_fixture_stop_unmanaged_does_not_pkill(self):
        with patch("tempfile.mkdtemp", return_value="/unused-mocked-fixture"):
            m = module("vulnerable_fixture")
        with patch.dict(m.FIXTURE_PROCESS, {"pid": None, "port": None}), patch.object(m.subprocess, "run") as run:
            result = json.loads(m._stop_fixture("127.0.0.1", 9999))
        run.assert_not_called()
        self.assertNotEqual(result["status"], "stopped")

    def test_directory_budget_and_transport_errors_are_explicit(self):
        m = module("web_fuzz")
        with patch.object(m, "guarded_urlopen", side_effect=OSError("secret-token")) as request:
            result = m.dir_bust("example.test", ["x"] * 501, [""])
            request.assert_not_called()
            self.assertIn("error", result[0])
            result = m.dir_bust("example.test", ["x"], [""])
        self.assertIn("error", result[0])
        self.assertNotIn("secret-token", json.dumps(result))

    def test_oob_errors_are_not_empty_success(self):
        m = module("oob_test")
        client = AsyncMock()
        client.get.side_effect = m.httpx.ConnectError("secret-token")
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=client)
        context.__aexit__ = AsyncMock(return_value=False)
        with patch.object(m.httpx, "AsyncClient", return_value=context):
            result = asyncio.run(m.oob_test("example.test"))
        self.assertEqual(client.get.await_count, 12)
        self.assertFalse(result["coverage_complete"])
        self.assertFalse(result["remote_effects_verified"])
        self.assertNotIn("secret-token", json.dumps(result))

    def test_splitting_invalid_scheme_never_creates_client(self):
        m = module("http_request_splitting")
        with patch.object(m.httpx, "AsyncClient") as client:
            result = asyncio.run(m.http_request_splitting("file:///etc/passwd"))
        self.assertIn("error", result)
        client.assert_not_called()

    def test_smuggling_connection_failures_stay_unverified(self):
        m = module("smuggling_check")
        with patch.object(m.asyncio, "open_connection", new=AsyncMock(side_effect=OSError("secret-token"))):
            result = asyncio.run(m.smuggling_check("example.test"))
        self.assertFalse(result["coverage_complete"])
        self.assertFalse(result["smuggling_vulnerable"])
        self.assertNotIn("secret-token", json.dumps(result))

    def test_scanner_budget_and_non_http_failure_accounting(self):
        m = module("vuln_scanner")
        client = AsyncMock()
        client.get.side_effect = ValueError("secret-token")
        observed = m._ObservedClient(client)
        with self.assertRaises(ValueError):
            asyncio.run(observed.get("http://example.test"))
        self.assertEqual(observed.errors, [{"kind": "ValueError"}])
        observed.attempted = 500
        with self.assertRaises(m.httpx.RequestError):
            asyncio.run(observed.get("http://example.test"))
        self.assertEqual(client.get.await_count, 1)


if __name__ == "__main__":
    unittest.main()
