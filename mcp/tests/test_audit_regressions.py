"""Offline negative controls reproduced during the local source audit."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastmcp import Client

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools import engagement_gate as gate
from cyber_tools.idor_access_validation import idor_access_validation
from cyber_tools.retest_vuln import retest_vuln
from cyber_tools.vuln_validate import vuln_validate


class TestScopeRegressions(unittest.TestCase):
    def setUp(self):
        self.saved = copy.deepcopy(gate.ENGAGEMENT)
        gate.engagement_gate("init", scope_json=json.dumps({"domains": ["allowed.test"]}))
        gate.engagement_gate("authorize", confirmation="yes")

    def tearDown(self):
        gate.ENGAGEMENT.clear()
        gate.ENGAGEMENT.update(self.saved)

    def validate(self, target):
        return json.loads(gate.engagement_gate("validate", target=target))["validated"]

    def test_domain_substrings_and_url_paths_are_not_in_scope(self):
        for target in ["https://allowed.test.outside.test/", "https://outside.test/allowed.test",
                       "https://allowed.test@outside.test/"]:
            with self.subTest(target=target):
                self.assertFalse(self.validate(target))

    def test_real_domain_and_subdomain_are_in_scope(self):
        self.assertTrue(self.validate("https://ALLOWED.test:8443/"))
        self.assertTrue(self.validate("https://api.allowed.test/"))

    def test_cidr_uses_network_membership(self):
        gate.engagement_gate("init", scope_json=json.dumps({"networks": ["192.0.2.0/24"]}))
        gate.engagement_gate("authorize", confirmation="yes")
        self.assertTrue(self.validate("http://192.0.2.8:8080/"))
        self.assertFalse(self.validate("http://198.51.100.1/192.0.2.0/24"))

    def test_new_engagement_drops_old_scope_and_authorization(self):
        gate.engagement_gate("init", target="new.test")
        state = json.loads(gate.engagement_gate("status"))
        self.assertFalse(state["authorized"])
        self.assertEqual(state["scope"]["domains"], ["new.test"])

    def test_invalid_scope_does_not_keep_authorization(self):
        result = json.loads(gate.engagement_gate("init", scope_json="not json"))
        self.assertIn("error", result)
        self.assertFalse(json.loads(gate.engagement_gate("status"))["authorized"])

    def test_per_call_scope_cannot_widen_authorized_scope(self):
        result = json.loads(gate.engagement_gate("validate", target="outside.test",
                            scope_json=json.dumps({"domains": ["outside.test"]})))
        self.assertFalse(result["validated"])


class TestMcpScopeDispatch(unittest.IsolatedAsyncioTestCase):
    async def authorize(self, client):
        await client.call_tool("engagement_gate", {"action": "init", "target": "allowed.test"})
        await client.call_tool("engagement_gate", {"action": "authorize", "confirmation": "yes"})

    async def test_unapproved_call_is_blocked_before_scanner(self):
        from server import mcp
        with patch("server.scan_ports", return_value=[]) as scan:
            async with Client(mcp) as client:
                await client.call_tool("engagement_gate", {"action": "init", "target": "allowed.test"})
                response = await client.call_tool("port_scan", {"target": "allowed.test"}, raise_on_error=False)
            self.assertTrue(response.is_error)
            scan.assert_not_called()

    async def test_approved_call_works_and_outside_target_is_blocked(self):
        from server import mcp
        with patch("server.scan_ports", return_value=[]) as scan:
            async with Client(mcp) as client:
                await self.authorize(client)
                response = await client.call_tool("port_scan", {"target": "allowed.test"})
                self.assertFalse(response.is_error)
                response = await client.call_tool("port_scan", {"target": "outside.test"}, raise_on_error=False)
                self.assertTrue(response.is_error)
            self.assertEqual(scan.call_count, 1)

    async def test_another_client_does_not_inherit_authorization(self):
        from server import mcp
        with patch("server.scan_ports", return_value=[]) as scan:
            async with Client(mcp) as first, Client(mcp) as second:
                await self.authorize(first)
                result = await second.call_tool("port_scan", {"target": "allowed.test"}, raise_on_error=False)
                self.assertTrue(result.is_error)
            scan.assert_not_called()

    async def test_offline_report_does_not_require_engagement(self):
        from server import mcp
        async with Client(mcp) as client:
            result = await client.call_tool("generate_report", {"target": "outside.test", "findings": "{}"})
            self.assertFalse(result.is_error)

    async def test_supply_chain_is_not_an_offline_scope_exception(self):
        from server import mcp
        with patch("server._supply", return_value={}) as scan:
            async with Client(mcp) as client:
                result = await client.call_tool("supply_chain", {"target": "https://outside.test"}, raise_on_error=False)
                self.assertTrue(result.is_error)
            scan.assert_not_called()

    async def test_apk_download_requires_scope(self):
        from server import mcp
        with patch("server._apk", return_value={}) as download:
            async with Client(mcp) as client:
                result = await client.call_tool("apk_analyze", {"target": "https://outside.test/app.apk"}, raise_on_error=False)
                self.assertTrue(result.is_error)
            download.assert_not_called()

    async def test_raw_host_header_cannot_bypass_allowed_target_argument(self):
        from server import mcp
        with patch("server._raw_replay", return_value="{}") as send:
            async with Client(mcp) as client:
                await self.authorize(client)
                result = await client.call_tool("raw_replay", {
                    "action": "replay", "target": "https://allowed.test",
                    "raw_request": "GET / HTTP/1.1\r\nHost: outside.test\r\n\r\n"
                }, raise_on_error=False)
                self.assertTrue(result.is_error)
            send.assert_not_called()

    async def test_bulk_checks_every_destination_before_scanning(self):
        from server import mcp
        with patch("server._bulk_scan", return_value="{}") as scan:
            async with Client(mcp) as client:
                await self.authorize(client)
                result = await client.call_tool("bulk_scan", {"targets": "allowed.test,outside.test"}, raise_on_error=False)
                self.assertTrue(result.is_error)
            scan.assert_not_called()

    async def test_secondary_login_destination_is_checked(self):
        from server import mcp
        with patch("server._authenticated_scan", return_value="{}") as scan:
            async with Client(mcp) as client:
                await self.authorize(client)
                result = await client.call_tool("authenticated_scan", {
                    "target": "https://allowed.test", "login_url": "https://outside.test/login"
                }, raise_on_error=False)
                self.assertTrue(result.is_error)
            scan.assert_not_called()

    async def test_readonly_cve_intel_remains_available(self):
        from server import mcp
        with patch("server.cve_lookup", return_value=[]):
            async with Client(mcp) as client:
                result = await client.call_tool("cve_search", {"service": "test"}, raise_on_error=False)
                self.assertFalse(result.is_error)


class TestRetestRegressions(unittest.TestCase):
    def test_all_network_errors_are_inconclusive_not_fixed(self):
        with patch("cyber_tools.retest_vuln.httpx.get", side_effect=httpx.ConnectError("offline")):
            result = json.loads(retest_vuln("https://fixture.test/item", "xss"))
        self.assertEqual(result["status"], "inconclusive")
        self.assertFalse(result.get("verified_fixed", False))

    def test_blocked_responses_are_inconclusive(self):
        with patch("cyber_tools.retest_vuln.httpx.get", return_value=httpx.Response(403, text="Forbidden")):
            result = json.loads(retest_vuln("https://fixture.test/item", "xss"))
        self.assertEqual(result["status"], "inconclusive")

    def test_blocked_payload_echo_is_not_exploit_confirmation(self):
        response = httpx.Response(403, text="Blocked payload: <script>alert(1)</script>")
        with patch("cyber_tools.retest_vuln.httpx.get", return_value=response):
            result = json.loads(retest_vuln("https://fixture.test/item", "xss"))
        self.assertEqual(result["status"], "inconclusive")

    def test_login_redirect_is_inconclusive(self):
        response = httpx.Response(302, headers={"Location": "/login"})
        with patch("cyber_tools.retest_vuln.httpx.get", return_value=response):
            result = json.loads(retest_vuln("https://fixture.test/item", "xss"))
        self.assertEqual(result["status"], "inconclusive")

    def test_negative_retest_only_says_not_reproduced(self):
        with patch("cyber_tools.retest_vuln.httpx.get", return_value=httpx.Response(200, text="safe")):
            result = json.loads(retest_vuln("https://fixture.test/item", "xss"))
        self.assertEqual(result["status"], "not_reproduced")
        self.assertFalse(result["verified_fixed"])

    def test_existing_query_is_preserved_and_payload_encoded(self):
        with patch("cyber_tools.retest_vuln.httpx.get", return_value=httpx.Response(200, text="safe")) as get:
            retest_vuln("https://fixture.test/item?tenant=qa&id=1", "xss", param="id", original_payload="a&b")
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(get.call_args.args[0]).query)
        self.assertEqual(query, {"tenant": ["qa"], "id": ["a&b"]})


class TestIdorRegressions(unittest.TestCase):
    def test_public_shared_response_is_not_confirmed_bola(self):
        response = {"status": 200, "body_size": 80, "body_hash": "shared-public", "accessible": True}
        with patch("cyber_tools.idor_access_validation._request_raw", return_value=response):
            result = json.loads(idor_access_validation("https://fixture.test/public", resource_ids="1",
                                                      user_a_cookie="sid=a", user_b_cookie="sid=b"))
        self.assertFalse(result["bola_found"])
        self.assertNotEqual(result["confidence"], "HIGH")
        self.assertIn("ownership_not_established", result["coverage"])


class TestValidatorRegressions(unittest.TestCase):
    def validate(self, **finding):
        return json.loads(vuln_validate(json.dumps(finding)))

    def test_missing_evidence_is_unverified_not_false_positive(self):
        result = self.validate(type="ssrf", evidence="", reproducible=False)
        self.assertEqual(result["validation"], "unverified")
        self.assertFalse(result["is_false_positive"])

    def test_correlated_callback_is_scored(self):
        result = self.validate(type="ssrf", evidence="correlated callback observed", reproducible=True,
                               callback_received=True, callback_id="case-1",
                               callback_hits=[{"callback_id": "case-1", "protocol": "http"}])
        self.assertFalse(result["is_false_positive"])
        self.assertIn("callback_received", [e["type"] for e in result["evidence_scored"]])

    def test_uncorrelated_callback_boolean_is_not_proof(self):
        result = self.validate(type="ssrf", evidence="callback claimed", callback_received=True)
        self.assertNotIn("callback_received", [e["type"] for e in result["evidence_scored"]])
        self.assertEqual(result["validation"], "unverified")

    def test_unrelated_error_text_does_not_discard_other_vuln_types(self):
        result = self.validate(type="xss", evidence="template not found", reproducible=True)
        self.assertFalse(result["is_false_positive"])

    def test_nonstring_evidence_does_not_crash(self):
        result = self.validate(type="ssrf", evidence={"callback": "pending"})
        self.assertEqual(result["validation"], "unverified")


class TestCiRegressions(unittest.TestCase):
    def test_ci_runs_offline_regressions(self):
        root = Path(__file__).resolve().parents[2]
        ci = (root / ".github/workflows/ci.yml").read_text()
        self.assertIn("scripts/run_offline_tests.py", ci)


if __name__ == "__main__":
    unittest.main()
