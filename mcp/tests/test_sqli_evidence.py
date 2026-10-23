"""Causal SQLi regressions. No requests leave the in-process transport."""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.sqli_detect import sqli_detect


class TestSqliEvidence(unittest.IsolatedAsyncioTestCase):
    async def scan(self, handler, target="https://example.test/item?id=7", **kwargs):
        self.requests = []

        def respond(request):
            self.requests.append(request)
            return handler(request)

        real = httpx.AsyncClient
        with patch("httpx.AsyncClient", side_effect=lambda **kw:
                   real(transport=httpx.MockTransport(respond), **kw)):
            return await sqli_detect(target, **kwargs)

    async def test_static_sql_error_documentation_is_not_sqli(self):
        out = await self.scan(lambda r: httpx.Response(
            200, text="SQL syntax error MySQL: this is a documentation example."))
        self.assertFalse(out["vulnerable"])

    async def test_input_rejection_status_is_not_boolean_sqli(self):
        out = await self.scan(lambda r: httpx.Response(
            403 if "1=2" in r.url.params.get("id", "") else 200,
            text="Forbidden" if "1=2" in r.url.params.get("id", "") else "Welcome"))
        self.assertFalse(out["vulnerable"])

    async def test_preserves_original_values_duplicates_blanks_and_encoding(self):
        target = "https://example.test/item?tenant=qa%20team&id=7&id=9&blank=&opaque=a%2fb+z"
        await self.scan(lambda r: httpx.Response(200, text="stable"), target, param="id")
        self.assertEqual(str(self.requests[0].url), target)
        for request in self.requests:
            query = request.url.query.decode()
            self.assertIn("tenant=qa%20team", query)
            self.assertIn("blank=", query)
            self.assertIn("opaque=a%2fb+z", query)
            ids = request.url.params.get_list("id")
            self.assertEqual(len(ids), 2)
            self.assertTrue(ids[0] == "7" or ids[1] == "9")

    async def test_one_transient_error_does_not_confirm(self):
        seen = 0

        def handler(request):
            nonlocal seen
            value = request.url.params.get("id", "")
            if "'" in value:
                seen += 1
                if seen == 1:
                    return httpx.Response(500, text="SQL syntax error MySQL")
            return httpx.Response(200, text="stable")

        out = await self.scan(handler)
        self.assertFalse(out["vulnerable"])
        self.assertTrue(out["candidates"])
        self.assertEqual(out["assessment"], "inconclusive")

    async def test_reproducible_new_error_has_control_evidence(self):
        out = await self.scan(lambda r: httpx.Response(
            500, text="SQL syntax error MySQL") if "'" in r.url.params.get("id", "")
            else httpx.Response(200, text="stable"))
        self.assertTrue(out["vulnerable"])
        finding = next(f for f in out["findings"] if f["technique"] == "error_based")
        proof = json.loads(finding["evidence"])
        self.assertEqual(proof["confirmation_rounds"], 2)
        self.assertGreaterEqual(len(proof["baseline"]), 3)
        self.assertGreaterEqual(len(proof["controls"]), 2)
        self.assertEqual(len(proof["probes"]), 2)

    async def test_reflected_payload_is_not_boolean_or_union_proof(self):
        out = await self.scan(lambda r: httpx.Response(
            200, text="<table><tr><td>" + r.url.params.get("id", "") * 20 + "</td></tr></table>"))
        self.assertFalse(out["vulnerable"])

    async def test_boolean_proof_has_two_predicates_and_reversed_round(self):
        def handler(request):
            value = request.url.params.get("id", "")
            if "AND" in value:
                import re
                match = re.search(r"(\d+)\s*=\s*(\d+)", value)
                if match and match[1] != match[2]:
                    return httpx.Response(200, text="No matching records. " * 10)
            return httpx.Response(200, text="Synthetic item seven. " * 10)

        out = await self.scan(handler)
        self.assertTrue(out["vulnerable"])
        finding = next(f for f in out["findings"] if f["technique"] == "boolean_blind")
        evidence = json.loads(finding["evidence"])
        self.assertEqual(evidence["confirmation_rounds"], 2)
        self.assertEqual(evidence["request_order"], ["true,false", "false,true"])
        self.assertEqual(len(evidence["pairs"]), 2)
        self.assertTrue(all(pair["true"]["status"] == pair["false"]["status"] == 200
                            for pair in evidence["pairs"]))

    async def test_unstable_baselines_are_inconclusive(self):
        seen = 0

        def handler(request):
            nonlocal seen
            seen += 1
            return httpx.Response(200, text=("alpha " if seen % 2 else "zulu ") * 100)

        out = await self.scan(handler)
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["assessment"], "inconclusive")

    async def test_transport_failure_is_inconclusive_not_clean(self):
        def handler(request):
            raise httpx.ConnectError("offline", request=request)

        out = await self.scan(handler)
        self.assertEqual(out["assessment"], "inconclusive")
        self.assertFalse(out["coverage_complete"])
        self.assertTrue(out["errors"])

    async def test_invalid_preset_makes_no_requests(self):
        out = await self.scan(lambda r: httpx.Response(200), preset="typo-deep")
        self.assertEqual(self.requests, [])
        self.assertEqual(out["assessment"], "inconclusive")
        self.assertIn("invalid_preset", out["errors"])

    async def test_request_budget_and_deferred_techniques_are_explicit(self):
        out = await self.scan(lambda r: httpx.Response(200, text="stable"))
        self.assertEqual(out["requests_sent"], len(self.requests))
        self.assertLessEqual(out["requests_sent"], out["request_budget"])
        self.assertIn("time_blind", out["techniques_skipped"])
        self.assertIn("union_based", out["techniques_skipped"])
        self.assertFalse(any("SLEEP" in str(r.url) or "BENCHMARK" in str(r.url)
                             for r in self.requests))
        json.dumps(out)

    async def test_findings_work_with_existing_report_converter(self):
        from cyber_tools.report_schema_v2 import report_schema_v2
        out = await self.scan(lambda r: httpx.Response(
            500, text="SQL syntax error MySQL") if "'" in r.url.params.get("id", "")
            else httpx.Response(200, text="stable"))
        report = json.loads(report_schema_v2("create", json.dumps(out["findings"])))
        self.assertEqual(len(report["findings"]), len(out["findings"]))

    async def test_confirmed_findings_survive_later_request_budget_exhaustion(self):
        from cyber_tools.sqli_probe import PRESETS
        with patch.dict(PRESETS, {"observe-first": {"seconds": 18, "requests": 8, "params": 2}}):
            out = await self.scan(lambda r: httpx.Response(
                500, text="SQL syntax error MySQL") if "'" in r.url.params.get("id", "")
                else httpx.Response(200, text="stable"))
        self.assertEqual(out["requests_sent"], 8)
        self.assertTrue(out["vulnerable"])
        self.assertFalse(out["coverage_complete"])

    async def test_deadline_cancels_inflight_io(self):
        from cyber_tools.sqli_probe import PRESETS
        started = asyncio.get_running_loop().time()

        async def handler(request):
            await asyncio.sleep(5)
            return httpx.Response(200, text="late")

        real = httpx.AsyncClient
        with patch.dict(PRESETS, {"observe-first": {"seconds": 0.03, "requests": 80, "params": 2}}), \
             patch("httpx.AsyncClient", side_effect=lambda **kw:
                   real(transport=httpx.MockTransport(handler), **kw)):
            out = await sqli_detect("https://example.test/?id=7")
        self.assertLess(asyncio.get_running_loop().time() - started, 0.5)
        self.assertEqual(out["assessment"], "inconclusive")

    async def test_oversized_response_is_inconclusive(self):
        out = await self.scan(lambda r: httpx.Response(200, content=b"x" * 262145))
        self.assertFalse(out["coverage_complete"])
        self.assertIn("response_body_limit", out["errors"])

    async def test_blind_confirmation_rejects_syntax_sensitive_filter(self):
        # An application rule recognizes one predicate string; it does not execute SQL.
        out = await self.scan(lambda r: httpx.Response(200, text=(
            "No matching records. " * 10 if "17=18" in r.url.params.get("id", "")
            else "Synthetic item seven. " * 10)))
        self.assertFalse(out["vulnerable"])
        self.assertTrue(out["candidates"])

    async def test_boolean_control_errors_do_not_allow_high_confidence(self):
        def handler(request):
            value = request.url.params.get("id", "")
            if value in ("8", "9"):
                return httpx.Response(500, text="unexpected control failure")
            if "17=18" in value or "29=30" in value:
                return httpx.Response(200, text="No matching records. " * 10)
            return httpx.Response(200, text="Synthetic item seven. " * 10)

        out = await self.scan(handler)
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["assessment"], "inconclusive")

    async def test_unsupported_scheme_is_rejected_before_network(self):
        out = await self.scan(lambda r: httpx.Response(200), "ftp://example.test/item?id=7")
        self.assertEqual(self.requests, [])
        self.assertEqual(out["assessment"], "inconclusive")

    async def test_block_page_with_200_is_not_boolean_proof(self):
        out = await self.scan(lambda r: httpx.Response(200, text=(
            "Request blocked by Web Application Firewall"
            if "17=18" in r.url.params.get("id", "") or "29=30" in r.url.params.get("id", "")
            else "Synthetic item seven. " * 10)))
        self.assertFalse(out["vulnerable"])
        self.assertFalse(out["coverage_complete"])

    async def test_redirect_is_not_followed_or_reported_clean(self):
        out = await self.scan(lambda r: httpx.Response(
            302, headers={"Location": "https://outside.invalid/"}))
        self.assertEqual(out["assessment"], "inconclusive")
        self.assertTrue(all(r.url.host == "example.test" for r in self.requests))

    async def test_does_not_depend_on_python311_timeout_api(self):
        # CI supports Python 3.10, which has wait_for but no asyncio.timeout.
        with patch.object(asyncio, "timeout", None, create=True):
            out = await self.scan(lambda r: httpx.Response(200, text="stable"))
        self.assertEqual(out["assessment"], "no_evidence")

    async def test_repeated_warning_text_does_not_block_deadline(self):
        from cyber_tools.sqli_probe import PRESETS
        started = asyncio.get_running_loop().time()
        with patch.dict(PRESETS, {"observe-first": {"seconds": 0.01, "requests": 80, "params": 2}}):
            out = await self.scan(lambda r: httpx.Response(200, text="Warning " * 4096))
        self.assertLess(asyncio.get_running_loop().time() - started, 0.35)
        self.assertFalse(out["vulnerable"])

    async def test_finding_is_replayable_without_outer_scan_envelope(self):
        out = await self.scan(lambda r: httpx.Response(
            500, text="SQL syntax error MySQL") if "'" in r.url.params.get("id", "")
            else httpx.Response(200, text="stable"),
            "https://example.test/item?id=7&tenant=qa%20team", param="id")
        finding = out["findings"][0]
        replay = finding["replay"]
        self.assertEqual(replay["url"], "https://example.test/item?id=7&tenant=qa%20team")
        self.assertEqual(replay["original_value"], "7")
        self.assertEqual(replay["probe_values"], ["7'", "7'"])
        self.assertTrue(finding["reproducible"])

    async def test_replay_redacts_secrets_and_declares_missing_context(self):
        out = await self.scan(lambda r: httpx.Response(
            500, text="SQL syntax error MySQL") if "'" in r.url.params.get("id", "")
            else httpx.Response(200, text="stable"),
            "https://example.test/item?id=7&token=DO-NOT-EXPORT", param="id")
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(out))
        self.assertFalse(out["findings"][0]["reproducible"])
        self.assertEqual(out["findings"][0]["replay"]["requires_secrets"], ["token"])

    async def test_operational_timings_do_not_change_finding_identity(self):
        from cyber_tools.finding_contract import finding_fingerprint
        handler = lambda r: httpx.Response(
            500, text="SQL syntax error MySQL") if "'" in r.url.params.get("id", "") \
            else httpx.Response(200, text="stable")
        first = (await self.scan(handler))["findings"][0]
        second = (await self.scan(handler))["findings"][0]
        proof = json.loads(second["evidence"])
        proof["baseline"][0]["elapsed_ms"] += 123
        second["evidence"] = json.dumps(proof)
        self.assertEqual(finding_fingerprint(first), finding_fingerprint(second))
