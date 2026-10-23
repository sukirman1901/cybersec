"""OR fallback causal evidence; real SQL behavior lives in SQLite benchmark tests."""

import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.finding_contract import finding_fingerprint
from cyber_tools.sqli_detect import sqli_detect

EMPTY = '{"rows": []}'
EXPANDED = '{"rows": [[7, "alpha"], [8, "bravo"]]}'


def true_or(value):
    match = re.search(r"\bOR (\d+)=(\d+)", value)
    return match is not None and match[1] == match[2]


class TestOrEvidence(unittest.IsolatedAsyncioTestCase):
    async def scan(self, handler=None, target="https://example.test/item?id=999&tenant=qa%20team"):
        self.requests = []

        def respond(request):
            self.requests.append(request)
            if handler is not None:
                return handler(request)
            return httpx.Response(200, text=EXPANDED if true_or(request.url.params["id"]) else EMPTY)

        real = httpx.AsyncClient
        with patch("httpx.AsyncClient", side_effect=lambda **kw:
                   real(transport=httpx.MockTransport(respond), **kw)):
            return await sqli_detect(target, param="id")

    async def test_or_evidence_has_controls_two_rounds_and_recovery(self):
        out = await self.scan()
        self.assertTrue(out["vulnerable"])
        finding = out["findings"][0]
        proof = json.loads(finding["evidence"])
        self.assertEqual(proof["operator"], "OR")
        self.assertEqual(proof["baseline_matches"], "false")
        self.assertEqual(proof["request_order"], ["true,false", "false,true"])
        self.assertEqual(proof["confirmation_rounds"], 2)
        self.assertEqual(len(proof["pairs"]), 2)
        self.assertEqual(len(proof["keyword_controls"]), 2)
        self.assertEqual(proof["recovery"]["status"], 200)
        replay = finding["replay"]
        self.assertIn("tenant=qa%20team", replay["url"])
        self.assertEqual(replay["probe_values"], [
            "999 OR 17=17", "999 OR 17=18", "999 OR 29=30", "999 OR 29=29"])
        self.assertEqual(finding["payload"], "paired_OR_predicates")
        self.assertTrue(finding["reproducible"])

    async def test_keyword_only_filter_does_not_confirm(self):
        out = await self.scan(lambda r: httpx.Response(
            200, text=EXPANDED if " OR " in r.url.params["id"] else EMPTY))
        self.assertFalse(out["vulnerable"])

    async def test_or_reflection_is_not_proof(self):
        out = await self.scan(lambda r: httpx.Response(
            200, text="<table>" + r.url.params["id"] * 20 + "</table>"))
        self.assertFalse(out["vulnerable"])

    async def test_one_predicate_string_filter_is_not_confirmed(self):
        out = await self.scan(lambda r: httpx.Response(
            200, text=EXPANDED if " OR 17=17" in r.url.params["id"] else EMPTY))
        self.assertFalse(out["vulnerable"])
        self.assertTrue(out["candidates"])

    async def test_two_different_true_responses_do_not_confirm(self):
        def handler(request):
            value = request.url.params["id"]
            text = EMPTY
            if true_or(value):
                text = EXPANDED if "17=17" in value else "an unrelated application response" * 5
            return httpx.Response(200, text=text)

        out = await self.scan(handler)
        self.assertFalse(out["vulnerable"])
        self.assertTrue(out["candidates"])

    async def test_changed_baseline_after_or_does_not_confirm(self):
        expanded_seen = False

        def handler(request):
            nonlocal expanded_seen
            value = request.url.params["id"]
            if true_or(value):
                expanded_seen = True
                return httpx.Response(200, text=EXPANDED)
            if value == "999" and expanded_seen:
                return httpx.Response(200, text="baseline state changed after probing")
            return httpx.Response(200, text=EMPTY)

        out = await self.scan(handler)
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["assessment"], "inconclusive")

    async def test_or_waf_response_is_not_proof(self):
        out = await self.scan(lambda r: httpx.Response(
            403 if true_or(r.url.params["id"]) else 200,
            text="Forbidden" if true_or(r.url.params["id"]) else EMPTY))
        self.assertFalse(out["vulnerable"])
        self.assertFalse(out["coverage_complete"])

    async def test_budget_exhaustion_mid_confirmation_does_not_publish(self):
        from cyber_tools.sqli_probe import PRESETS
        with patch.dict(PRESETS, {"observe-first": {"seconds": 18, "requests": 16, "params": 2}}):
            out = await self.scan()
        self.assertFalse(out["vulnerable"])
        self.assertIn("request_budget_reached", out["errors"])
        self.assertLessEqual(out["requests_sent"], 16)

    async def test_or_finding_identity_is_stable(self):
        first = (await self.scan())["findings"][0]
        second = (await self.scan())["findings"][0]
        self.assertEqual(finding_fingerprint(first), finding_fingerprint(second))

    async def test_or_replay_redacts_required_secret(self):
        out = await self.scan(target="https://example.test/item?id=999&token=DO-NOT-EXPORT")
        self.assertTrue(out["vulnerable"])
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(out))
        self.assertFalse(out["findings"][0]["reproducible"])
        self.assertEqual(out["findings"][0]["replay"]["requires_secrets"], ["token"])

    async def test_successful_and_does_not_run_or_fallback(self):
        def handler(request):
            value = request.url.params["id"]
            false = " AND 17=18" in value or " AND 29=30" in value
            return httpx.Response(200, text=EMPTY if false else EXPANDED)

        out = await self.scan(handler)
        self.assertTrue(out["vulnerable"])
        self.assertFalse(any(" OR " in request.url.params["id"] for request in self.requests))
