"""Hermetic feed freshness and uncertainty contracts."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cyber_tools.epss_lookup as ep

CVE = "CVE-2026-109618"


class TestEpssFreshness(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cache = patch.object(ep, "_KEV_CACHE", {"data": None})
        self.cache.start()
        self.addCleanup(self.cache.stop)
        self.now = 10000.0
        self.clock = patch.object(ep, "monotonic", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.kev_error = False
        self.first_error = False
        self.score = "0.42"
        self.rows = True
        self.calls = []
        real = httpx.AsyncClient
        self.transport = patch.object(ep.httpx, "AsyncClient", side_effect=lambda **kw:
                                     real(transport=httpx.MockTransport(self.respond), **kw))
        self.transport.start()
        self.addCleanup(self.transport.stop)

    def respond(self, request):
        self.calls.append(request)
        if request.url.host == "api.first.org":
            if self.first_error:
                return httpx.Response(503)
            return httpx.Response(200, json={"data": [{"cve": CVE, "epss": self.score,
                "percentile": "0.9", "date": "2026-10-24"}] if self.rows else []})
        if self.kev_error:
            return httpx.Response(503)
        return httpx.Response(200, json={"dateReleased": "2026-10-23T00:00:00Z",
                                        "vulnerabilities": [{"cveID": CVE}]})

    async def test_unavailable_kev_is_unknown_not_false(self):
        self.kev_error = True
        out = await ep.epss_lookup([CVE])
        self.assertIsNone(out["entries"][0]["in_kev"])
        self.assertEqual(out["sources"]["kev"]["status"], "unavailable")
        self.assertIn("error", out["sources"]["kev"])

    async def test_cache_expires_at_one_hour_and_stale_is_not_current(self):
        first = await ep.epss_lookup([CVE])
        self.assertTrue(first["entries"][0]["in_kev"])
        self.now += 3599
        await ep.epss_lookup([CVE])
        self.assertEqual(len(self.calls), 3)
        self.now += 1
        self.kev_error = True
        out = await ep.epss_lookup([CVE])
        self.assertEqual(len(self.calls), 5)
        self.assertIsNone(out["entries"][0]["in_kev"])
        self.assertTrue(out["entries"][0]["stale_in_kev"])
        self.assertEqual(out["sources"]["kev"]["status"], "stale")
        self.assertEqual(out["sources"]["kev"]["age_seconds"], 3600)
        self.kev_error = False
        self.now += 1
        recovered = await ep.epss_lookup([CVE])
        self.assertTrue(recovered["entries"][0]["in_kev"])
        self.assertEqual(recovered["sources"]["kev"]["status"], "fresh")

    async def test_disabled_kev_and_invalid_scores_remain_unknown(self):
        for value in ("NaN", "Infinity", "-0.1", "1.01", "bad", None, True):
            with self.subTest(value=value):
                self.score = value
                out = await ep.epss_lookup([CVE], include_kev=False)
                self.assertIsNone(out["entries"][0]["epss"])
                self.assertIsNone(out["entries"][0]["in_kev"])
                self.assertTrue(out["entries"][0]["patch_priority"].startswith("unknown"))
                json.dumps(out, allow_nan=False)
        self.assertEqual(len(self.calls), 7)

    async def test_source_dates_are_retained(self):
        out = await ep.epss_lookup([CVE])
        self.assertEqual(out["entries"][0]["epss_date"], "2026-10-24")
        self.assertTrue(out["sources"]["epss"]["fetched_at"].endswith("Z"))
        self.assertEqual(out["sources"]["kev"]["source_date"], "2026-10-23T00:00:00Z")

    async def test_missing_epss_does_not_hide_kev_membership(self):
        self.rows = False
        out = await ep.epss_lookup([CVE])
        self.assertEqual(len(out["entries"]), 1)
        self.assertTrue(out["entries"][0]["in_kev"])
        self.assertTrue(out["entries"][0]["patch_priority"].startswith("P0"))
        self.assertIn(CVE, out["unknown_not_in_feed"])

    async def test_first_outage_still_checks_kev(self):
        self.first_error = True
        out = await ep.epss_lookup([CVE])
        self.assertEqual(out["sources"]["epss"]["status"], "unavailable")
        self.assertTrue(out["entries"][0]["in_kev"])
        self.assertEqual(len(self.calls), 2)

    async def test_fresh_negative_and_boundary_scores(self):
        other = "CVE-2026-109619"
        out = await ep.epss_lookup([CVE, other, CVE, "bad"])
        self.assertEqual(out["count"], 2)
        self.assertIs(out["entries"][1]["in_kev"], False)
        self.assertIsNone(out["entries"][1]["epss"])
        self.assertTrue(out["entries"][1]["patch_priority"].startswith("unknown"))
        for score, priority in ((0, "P3"), (0.1, "P2"), (0.5, "P1"), (1, "P1")):
            self.score = score
            out = await ep.epss_lookup([CVE], include_kev=False)
            self.assertEqual(out["entries"][0]["epss"], score)
            self.assertTrue(out["entries"][0]["patch_priority"].startswith(priority))

    async def test_invalid_percentile_is_null(self):
        real_respond = self.respond
        def respond(request):
            response = real_respond(request)
            if request.url.host == "api.first.org":
                payload = response.json()
                payload["data"][0]["percentile"] = "Infinity"
                return httpx.Response(200, json=payload)
            return response
        self.transport.stop()
        real = httpx.AsyncClient
        with patch.object(ep.httpx, "AsyncClient", side_effect=lambda **kw:
                          real(transport=httpx.MockTransport(respond), **kw)):
            out = await ep.epss_lookup([CVE])
        self.assertIsNone(out["entries"][0]["percentile"])
        json.dumps(out, allow_nan=False)
