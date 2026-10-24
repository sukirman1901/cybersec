"""Offline regressions for epss_lookup using httpx MockTransport (no live API)."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cyber_tools.epss_lookup as ep


def mock_first_cve(cve, epss="0.42", percentile="0.71"):
    return {"cve": cve, "epss": epss, "percentile": percentile}


class TestEpssLookup(unittest.IsolatedAsyncioTestCase):
    async def test_scores_and_kev_flag(self):
        ep._KEV_CACHE["data"] = None  # reset cache for hermetic ordering
        def respond(request):
            if "/sites/default/files/feeds/" in str(request.url):
                return httpx.Response(200, json={"vulnerabilities": [
                    {"cveID": "CVE-2026-109618"}]})
            return httpx.Response(200, json={"data": [
                mock_first_cve("CVE-2026-109618", "0.97", "0.99"),
                mock_first_cve("CVE-2026-109619", "0.12", "0.55"),
            ]})
        real = httpx.AsyncClient
        with patch.object(ep.httpx, "AsyncClient", side_effect=lambda **kw:
                          real(transport=httpx.MockTransport(respond), **kw)):
            result = await ep.epss_lookup(["CVE-2026-109618", "CVE-2026-109619"])
        self.assertEqual(result["count"], 2)
        e0 = result["entries"][0]
        self.assertAlmostEqual(e0["epss"], 0.97, places=2)
        self.assertTrue(e0["in_kev"], "KEV member CVE-2026-109618 must be flagged")
        self.assertTrue(e0["patch_priority"].startswith("P0"))
        e1 = result["entries"][1]
        self.assertFalse(e1["in_kev"])
        self.assertTrue(e1["patch_priority"].startswith("P2"))

    async def test_rejects_empty(self):
        result = await ep.epss_lookup([])
        self.assertEqual(result["count"], 0)
        self.assertIn("error", result)

    async def test_caps_25_ids(self):
        called = {}

        def respond(request):
            called["n"] = request.url.params.get("cve", "").count(",") + 1
            return httpx.Response(200, json={"data": []})
        real = httpx.AsyncClient
        with patch.object(ep.httpx, "AsyncClient", side_effect=lambda **kw:
                          real(transport=httpx.MockTransport(respond), **kw)):
            result = await ep.epss_lookup([f"CVE-2026-{i:04d}" for i in range(40)])
        self.assertLessEqual(called["n"], 25)
        # Requested CVEs remain visible even without EPSS rows (KEV is independent).
        self.assertEqual(result["count"], 25)
        self.assertEqual(len(result["unknown_not_in_feed"]), 25)
        self.assertTrue(all(entry["epss"] is None for entry in result["entries"]))


if __name__ == "__main__":
    unittest.main()
