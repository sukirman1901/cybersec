"""Opt-in EPSS/KEV auto-enrichment for vuln_scan findings; offline fixtures only.

Contract: default vuln_scan keeps zero extra outbound intel traffic; when
epss_intel=True the scanner may make at most the two read-only intel requests
already owned by epss_lookup (FIRST + cached CISA KEV), never target probing,
and enrichment failures must never fail the scan itself.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from fastmcp import Client

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cyber_tools.vuln_scanner as vs
from cyber_tools.vuln_scanner import scan_vulnerabilities

FAKE_INTEL = {
    "entries": [
        {"cve": "CVE-2026-109618", "epss": 0.972311, "percentile": 0.99541,
         "in_kev": True, "patch_priority": "P0"},
        {"cve": "CVE-2026-109619", "epss": 0.020499, "percentile": 0.77187,
         "in_kev": False, "patch_priority": "P2"},
    ],
    "count": 2,
    "unknown_not_in_feed": [],
    "references": ["https://www.first.org/epss/",
                   "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
}


class TestVulnScanEpssIntel(unittest.IsolatedAsyncioTestCase):
    async def scan(self, **kwargs):
        requests = []

        def respond(request):
            requests.append(request)
            if request.url.path == "/":
                return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"}, text="Hello")
            return httpx.Response(404, text="Not found")

        real_client = httpx.AsyncClient
        with patch("cyber_tools.vuln_scanner.httpx.AsyncClient", side_effect=lambda **kw:
                   real_client(transport=httpx.MockTransport(respond), **kw)):
            result = await scan_vulnerabilities("https://example.test", **kwargs)
        json.dumps(result)
        return result, requests

    async def test_optin_intel_enriches_cve_findings(self):
        with patch.object(vs, "_epss_lookup", AsyncMock(return_value=FAKE_INTEL)) as intel:
            result, requests = await self.scan(epss_intel=True)
        intel.assert_awaited_once()
        self.assertEqual(sorted(set(request.url.host for request in requests)),
                         ["example.test"])  # enrich never probes another host
        cve_findings = [v for v in result["vulnerabilities"] if v.get("type") == "cve"]
        self.assertEqual(len(cve_findings), 2)
        for finding in cve_findings:
            self.assertIn(finding["cve"], ("CVE-2026-109618", "CVE-2026-109619"))
            self.assertIn("intel", finding)
            self.assertIn(finding["intel"]["patch_priority"], ("P0", "P2"))
            self.assertIn("epss", finding["intel"])
        summary = result["intel_summary"]
        self.assertTrue(summary["attempted"])
        self.assertEqual(summary["enriched"], 2)
        json.dumps(summary, allow_nan=False)

    async def test_default_is_off_and_makes_no_intel_calls(self):
        with patch.object(vs, "_epss_lookup", AsyncMock(side_effect=AssertionError("must not be called"))) as intel:
            result, _ = await self.scan()
        intel.assert_not_awaited()
        self.assertTrue(all("intel" not in v for v in result["vulnerabilities"]))

    async def test_intel_failure_never_fails_the_scan(self):
        with patch.object(vs, "_epss_lookup", AsyncMock(side_effect=RuntimeError("FIRST down"))):
            result, _ = await self.scan(epss_intel=True)
        self.assertIn("vulnerabilities", result)
        self.assertTrue(all("intel" not in v for v in result["vulnerabilities"]))
        self.assertTrue(result["intel_summary"]["attempted"])
        self.assertIn("error", result["intel_summary"])

    async def test_mcp_vuln_scan_schema_offers_epss_intel(self):
        from server import mcp
        async with Client(mcp) as client:
            tools = {tool.name: tool for tool in await client.list_tools()}
            schema = tools["vuln_scan"].inputSchema
            self.assertIn("epss_intel", schema["properties"])
            self.assertFalse(schema["properties"]["epss_intel"].get("default", True))


if __name__ == "__main__":
    unittest.main()
