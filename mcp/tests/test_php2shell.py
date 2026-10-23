"""Offline PHP2SHELL detection regressions; never send exploit traffic."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastmcp import Client

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.vuln_scanner import scan_vulnerabilities
from cyber_tools.vuln_db import cve_lookup

CVES = {"CVE-2026-109618", "CVE-2026-109619"}


class TestPhp2ShellScanner(unittest.IsolatedAsyncioTestCase):
    async def scan(self, headers=None, fail=False):
        requests = []

        def respond(request):
            requests.append(request)
            if fail:
                raise httpx.ConnectError("offline", request=request)
            if request.url.path == "/":
                return httpx.Response(200, headers=headers or {}, text="Hello")
            return httpx.Response(404, text="Not found")

        real_client = httpx.AsyncClient
        with patch("cyber_tools.vuln_scanner.httpx.AsyncClient", side_effect=lambda **kw:
                   real_client(transport=httpx.MockTransport(respond), **kw)):
            result = await scan_vulnerabilities("https://example.test")
        json.dumps(result)
        return result, requests

    async def test_all_supported_branch_boundaries(self):
        for minor, fixed in ((2, 35), (3, 36), (4, 27), (5, 12)):
            for patch_number in (0, fixed - 1, fixed, fixed + 1, 100):
                with self.subTest(minor=minor, patch=patch_number):
                    version = f"8.{minor}.{patch_number}"
                    result, _ = await self.scan({"X-Powered-By": f"PHP/{version}"})
                    affected = patch_number < fixed
                    assessment = result.get("php2shell", {})
                    self.assertEqual(assessment.get("status"),
                                     "potentially_affected" if affected else "not_affected_by_version")
                    self.assertEqual(assessment["fixed_version"], f"8.{minor}.{fixed}")
                    findings = [v for v in result["vulnerabilities"] if v.get("cve") in CVES]
                    self.assertEqual({v["cve"] for v in findings}, CVES if affected else set())
                    for finding in findings:
                        self.assertIn(finding["confidence"], ("HIGH", "MEDIUM", "LOW"))
                        self.assertEqual(finding["severity"], "critical")
                        self.assertIn(version, finding["evidence"])
                        self.assertTrue(finding["references"])

    async def test_unknown_is_not_safe(self):
        for banner in (None, "PHP", "PHP/8.4", "PHP/8.4.27RC1", "PHP/8.6.0",
                       "PHP/7.4.33", "PHP/8.1.33", "PHP/8.4.27garbage", "PHP/8.4.27.1"):
            with self.subTest(banner=banner):
                result, _ = await self.scan({"X-Powered-By": banner} if banner else
                                            {"Set-Cookie": "PHPSESSID=abc"})
                self.assertEqual(result.get("php2shell", {}).get("status"), "unknown")
                self.assertFalse([v for v in result["vulnerabilities"] if v.get("cve") in CVES])

    async def test_server_header_and_backport_warning(self):
        result, _ = await self.scan({"Server": "Apache PHP/8.4.26-1+deb12u1"})
        self.assertEqual(result.get("php2shell", {}).get("status"), "potentially_affected")
        self.assertIn("backport", " ".join(result["php2shell"]["limitations"]).lower())
        self.assertEqual(result["php2shell"]["evidence"][0]["source"], "header:server")
        self.assertEqual(result["php2shell"]["confidence"], "LOW")
        self.assertTrue(any("backport" in n.lower() for n in result["php2shell"]["confidence_notes"]))

    async def test_conflicting_versions_are_unknown(self):
        for headers in ({"Server": "PHP/8.4.26", "X-Powered-By": "PHP/8.4.27"},
                        {"X-Powered-By": "PHP/8.4.26, PHP/8.4.27"}):
            result, _ = await self.scan(headers)
            self.assertEqual(result.get("php2shell", {}).get("status"), "unknown")
            self.assertEqual(len(result["php2shell"]["observed_versions"]), 2)

    async def test_detection_adds_no_requests(self):
        _, baseline = await self.scan()
        result, detected = await self.scan({"X-Powered-By": "PHP/8.4.26"})
        self.assertEqual(result.get("php2shell", {}).get("status"), "potentially_affected")
        self.assertEqual([(r.method, str(r.url), r.content) for r in detected],
                         [(r.method, str(r.url), r.content) for r in baseline])

    async def test_network_failure_has_unknown_assessment(self):
        result, _ = await self.scan(fail=True)
        self.assertEqual(result.get("php2shell", {}).get("status"), "unknown")

    async def test_oversized_numeric_banner_does_not_abort_scan(self):
        result, requests = await self.scan({"X-Powered-By": "PHP/8.4." + "9" * 4301})
        self.assertNotIn("error", result)
        self.assertEqual(result.get("php2shell", {}).get("status"), "unknown")
        self.assertTrue(any(r.url.path == "/.git/config" for r in requests))
        self.assertIn("Missing X-Frame-Options Header", [v["name"] for v in result["vulnerabilities"]])

    async def test_summary_contract_preserves_probable_not_verified(self):
        result, _ = await self.scan({"X-Powered-By": "PHP/8.4.26"})
        self.assertEqual(result["by_confidence"]["MEDIUM"], 2)
        self.assertEqual(result["by_confidence"]["probable"], 2)
        self.assertEqual(result["by_severity"]["critical"], 2)
        self.assertEqual(result["verified_count"], 0)
        self.assertEqual(result["count"], len(result["vulnerabilities"]))
        # HIGH/MEDIUM/LOW also roll into probable — do not double-count in the sum gate.
        graded = sum(result["by_confidence"][k] for k in ("verified", "probable", "info"))
        self.assertEqual(graded, result["count"])
        for finding in result["vulnerabilities"]:
            self.assertTrue({"name", "severity", "description", "matched_at", "type", "confidence"} <= finding.keys())
        php2shell_findings = [f for f in result["vulnerabilities"] if f.get("cve") in CVES]
        self.assertEqual(len(php2shell_findings), 2)
        self.assertTrue(all(f["confidence"] == "MEDIUM" for f in php2shell_findings))


class TestPhp2ShellLookup(unittest.TestCase):
    def lookup(self, service, version=""):
        with patch("urllib.request.urlopen", side_effect=OSError("offline")):
            return cve_lookup(service, version)

    def test_lookup_uses_same_numeric_boundaries(self):
        for minor, fixed in ((2, 35), (3, 36), (4, 27), (5, 12)):
            for number in (fixed - 1, fixed, 100):
                with self.subTest(minor=minor, number=number):
                    result = self.lookup("PHP", f"8.{minor}.{number}")
                    found = {v["id"] for v in result} & CVES
                    self.assertEqual(found, CVES if number < fixed else set())
                    for finding in result:
                        if finding["id"] in CVES:
                            self.assertIn(finding["confidence"], ("probable", "HIGH", "MEDIUM", "LOW"))

    def test_no_php2shell_match_for_other_service_or_constraint(self):
        for service, version in (("nginx", "8.4.26"), ("php", "^8.4"),
                                 ("php", "8.4"), ("php", "8.6.0")):
            self.assertFalse({v["id"] for v in self.lookup(service, version)} & CVES)

    def test_oversized_numeric_lookup_is_unknown_not_an_exception(self):
        self.assertFalse({v["id"] for v in self.lookup("php", "8.4." + "9" * 4301)} & CVES)

    def test_nvd_keyword_hits_cannot_override_version_assessment(self):
        from io import BytesIO
        data = {"vulnerabilities": [{"cve": {"id": cid}} for cid in
                                    (*sorted(CVES), "CVE-OTHER") ]}
        for version in ("8.4.26", "8.4.27", "8.4", "8.6.0"):
            with self.subTest(version=version):
                with patch("urllib.request.urlopen", return_value=BytesIO(json.dumps(data).encode())):
                    result = cve_lookup("php", version)
                records = [v for v in result if v["id"] in CVES]
                self.assertEqual(len(records), 2 if version == "8.4.26" else 0)
                self.assertTrue(all(v.get("confidence") in ("probable", "HIGH", "MEDIUM", "LOW")
                                    for v in records))
                self.assertIn("CVE-OTHER", {v["id"] for v in result})


class TestPhp2ShellMcp(unittest.IsolatedAsyncioTestCase):
    async def test_registered_tools_return_serializable_bounded_findings(self):
        from server import mcp
        real_client = httpx.AsyncClient

        def respond(request):
            if request.url.path == "/":
                return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"}, text="Hello")
            return httpx.Response(404, text="Not found")

        async with Client(mcp) as client:
            tools = {tool.name: tool for tool in await client.list_tools()}
            for name in ("cve_search", "vuln_scan"):
                self.assertIn("PHP2SHELL", tools[name].description)
            with patch("urllib.request.urlopen", side_effect=OSError("offline")):
                lookup = await client.call_tool("cve_search", {"service": "php", "version": "8.4.26"})
            self.assertEqual({v["id"] for v in json.loads(lookup.content[0].text)["results"]}, CVES)
            with patch("cyber_tools.vuln_scanner.httpx.AsyncClient", side_effect=lambda **kw:
                       real_client(transport=httpx.MockTransport(respond), **kw)):
                scan = await client.call_tool("vuln_scan", {"target": "https://example.test"})
            result = json.loads(scan.content[0].text)
            self.assertEqual(result["php2shell"]["status"], "potentially_affected")
            self.assertEqual(result["by_confidence"]["probable"], 2)


if __name__ == "__main__":
    unittest.main()
