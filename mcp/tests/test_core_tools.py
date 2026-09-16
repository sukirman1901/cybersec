"""Smoke tests for recently fixed cyber_tools modules."""

import asyncio
import json
import sys
import unittest
from pathlib import Path

MCP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MCP_DIR))

from cyber_tools.dork_scan import _ENGINE_MAP, _unwrap_search_url
from cyber_tools.ssl_analyzer import _normalize_host, ssl_analyze
from cyber_tools.tool_health import check_tool_health
from cyber_tools.vuln_db import cve_lookup
from cyber_tools.vuln_scanner import PATH_CHECKS, scan_vulnerabilities
from cyber_tools.whois_lookup import _normalize_domain
from cyber_tools.social_osint import _profile_exists


class TestDorkScan(unittest.TestCase):
    def test_engine_map_has_ddg(self):
        self.assertIn("ddg", _ENGINE_MAP)
        self.assertIn("bing", _ENGINE_MAP)

    def test_unwrap_ddg_redirect(self):
        wrapped = (
            "https://duckduckgo.com/l/?uddg="
            "https%3A%2F%2Fexample.com%2Fpage"
        )
        self.assertEqual(_unwrap_search_url(wrapped), "https://example.com/page")


class TestSslAnalyzer(unittest.TestCase):
    def test_normalize_https_url(self):
        host, port = _normalize_host("https://example.com/path", 443)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)

    def test_normalize_host_port(self):
        host, port = _normalize_host("example.com:8443", 443)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8443)


class TestVulnScanner(unittest.TestCase):
    def test_path_checks_have_name(self):
        for pc in PATH_CHECKS:
            self.assertIn("name", pc)
            self.assertIn("severity", pc)
            self.assertIn("pattern", pc)


class TestVulnDb(unittest.TestCase):
    def test_nginx_known_vuln(self):
        results = cve_lookup("nginx", "1.18.0")
        self.assertGreaterEqual(len(results), 1)


class TestWhois(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertEqual(_normalize_domain("https://magelangkota.go.id/"), "magelangkota.go.id")


class TestSocialOsint(unittest.TestCase):
    def test_403_without_username_is_false(self):
        self.assertFalse(_profile_exists("nobody123xyz", "https://x.com/nobody123xyz", 403, "Forbidden"))

    def test_404_is_false(self):
        self.assertFalse(_profile_exists("user", "https://x.com/user", 404, "Not Found"))


class TestToolHealth(unittest.TestCase):
    def test_health_structure(self):
        h = check_tool_health(include_optional=False)
        self.assertIn("installed", h)
        self.assertIn("missing", h)
        self.assertIn("coverage_percent", h)


class TestFixtureIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_sqli_and_vuln_scan_on_fixture(self):
        from cyber_tools.vulnerable_fixture import vulnerable_fixture
        from cyber_tools.sqli_detect import sqli_detect

        start = json.loads(vulnerable_fixture("start", port=9999))
        self.assertEqual(start.get("status"), "started")
        base = start.get("base_url", "http://127.0.0.1:9999")

        sqli = await sqli_detect(f"{base}/sqli?id=1")
        self.assertTrue(sqli["vulnerable"])

        vulns = await scan_vulnerabilities(base)
        self.assertIn("vulnerabilities", vulns)

        json.loads(vulnerable_fixture("stop", port=9999))


class TestDetectorRegression(unittest.IsolatedAsyncioTestCase):
    """Regression tests for measured detector failures against the fixture."""

    async def asyncSetUp(self):
        from cyber_tools.vulnerable_fixture import vulnerable_fixture
        start = json.loads(vulnerable_fixture("start", port=9999))
        self.assertEqual(start.get("status"), "started")
        self.base = start.get("base_url", "http://127.0.0.1:9999")

    async def asyncTearDown(self):
        from cyber_tools.vulnerable_fixture import vulnerable_fixture
        try:
            json.loads(vulnerable_fixture("stop", port=9999))
        except Exception:
            pass

    async def test_lfi_detect_finds_traversal(self):
        from cyber_tools.lfi_detect import lfi_detect
        r = await lfi_detect(f"{self.base}/lfi?file=x")
        self.assertTrue(r["vulnerable"], f"expected traversal found, got: {r}")

    def test_http_probe_respects_custom_port(self):
        from cyber_tools.http_probe import http_probe
        r = http_probe("http://127.0.0.1:9999")
        self.assertGreaterEqual(len(r["probes"]), 1)

    async def test_vuln_scan_no_svn_false_positive(self):
        from cyber_tools.vuln_scanner import scan_vulnerabilities
        vulns = await scan_vulnerabilities(self.base)
        names = [v["name"] for v in vulns["vulnerabilities"]]
        self.assertNotIn("SVN Entries Exposure", names)

    async def test_cmd_injection_finishes_under_30s(self):
        from cyber_tools.cmd_injection import cmd_injection
        await asyncio.wait_for(cmd_injection(f"{self.base}/cmd", param="host"), timeout=30)

    async def test_open_redirect_finishes_under_30s(self):
        from cyber_tools.open_redirect import open_redirect
        await asyncio.wait_for(open_redirect(f"{self.base}/redirect"), timeout=30)

    async def test_xss_detect_finds_reflected(self):
        from cyber_tools.xss_detect import xss_detect
        r = await xss_detect(f"{self.base}/xss/reflected?q=x")
        self.assertTrue(r["vulnerable"], f"expected reflected XSS, got: {r}")

    async def test_ssrf_detect_finds_localhost_probe(self):
        from cyber_tools.ssrf_detect import ssrf_detect
        r = await ssrf_detect(f"{self.base}/ssrf?url=x")
        self.assertTrue(r["vulnerable"], f"expected SSRF via localhost probe, got: {r}")


if __name__ == "__main__":
    unittest.main()
