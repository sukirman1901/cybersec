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


if __name__ == "__main__":
    unittest.main()
