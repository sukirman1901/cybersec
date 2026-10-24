"""Harness parity helpers, quality gates, and bounded flaky-module regressions."""

from __future__ import annotations

import asyncio
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[2]


class TestHarnessParity(unittest.TestCase):
    def test_cursor_agents_mirror_opencode_roles(self):
        cursor = {p.stem for p in (ROOT / "agents").glob("*.md")}
        opencode = {p.stem for p in (ROOT / ".opencode" / "agents").glob("*.md")}
        self.assertTrue({"pentester", "recon", "vuln-analyst", "report-writer"} <= cursor)
        self.assertTrue({"pentester", "recon", "vuln-analyst", "report-writer"} <= opencode)
        plugin = json.loads((ROOT / ".cursor-plugin" / "plugin.json").read_text())
        self.assertEqual(plugin.get("agents"), "./agents/")
        self.assertEqual(plugin.get("rules"), "./rules/")
        self.assertTrue((ROOT / "rules" / "cybersec-pipeline.mdc").is_file())

    def test_cursor_agent_frontmatter_has_name(self):
        text = (ROOT / "agents" / "recon.md").read_text()
        self.assertIn("name: recon", text)
        self.assertIn("permissionMode: readonly", text)


class TestWorkflowPresets(unittest.TestCase):
    def test_observe_first_is_default_and_gated(self):
        from cyber_tools.pentest_workflow import pentest_workflow
        plan = json.loads(pentest_workflow("example.test"))
        self.assertEqual(plan["preset"], "observe-first")
        tools = [s["tool"] for s in plan["steps"]]
        self.assertEqual(tools[0], "engagement_gate")
        self.assertIn("findings_manager", tools)
        self.assertIn("report_schema_v2", tools)
        self.assertIn("branded_report", tools)

    def test_staging_deep_keeps_approval_and_retest(self):
        from cyber_tools.pentest_workflow import pentest_workflow
        plan = json.loads(pentest_workflow("example.test", template="staging-deep"))
        tools = [s["tool"] for s in plan["steps"]]
        self.assertIn("approval_artifact", tools)
        self.assertIn("retest_vuln", tools)
        self.assertIn("idor_access_validation", tools)

    def test_scan_template_observe_first(self):
        from cyber_tools.scan_template import scan_template
        plan = json.loads(scan_template("example.test"))
        self.assertEqual(plan["template"], "observe-first")
        self.assertEqual(plan["steps"][0]["tool"], "engagement_gate")


class TestReportQualityGates(unittest.TestCase):
    def test_schema_requires_confidence_and_coverage(self):
        from cyber_tools.report_schema_v2 import report_schema_v2
        bad = report_schema_v2("validate", json.dumps([{
            "title": "XSS", "severity": "high", "evidence": "reflected",
        }]))
        result = json.loads(bad)
        self.assertFalse(result["is_valid"])
        errors = " ".join(e for item in result["error_details"] for e in item["errors"])
        self.assertIn("confidence", errors.lower())
        self.assertIn("coverage", errors.lower())

        good = report_schema_v2("validate", json.dumps([{
            "title": "XSS", "severity": "high", "evidence": "reflected",
            "confidence": "HIGH", "coverage": "preset=observe-first; params=1",
        }]))
        self.assertTrue(json.loads(good)["is_valid"])


class TestIdorDualRole(unittest.TestCase):
    def test_single_role_is_low_confidence(self):
        from cyber_tools.idor_access_validation import idor_access_validation

        def fake_urlopen(req, timeout=8):
            class Resp:
                status = 200
                def read(self):
                    return b'{"id":1,"secret":true}'
            return Resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = json.loads(idor_access_validation(
                "https://example.test/api/item", resource_ids="1,2",
                user_a_cookie="sid=a",
            ))
        self.assertFalse(result["dual_role_tested"])
        self.assertEqual(result["confidence"], "LOW")
        self.assertIn("dual_role_not_tested", result["coverage"])

    def test_dual_role_hash_match_without_private_ownership_is_unverified(self):
        from cyber_tools.idor_access_validation import idor_access_validation

        def fake_urlopen(req, timeout=8):
            class Resp:
                status = 200
                def read(self):
                    return b'{"id":1,"owner":"shared"}'
            return Resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = json.loads(idor_access_validation(
                "https://example.test/api/item", resource_ids="1",
                user_a_cookie="sid=a", user_b_cookie="sid=b",
            ))
        self.assertTrue(result["dual_role_tested"])
        self.assertFalse(result["bola_found"])
        self.assertTrue(result["cross_role_access_observed"])
        self.assertEqual(result["confidence"], "LOW")


class TestBoundedFlakyModules(unittest.IsolatedAsyncioTestCase):
    async def test_cors_observe_first_finishes_quickly(self):
        from cyber_tools.cors_check import cors_check

        def handler(request):
            return httpx.Response(200, headers={
                "Access-Control-Allow-Origin": request.headers.get("Origin", ""),
                "Access-Control-Allow-Credentials": "true",
            })

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch("cyber_tools.cors_check.httpx.AsyncClient",
                   side_effect=lambda **kw: real(transport=transport, **kw)):
            started = time.monotonic()
            result = await cors_check("https://example.test/", preset="observe-first")
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 8.0)
        self.assertIn("confidence", result)
        self.assertIn("coverage", result)
        self.assertEqual(result["preset"], "observe-first")
        self.assertTrue(result["vulnerable"])

    async def test_laravel_scan_has_coverage_and_budget(self):
        from cyber_tools.laravel_scan import laravel_scan

        def handler(request):
            if request.url.path == "/.env":
                return httpx.Response(200, text="APP_KEY=base64:x\nDB_PASSWORD=secret")
            return httpx.Response(404, text="missing")

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch("cyber_tools.laravel_scan.httpx.AsyncClient",
                   side_effect=lambda **kw: real(transport=transport, **kw)):
            result = await laravel_scan("https://example.test/", preset="observe-first")
        self.assertGreaterEqual(result["count"], 1)
        self.assertIn(result["confidence"], ("HIGH", "MEDIUM", "LOW"))
        self.assertIn("preset=observe-first", result["coverage"])

    async def test_xss_detect_observe_first_skips_stored_and_bounds(self):
        from cyber_tools.xss_detect import xss_detect

        calls = []

        def handler(request):
            calls.append(request)
            q = dict(request.url.params)
            body = f"search={next(iter(q.values()), '')}" if q else "ok"
            return httpx.Response(200, text=body)

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch("cyber_tools.xss_detect.httpx.AsyncClient",
                   side_effect=lambda **kw: real(transport=transport, **kw)):
            started = time.monotonic()
            result = await xss_detect("https://example.test/?q=test", preset="observe-first")
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 12.0)
        self.assertIn("stored_xss_skipped", result["coverage"])
        self.assertIn(result["confidence"], ("HIGH", "MEDIUM", "LOW"))
        self.assertTrue(all(r.method in ("GET", "POST") for r in calls))


if __name__ == "__main__":
    unittest.main()
