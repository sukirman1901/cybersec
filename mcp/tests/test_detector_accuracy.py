"""Detector contract + accuracy regressions for web/CMS/CLI/auto_exploit."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestCmsContentConfirm(unittest.IsolatedAsyncioTestCase):
    async def test_joomla_403_config_is_not_high(self):
        from cyber_tools.joomla_scan import joomla_scan

        def handler(request):
            path = request.url.path
            if path in ("", "/"):
                return httpx.Response(200, text="<html>/media/system/js/ joomla</html>")
            if "configuration" in path:
                return httpx.Response(403, text="Forbidden")
            return httpx.Response(404, text="missing")

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch(
            "cyber_tools.joomla_scan.httpx.AsyncClient",
            side_effect=lambda **kw: real(transport=transport, **{k: v for k, v in kw.items() if k != "transport"}),
        ):
            result = await joomla_scan("https://example.test/")
        self.assertTrue(result["is_joomla"])
        self.assertIn(result["confidence"], ("HIGH", "MEDIUM", "LOW"))
        self.assertIn("coverage", result)
        config = [f for f in result["findings"] if f.get("path") and "configuration" in f["path"]]
        self.assertTrue(config)
        for f in config:
            self.assertNotEqual(f.get("confidence"), "HIGH")
            self.assertNotEqual(str(f.get("severity", "")).lower(), "high")

    async def test_drupal_403_settings_not_disclosure(self):
        from cyber_tools.drupal_scan import drupal_scan

        def handler(request):
            if request.url.path in ("", "/"):
                return httpx.Response(200, text="Drupal sites/default")
            if "settings.php" in request.url.path:
                return httpx.Response(403, text="Forbidden")
            return httpx.Response(404, text="x")

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch(
            "cyber_tools.drupal_scan.httpx.AsyncClient",
            side_effect=lambda **kw: real(transport=transport, **{k: v for k, v in kw.items() if k != "transport"}),
        ):
            result = await drupal_scan("https://example.test/")
        self.assertTrue(result["drupal_detected"])
        settings = [f for f in result["findings"] if "settings.php" in f.get("path", "")]
        self.assertTrue(settings)
        self.assertEqual(settings[0]["severity"], "info")
        self.assertEqual(settings[0]["confidence"], "LOW")

    async def test_magento_env_php_requires_markers_for_high(self):
        from cyber_tools.magento_scan import magento_scan

        def handler(request):
            if request.url.path in ("", "/"):
                return httpx.Response(200, text="Magento Mage theme")
            if request.url.path.endswith("env.php"):
                return httpx.Response(
                    200,
                    text="<?php return ['db' => ['host'=>'x','username'=>'u','password'=>'p','dbname'=>'m']];",
                )
            return httpx.Response(404, text="x")

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch(
            "cyber_tools.magento_scan.httpx.AsyncClient",
            side_effect=lambda **kw: real(transport=transport, **{k: v for k, v in kw.items() if k != "transport"}),
        ):
            result = await magento_scan("https://example.test/")
        env = [f for f in result["findings"] if f.get("path", "").endswith("env.php")]
        self.assertTrue(env)
        self.assertEqual(env[0]["confidence"], "HIGH")
        self.assertIn("content_confirm=True", env[0]["coverage"])


class TestSqliObserveFirst(unittest.IsolatedAsyncioTestCase):
    async def test_sqli_observe_first_has_contract_and_bounds(self):
        from cyber_tools.sqli_detect import sqli_detect

        def handler(request):
            q = request.url.params.get("id", "")
            if "'" in q or "OR" in q.upper():
                return httpx.Response(200, text="You have an error in your SQL syntax; check MySQL")
            return httpx.Response(200, text="ok")

        transport = httpx.MockTransport(handler)
        real = httpx.AsyncClient
        with patch(
            "cyber_tools.sqli_detect.httpx.AsyncClient",
            side_effect=lambda **kw: real(transport=transport, **{k: v for k, v in kw.items() if k != "transport"}),
        ):
            result = await sqli_detect("https://example.test/item", param="id", preset="observe-first")
        self.assertEqual(result["preset"], "observe-first")
        self.assertIn(result["confidence"], ("HIGH", "MEDIUM", "LOW"))
        self.assertIn("preset=observe-first", result["coverage"])
        self.assertTrue(result["vulnerable"])


class TestCliMissing(unittest.IsolatedAsyncioTestCase):
    async def test_nikto_missing_is_cli_missing_not_clean(self):
        from cyber_tools import cli_tools

        with patch.object(cli_tools, "_check", return_value=False):
            result = await cli_tools.nikto_scan("https://example.test")
        self.assertFalse(result["available"])
        self.assertEqual(result["coverage"], "cli_missing")
        self.assertEqual(result["confidence"], "LOW")
        self.assertFalse(result.get("ran", True))
        self.assertEqual(result.get("findings"), [])


class TestAutoExploitGates(unittest.TestCase):
    def setUp(self):
        from cyber_tools import approval_artifact as aa

        aa.PENDING.clear()
        aa.AUDIT.clear()
        aa.COUNTER[0] = 0

    def test_blocked_without_approval(self):
        from cyber_tools.auto_exploit import auto_exploit

        result = json.loads(auto_exploit("https://example.test/", vuln_type="xss", param="q"))
        self.assertTrue(result["blocked"])
        self.assertFalse(result["exploited"])
        self.assertIn("approval_required", result["coverage"])

    def test_verify_no_longer_always_true_for_xss(self):
        from cyber_tools.auto_exploit import _verify

        class Resp:
            def read(self):
                return b"safe page no script"

        def fetch(url):
            return {"status": 200, "body": "safe page no script", "headers": {}, "url": url}

        with patch("cyber_tools.auto_exploit._fetch", side_effect=lambda url: fetch(url), create=True):
            ok, evidence = _verify("https://example.test/", "xss", "q")
        self.assertFalse(ok)
        self.assertIn("payload_not_reflected", evidence)

    def test_approved_but_validate_gate_can_block_exploit_claim(self):
        from cyber_tools.approval_artifact import approval_artifact
        from cyber_tools.auto_exploit import auto_exploit

        req = json.loads(approval_artifact(
            "request",
            tool_name="auto_exploit",
            target="https://example.test/",
            rationale="lab",
        ))
        approval_artifact("approve", artifact_id=req["artifact_id"], approver="tester")

        fetch = {"status": 200, "body": "ok",
                 "headers": {"content-type": "text/plain"},
                 "url": "https://example.test/?q=x"}
        with patch("cyber_tools.auto_exploit._fetch", return_value=fetch, create=True):
            result = json.loads(auto_exploit(
                "https://example.test/",
                vuln_type="xss",
                param="q",
                approval_id=req["artifact_id"],
            ))
        self.assertFalse(result["exploited"])
        phases = [p["phase"] for p in result["phases"]]
        self.assertIn("approval", phases)
        self.assertIn("verify", phases)


if __name__ == "__main__":
    unittest.main()
