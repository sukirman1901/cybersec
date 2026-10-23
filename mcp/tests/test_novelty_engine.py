"""Novelty engine v1 — fingerprints, triage, vuln_diff, nuclei flag."""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestFindingContract(unittest.TestCase):
    def test_fingerprint_distinguishes_path_and_param(self):
        from cyber_tools.finding_contract import finding_fingerprint

        a = {"target": "https://ex.test/a", "type": "xss", "param": "q", "evidence": "reflected"}
        b = {"target": "https://ex.test/b", "type": "xss", "param": "q", "evidence": "reflected"}
        c = {"target": "https://ex.test/a", "type": "xss", "param": "id", "evidence": "reflected"}
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(c))

    def test_validate_requires_confidence_coverage(self):
        from cyber_tools.finding_contract import validate_contract

        bad = validate_contract({"title": "XSS", "severity": "high", "target": "https://x.test"})
        self.assertFalse(bad["ok"])
        good = validate_contract({
            "title": "XSS", "severity": "high", "target": "https://x.test",
            "confidence": "HIGH", "coverage": "reflected_probe", "evidence": "alert",
        })
        self.assertTrue(good["ok"])
        self.assertEqual(good["normalized"]["confidence"], "HIGH")


class TestFindingsManagerNovelty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "findings.json"
        import cyber_tools.findings_manager as fm
        self.fm = fm
        self._orig = fm.FINDINGS_DB
        fm.FINDINGS_DB = str(self.db_path)

    def tearDown(self):
        self.fm.FINDINGS_DB = self._orig
        self.tmp.cleanup()

    def _finding(self, path="/x", param="q", **extra):
        base = {
            "title": "Reflected XSS",
            "type": "xss",
            "severity": "high",
            "target": f"https://example.test{path}",
            "param": param,
            "confidence": "HIGH",
            "coverage": "unit-test",
            "evidence": f"payload reflected on {path}?{param}=",
        }
        base.update(extra)
        return base

    def test_add_rejects_missing_quality(self):
        result = json.loads(self.fm.findings_manager(
            "add", findings_json=json.dumps({"title": "x", "severity": "high", "target": "https://t"}),
        ))
        self.assertEqual(result["added"], 0)
        self.assertGreaterEqual(result["rejected_count"], 1)

    def test_add_novel_then_duplicate_then_regression(self):
        f = self._finding()
        first = json.loads(self.fm.findings_manager("add", findings_json=json.dumps([f])))
        self.assertEqual(first["added"], 1)
        fid = json.loads(self.fm.findings_manager("list"))["findings"][0]["id"]

        second = json.loads(self.fm.findings_manager("add", findings_json=json.dumps([f])))
        self.assertEqual(second["duplicates"], 1)
        self.assertEqual(second["added"], 0)

        self.fm.findings_manager("update", finding_id=fid, status="fixed")
        third = json.loads(self.fm.findings_manager("add", findings_json=json.dumps([f])))
        self.assertEqual(third["regressions"], 1)
        listed = json.loads(self.fm.findings_manager("list"))["findings"][0]
        self.assertEqual(listed["triage"], "regression")
        self.assertEqual(listed["status"], "new")

    def test_novelty_action_classifies_without_persist(self):
        f = self._finding()
        self.fm.findings_manager("add", findings_json=json.dumps([f]))
        other = self._finding(path="/y", param="search")
        result = json.loads(self.fm.findings_manager(
            "novelty", findings_json=json.dumps([f, other]),
        ))
        self.assertEqual(result["summary"]["duplicate"], 1)
        self.assertEqual(result["summary"]["novel"], 1)
        self.assertEqual(result["persisted_novel"], 0)
        self.assertEqual(json.loads(self.fm.findings_manager("stats"))["total"], 1)


class TestVulnDiffNovelty(unittest.TestCase):
    def test_port_diff_no_nameerror(self):
        from cyber_tools.vuln_diff import vuln_diff

        result = json.loads(vuln_diff(
            json.dumps({"vulnerabilities": [], "open_ports": [{"port": 80}]}),
            json.dumps({"vulnerabilities": [], "open_ports": [{"port": 443}]}),
        ))
        self.assertEqual(set(result["summary"]["new_open_ports"]), {443})
        self.assertEqual(set(result["summary"]["closed_ports"]), {80})

    def test_fingerprint_novelty_and_regression(self):
        from cyber_tools.vuln_diff import vuln_diff

        finding = {
            "type": "xss", "severity": "high", "target": "https://ex.test/a",
            "param": "q", "confidence": "HIGH", "coverage": "t", "evidence": "x",
        }
        before = {"findings": [{**finding, "status": "fixed"}]}
        after = {"findings": [finding]}
        result = json.loads(vuln_diff(json.dumps(before), json.dumps(after)))
        self.assertEqual(result["summary"]["regressions"], 1)
        self.assertIn("REGRESSION", result["overall"])


class TestNucleiFlag(unittest.TestCase):
    def test_uses_jsonl_short_flag(self):
        from cyber_tools import nuclei_scan as mod
        src = inspect.getsource(mod.nuclei_scan)
        self.assertIn('"-j"', src)
        self.assertNotIn('"-json"', src)


class TestWordpressContract(unittest.IsolatedAsyncioTestCase):
    async def test_non_wp_has_coverage(self):
        import httpx
        from cyber_tools.wordpress_scan import wordpress_scan

        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html>hello</html>"))
        real = httpx.AsyncClient
        with patch("cyber_tools.wordpress_scan.httpx.AsyncClient",
                   side_effect=lambda **kw: real(transport=transport, **kw)):
            result = await wordpress_scan("https://example.test/")
        self.assertFalse(result["is_wordpress"])
        self.assertIn("confidence", result)
        self.assertIn("coverage", result)


if __name__ == "__main__":
    unittest.main()
