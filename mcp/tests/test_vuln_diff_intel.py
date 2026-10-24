"""Stored intel changes are not vulnerability lifecycle changes."""
import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.vuln_diff import vuln_diff
from cyber_tools.finding_contract import finding_fingerprint


def snapshot():
    return {"vulnerabilities": [{
        "type": "cve", "cve": "CVE-2026-109618", "name": "PHP version correlation",
        "matched_at": "https://example.test/", "severity": "critical",
        "confidence": "HIGH", "evidence": "PHP/8.4.26",
        "intel": {"epss": 0.1, "percentile": 0.8, "in_kev": False,
                  "kev_status": "fresh", "patch_priority": "P2-medium",
                  "patch_priority_basis": "EPSS only", "epss_date": "2026-10-23"},
    }], "intel_summary": {"sources": {
        "epss": {"status": "fresh", "fetched_at": "2026-10-23T00:00:00Z"},
        "kev": {"status": "fresh", "fetched_at": "2026-10-23T00:00:00Z",
                "source_date": "2026-10-23", "age_seconds": 0}}}}


def finding(scan):
    return scan["vulnerabilities"][0]


class TestVulnDiffIntel(unittest.TestCase):
    def compare(self, before, after):
        # Offline contract: neither target nor feed traffic is permitted.
        with patch("httpx.AsyncClient", side_effect=AssertionError("network forbidden")):
            return json.loads(vuln_diff(json.dumps(before), json.dumps(after)))

    def assert_no_lifecycle(self, out):
        for field in ("novel", "resolved", "changed", "regressions"):
            self.assertEqual(out["summary"][field], 0)

    def test_priority_change_is_separate_and_keeps_identity(self):
        before = snapshot()
        after = deepcopy(before)
        finding(after)["intel"].update(epss=0.9, patch_priority="P1-high")
        out = self.compare(before, after)
        self.assert_no_lifecycle(out)
        self.assertEqual(out["summary"]["intel_changes"], 1)
        change = out["intel_changes"][0]
        self.assertEqual(change["fingerprint"], finding_fingerprint(finding(before)))
        self.assertIn("epss", change["changed_fields"])
        self.assertEqual(change["before"]["intel"]["epss"], 0.1)
        self.assertEqual(change["after"]["intel"]["epss"], 0.9)
        self.assertIn("INTEL", out["overall"])
        self.assertNotIn("WORSE", out["overall"])

    def test_kev_membership_change_is_not_new_vulnerability(self):
        before = snapshot()
        after = deepcopy(before)
        finding(after)["intel"].update(in_kev=True, patch_priority="P0-patch-now",
                                        patch_priority_basis="KEV")
        out = self.compare(before, after)
        self.assert_no_lifecycle(out)
        self.assertIn("in_kev", out["intel_changes"][0]["changed_fields"])

    def test_expired_feed_is_quality_degradation_not_risk_reduction(self):
        before = snapshot()
        finding(before)["intel"].update(in_kev=True, patch_priority="P0-patch-now")
        after = deepcopy(before)
        finding(after)["intel"].update(in_kev=None, stale_in_kev=True, kev_status="stale",
                                        patch_priority="P2-medium")
        after["intel_summary"]["sources"]["kev"].update(status="stale", age_seconds=3600)
        out = self.compare(before, after)
        self.assert_no_lifecycle(out)
        self.assertEqual(out["intel_changes"][0]["data_quality"], "degraded")
        self.assertIsNone(out["intel_changes"][0]["after"]["intel"]["in_kev"])
        self.assertNotIn("IMPROVED", out["overall"])

    def test_recovered_feed_is_quality_recovery(self):
        after = snapshot()
        before = deepcopy(after)
        finding(before)["intel"].update(in_kev=None, kev_status="unavailable")
        before["intel_summary"]["sources"]["kev"]["status"] = "unavailable"
        out = self.compare(before, after)
        self.assertEqual(out["intel_changes"][0]["data_quality"], "recovered")

    def test_timestamps_and_cache_hit_alone_are_ignored(self):
        before = snapshot()
        after = deepcopy(before)
        finding(after)["intel"].update(epss_date="2026-10-24", kev_status="cached")
        for source in after["intel_summary"]["sources"].values():
            source.update(fetched_at="2026-10-24T00:00:00Z", source_date="2026-10-24",
                          age_seconds=50)
        after["intel_summary"]["sources"]["kev"]["status"] = "cached"
        out = self.compare(before, after)
        self.assertEqual(out["intel_changes"], [])
        self.assertEqual(out["overall"], "No changes detected between scans")

    def test_enrichment_added_removed_and_old_snapshots(self):
        enriched = snapshot()
        legacy = deepcopy(enriched)
        del finding(legacy)["intel"]
        legacy.pop("intel_summary")
        for before, after, quality in ((legacy, enriched, "added"),
                                        (enriched, legacy, "removed")):
            out = self.compare(before, after)
            self.assert_no_lifecycle(out)
            self.assertEqual(out["intel_changes"][0]["data_quality"], quality)
        self.assertEqual(self.compare(legacy, legacy)["intel_changes"], [])

    def test_intel_and_severity_change_can_coexist(self):
        before = snapshot()
        after = deepcopy(before)
        finding(after)["severity"] = "high"
        finding(after)["intel"]["epss"] = 0.8
        out = self.compare(before, after)
        self.assertEqual(out["summary"]["changed"], 1)
        self.assertEqual(out["summary"]["intel_changes"], 1)

    def test_new_or_resolved_findings_do_not_create_intel_events(self):
        for before, after, field in (({}, snapshot(), "novel"), (snapshot(), {}, "resolved")):
            out = self.compare(before, after)
            self.assertEqual(out["summary"][field], 1)
            self.assertEqual(out["intel_changes"], [])

    def test_feed_status_loss_without_score_change_is_visible(self):
        before = snapshot()
        after = deepcopy(before)
        after["intel_summary"]["sources"]["epss"]["status"] = "unavailable"
        out = self.compare(before, after)
        self.assertEqual(out["intel_changes"][0]["data_quality"], "degraded")
        self.assertIn("sources.epss.status", out["intel_changes"][0]["changed_fields"])

    def test_legacy_list_shape_and_malformed_intel_are_tolerated(self):
        before = snapshot()
        after = deepcopy(before)
        finding(before)["intel"] = "not an intel object"
        finding(after)["intel"] = None
        out = self.compare(before["vulnerabilities"], after["vulnerabilities"])
        self.assert_no_lifecycle(out)
        self.assertEqual(out["intel_changes"], [])

    def test_regression_and_intel_events_can_coexist(self):
        before = snapshot()
        finding(before)["status"] = "fixed"
        after = snapshot()
        finding(after)["intel"]["epss"] = 0.8
        out = self.compare(before, after)
        self.assertEqual(out["summary"]["regressions"], 1)
        self.assertEqual(out["summary"]["intel_changes"], 1)
        self.assertIn("REGRESSION", out["overall"])


class TestVulnDiffIntelMcp(unittest.IsolatedAsyncioTestCase):
    async def test_existing_signature_and_intel_output_survive_mcp(self):
        from fastmcp import Client
        from server import mcp
        before = snapshot()
        after = deepcopy(before)
        finding(after)["intel"]["epss"] = 0.8
        async with Client(mcp) as client:
            tools = {tool.name: tool for tool in await client.list_tools()}
            self.assertEqual(set(tools["vuln_diff"].inputSchema["properties"]),
                             {"scan_before", "scan_after"})
            result = await client.call_tool("vuln_diff", {
                "scan_before": json.dumps(before), "scan_after": json.dumps(after)})
        self.assertFalse(result.is_error)
        out = json.loads(result.content[0].text)
        self.assertEqual(out["summary"]["intel_changes"], 1)
        self.assertEqual(out["summary"]["novel"], 0)
