"""Benchmark accounting is tested independently of detector accuracy."""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.benchmark_detectors import classify, summarize, run_mock_benchmark, run_mock_case


class TestBenchmarkAccounting(unittest.TestCase):
    def test_confusion_matrix_and_exclusions(self):
        self.assertEqual(classify(True, True), "true_positive")
        self.assertEqual(classify(True, False), "false_negative")
        self.assertEqual(classify(False, True), "false_positive")
        self.assertEqual(classify(False, False), "true_negative")
        self.assertEqual(classify(False, False, error="offline"), "error")
        self.assertEqual(classify(False, False, incomplete=True), "incomplete")
        rows = [{"outcome": name} for name in (
            "true_positive", "true_negative", "false_positive", "false_negative",
            "error", "incomplete")]
        out = summarize(rows)
        self.assertEqual(out["scored"], 4)
        self.assertEqual(out["excluded"], 2)
        self.assertEqual(out["precision"], 0.5)
        self.assertEqual(out["recall"], 0.5)
        self.assertIsNone(summarize([])["precision"])
        self.assertIsNone(summarize([])["recall"])


class TestMockBenchmark(unittest.IsolatedAsyncioTestCase):
    async def test_detector_reported_error_and_timeout_are_not_negative(self):
        for response in ({"error": "synthetic error", "vulnerable": False}, TimeoutError()):
            stub = (AsyncMock(side_effect=response) if isinstance(response, Exception)
                    else AsyncMock(return_value=response))
            with patch("scripts.benchmark_detectors.xss_detect", stub):
                row = await run_mock_case("xss", "raw_html", True)
            self.assertEqual(row["outcome"], "error")

    async def test_rows_are_labelled_and_transport_errors_are_not_clean(self):
        rows = await run_mock_benchmark(1)
        self.assertEqual({r["detector"] for r in rows},
                         {"xss", "ssrf", "joomla", "drupal", "magento"})
        self.assertTrue(all(r["environment"] == "mock_http" for r in rows))
        self.assertEqual(len({r["case"] for r in rows}), len(rows))
        failures = [r for r in rows if r["case"].endswith("transport_error")]
        self.assertTrue(failures)
        self.assertTrue(all(r["outcome"] in ("error", "incomplete") for r in failures))
        self.assertTrue(all(r["unexpected_hosts"] == [] for r in rows))

    async def test_baseline_rows_include_every_fixture_not_just_passes(self):
        rows = await run_mock_benchmark(1)
        self.assertTrue(any(r["known_positive"] for r in rows))
        self.assertTrue(any(not r["known_positive"] for r in rows))
        self.assertTrue(any(r["case"] == "ssrf_generic_200" for r in rows))
        self.assertTrue(any(r["case"] == "xss_plain_text" for r in rows))
        counts = summarize(rows)
        self.assertEqual(sum(counts["counts"].values()), len(rows))

    async def test_blocked_response_remains_incomplete_without_false_positive(self):
        row = await run_mock_case("ssrf", "blocked", False)
        self.assertEqual(row["outcome"], "incomplete")
        self.assertFalse(row["detected"])


class TestMeasuredDetectorRegressions(unittest.IsolatedAsyncioTestCase):
    async def test_static_ssrf_baseline_with_short_control_is_not_new_content(self):
        from cyber_tools.ssrf_detect import _response_content
        baseline = "root:x:0:0:static documentation:/root:/bin/sh"
        self.assertEqual(_response_content(httpx.Response(200, text=baseline),
                                          "http://127.0.0.1", baseline, ["x"]), "")

    async def test_xss_non_html_and_static_script_are_not_positive(self):
        for mode in ("plain_text", "json", "static_script"):
            with self.subTest(mode=mode):
                row = await run_mock_case("xss", mode, False)
                self.assertEqual(row["outcome"], "true_negative")

    async def test_ssrf_generic_and_reflected_content_are_not_positive(self):
        for mode in ("generic_200", "reflected_url", "static_metadata"):
            with self.subTest(mode=mode):
                row = await run_mock_case("ssrf", mode, False)
                self.assertEqual(row["outcome"], "true_negative")

    async def test_cms_soft404_is_not_a_configuration_disclosure(self):
        for detector in ("joomla", "drupal", "magento"):
            with self.subTest(detector=detector):
                row = await run_mock_case(detector, "soft_404", False)
                self.assertEqual(row["outcome"], "true_negative")

    async def test_known_positive_cases_are_preserved(self):
        for detector, mode in (("xss", "raw_html"), ("ssrf", "simulated_file"),
                               ("ssrf", "simulated_metadata"), ("joomla", "disclosure"),
                               ("drupal", "disclosure"), ("magento", "disclosure")):
            with self.subTest(detector=detector, mode=mode):
                row = await run_mock_case(detector, mode, True)
                self.assertEqual(row["outcome"], "true_positive")
