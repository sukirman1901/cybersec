"""Benchmark accounting uses real localhost SQL, including the unchanged old subset."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.benchmark_sqli import CASES, ORIGINAL_CASE_COUNT, benchmark
import test_sqli_sqlite_benchmark as sqlite_fixture


class TestBenchmarkAccounting(unittest.IsolatedAsyncioTestCase):
    async def test_old_subset_is_separated_from_new_coverage(self):
        self.assertEqual(ORIGINAL_CASE_COUNT, 9)
        self.assertEqual(len({case[0] for case in CASES}), len(CASES))
        fixture = sqlite_fixture.TestSQLiteBenchmark
        fixture.setUpClass()
        try:
            report = await benchmark(fixture.base, 1)
        finally:
            fixture.tearDownClass()
        self.assertEqual(report["cases_per_run"], 13)
        self.assertEqual(len(report["results"]), 13)
        self.assertEqual(report["counts"], {
            "true_positive": 9, "true_negative": 4, "false_positive": 0, "false_negative": 0})
        self.assertEqual(report["subset_counts"]["original_nine"], {
            "true_positive": 7, "true_negative": 2, "false_positive": 0, "false_negative": 0})
        self.assertEqual(report["subset_counts"]["additional"], {
            "true_positive": 2, "true_negative": 2, "false_positive": 0, "false_negative": 0})
