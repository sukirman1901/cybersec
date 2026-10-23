"""Repeat the localhost SQLite benchmark and print bounded, labeled results.

Run from the repository root using the MCP virtualenv Python. This command has no
remote-target option. The server uses an ephemeral loopback port and synthetic data.
"""

import argparse
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "mcp"), str(ROOT / "mcp" / "tests")]

from cyber_tools.sqli_detect import sqli_detect
from test_sqli_sqlite_benchmark import TestSQLiteBenchmark


CASES = [
    ("numeric_error", "/unsafe-numeric", "7", "observe-first", True),
    ("string_error", "/unsafe-string", "alpha", "observe-first", True),
    ("numeric_blind", "/unsafe-numeric-blind", "7", "observe-first", True),
    ("string_blind", "/unsafe-string-blind", "alpha", "observe-first", True),
    ("equal_length_blind", "/unsafe-numeric-equal-blind", "7", "observe-first", True),
    ("safe_numeric", "/safe-numeric", "7", "observe-first", False),
    ("safe_string", "/safe-string", "alpha", "observe-first", False),
    ("empty_baseline_blind", "/unsafe-numeric-blind", "999", "observe-first", True),
    ("deep_string_blind", "/unsafe-string-blind", "alpha", "staging-deep", True),
]


async def benchmark(base, runs):
    rows = []
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    for run in range(runs):
        for name, path, value, preset, truth in CASES:
            result = await sqli_detect(f"{base}{path}?id={value}&tenant=qa%20team", "id", preset)
            found = result["vulnerable"]
            key = ("true_positive" if found else "false_negative") if truth else (
                "false_positive" if found else "true_negative")
            counts[key] += 1
            rows.append({"run": run + 1, "case": name, "known_vulnerable": truth,
                         "detected": found, "assessment": result["assessment"],
                         "techniques": result["techniques_found"],
                         "requests": result["requests_sent"], "outcome": key})
    return {"environment": "localhost HTTP + in-memory SQLite; synthetic rows only",
            "runs": runs, "cases_per_run": len(CASES), "counts": counts, "results": rows,
            "limitations": ["Empty-result blind baseline is a known false negative",
                            "Repeated presets are not independent real-world targets",
                            "No claims about MySQL/PostgreSQL/MSSQL, timing, UNION or WAF bypass"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("--runs must be between 1 and 10")
    TestSQLiteBenchmark.setUpClass()
    try:
        print(json.dumps(asyncio.run(benchmark(TestSQLiteBenchmark.base, args.runs)), indent=2))
    finally:
        TestSQLiteBenchmark.tearDownClass()
