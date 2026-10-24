"""Bounded local/offline detector benchmark; no remote-target argument.

Mock HTTP signal classification is not browser execution or actual SSRF. SQLite
results are kept in a separate environment group; repeats are not new targets.
"""
import argparse
import asyncio
import html
import json
from pathlib import Path
import sys
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "mcp"), str(ROOT / "mcp" / "tests")]

from cyber_tools.xss_detect import xss_detect
from cyber_tools.ssrf_detect import ssrf_detect
from cyber_tools.joomla_scan import joomla_scan
from cyber_tools.drupal_scan import drupal_scan
from cyber_tools.magento_scan import magento_scan

OUTCOMES = ("true_positive", "true_negative", "false_positive", "false_negative",
            "error", "incomplete")
DETECTORS = {"xss": xss_detect, "ssrf": ssrf_detect, "joomla": joomla_scan,
             "drupal": drupal_scan, "magento": magento_scan}
CMS = {
    "joomla": ("/configuration.php.bak", "<?php class JConfig { public $password = 'synthetic'; }"),
    "drupal": ("/sites/default/settings.php", "<?php $databases = ['default' => 'synthetic'];"),
    "magento": ("/app/etc/env.php", "<?php return ['db'=>['password'=>'synthetic', 'dbname'=>'lab']];"),
}
MOCK_CASES = (
    [("xss", name, name == "raw_html") for name in
     ("raw_html", "escaped_html", "plain_text", "json", "comment", "static_script", "transport_error")]
    + [("ssrf", name, name in ("simulated_file", "simulated_metadata")) for name in
       ("simulated_file", "simulated_metadata", "generic_200", "blocked", "reflected_url",
        "static_metadata", "transport_error")]
    + [(cms, name, name == "disclosure") for cms in CMS for name in
       ("disclosure", "forbidden", "soft_404", "clean", "transport_error")]
)


def classify(truth, detected, *, error=None, incomplete=False):
    if error:
        return "error"
    if incomplete:
        return "incomplete"
    return ("true_positive" if detected else "false_negative") if truth else (
        "false_positive" if detected else "true_negative")


def summarize(rows):
    counts = {name: sum(row["outcome"] == name for row in rows) for name in OUTCOMES}
    tp, fp, fn = (counts[name] for name in ("true_positive", "false_positive", "false_negative"))
    return {"counts": counts, "scored": sum(counts[k] for k in OUTCOMES[:4]),
            "excluded": counts["error"] + counts["incomplete"],
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


def fixture_response(detector, mode, request):
    """Deterministic response oracle. Never executes SQL, script or URL fetches."""
    if mode == "transport_error":
        raise httpx.ConnectError("synthetic fixture offline", request=request)
    if detector == "xss":
        value = request.url.params.get("q", "")
        if mode == "raw_html":
            return httpx.Response(200, text=f"<html><body>{value}</body></html>", headers={"Content-Type": "text/html"})
        if mode == "escaped_html":
            return httpx.Response(200, text=f"<html>{html.escape(value)}</html>", headers={"Content-Type": "text/html"})
        if mode == "plain_text":
            return httpx.Response(200, text=value, headers={"Content-Type": "text/plain", "X-Content-Type-Options": "nosniff"})
        if mode == "json":
            return httpx.Response(200, json={"value": value})
        if mode == "comment":
            return httpx.Response(200, text=f"<html><!-- {value} --></html>", headers={"Content-Type": "text/html"})
        return httpx.Response(200, text="<html><script>alert(1)</script></html>", headers={"Content-Type": "text/html"})
    if detector == "ssrf":
        value = request.url.params.get("url", "")
        if mode == "simulated_file":
            return httpx.Response(200, text="root:x:0:0:synthetic:/root:/bin/sh") if value.startswith("file:") else httpx.Response(404)
        if mode == "simulated_metadata":
            return httpx.Response(200, text="instance-id: synthetic-instance") if "/latest/meta-data/" in value else httpx.Response(404)
        if mode == "generic_200":
            return httpx.Response(200, text="Welcome to our ordinary home page. " * 10)
        if mode == "blocked":
            return httpx.Response(403, text="Forbidden")
        if mode == "reflected_url":
            return httpx.Response(200, text=f"Requested URL: {value}")
        return httpx.Response(200, text="Documentation: instance-id is a metadata field; no URLs were fetched.")
    path, config = CMS[detector]
    root = f"<html>{detector} login username password database config</html>"
    if request.url.path in ("", "/"):
        return httpx.Response(200, text=root)
    if mode == "soft_404":
        return httpx.Response(200, text=root)
    if request.url.path == path:
        if mode == "disclosure":
            return httpx.Response(200, text=config)
        if mode == "forbidden":
            return httpx.Response(403, text="Forbidden")
    return httpx.Response(404, text="Missing")


async def run_mock_case(detector, mode, truth, run=1):
    requests, statuses, transport_errors, unexpected = [], [], [], []
    def handler(request):
        requests.append(request)
        if request.url.host != "fixture.test" or len(requests) > 1000:
            unexpected.append(str(request.url.host))
            raise httpx.ConnectError("fixture boundary exceeded", request=request)
        try:
            response = fixture_response(detector, mode, request)
        except httpx.HTTPError as exc:
            transport_errors.append(type(exc).__name__)
            raise
        statuses.append(response.status_code)
        return response

    real_client = httpx.AsyncClient
    error, result = None, {}
    with patch("httpx.AsyncClient", side_effect=lambda **kw:
               real_client(transport=httpx.MockTransport(handler),
                           **{k: v for k, v in kw.items() if k != "transport"})):
        try:
            target = "https://fixture.test/"
            if detector == "xss":
                call = xss_detect(target + "?q=original", param="q", use_browser=False)
            elif detector == "ssrf":
                call = ssrf_detect(target + "?url=original")
            else:
                call = DETECTORS[detector](target)
            result = await asyncio.wait_for(call, timeout=10)
            error = result.get("error")
        except Exception as exc:
            error = type(exc).__name__
    if transport_errors or unexpected:
        error = error or "transport_error"
    incomplete = ((bool(statuses) and all(status in (403, 429) for status in statuses))
                  or result.get("coverage_complete") is False
                  or "deadline_reached" in str(result.get("coverage", "")))
    detected = bool(result.get("vulnerable", False))
    return {"run": run, "case": f"{detector}_{mode}", "detector": detector,
            "environment": "mock_http", "known_positive": truth, "detected": detected,
            "outcome": classify(truth, detected, error=error, incomplete=incomplete),
            "error": error, "incomplete": incomplete, "requests": len(requests),
            "transport_errors": len(transport_errors), "unexpected_hosts": unexpected,
            "findings": result.get("total_findings", result.get("count", 0))}


async def run_mock_benchmark(runs):
    rows = []
    for run in range(1, runs + 1):
        for detector, mode, truth in MOCK_CASES:
            rows.append(await run_mock_case(detector, mode, truth, run))
    return rows


async def run_sqlite_benchmark(runs):
    from scripts.benchmark_sqli import CASES
    from cyber_tools.sqli_detect import sqli_detect
    from test_sqli_sqlite_benchmark import TestSQLiteBenchmark
    rows = []
    TestSQLiteBenchmark.setUpClass()
    try:
        for run in range(1, runs + 1):
            for name, path, value, preset, truth in CASES:
                error, result = None, {}
                try:
                    result = await asyncio.wait_for(sqli_detect(
                        f"{TestSQLiteBenchmark.base}{path}?id={value}&tenant=qa%20team", "id", preset), 60)
                    error = result.get("error")
                except Exception as exc:
                    error = type(exc).__name__
                incomplete = not result.get("coverage_complete", False)
                detected = bool(result.get("vulnerable", False))
                rows.append({"run": run, "case": name, "detector": "sqli",
                             "environment": "localhost_http_sqlite", "known_positive": truth,
                             "detected": detected, "preset": preset, "error": error,
                             "incomplete": incomplete, "requests": result.get("requests_sent", 0),
                             "outcome": classify(truth, detected, error=error, incomplete=incomplete)})
    finally:
        TestSQLiteBenchmark.tearDownClass()
    return rows


def report(rows, runs):
    groups = {}
    for row in rows:
        key = f"{row['detector']}:{row['environment']}"
        groups.setdefault(key, []).append(row)
    return {"schema_version": 1, "runs": runs, "case_executions": len(rows),
            "groups": {key: summarize(group) for key, group in groups.items()}, "results": rows,
            "limitations": ["Synthetic selected cases, not real-world detection accuracy",
                            "Repeated runs/presets are not independent targets",
                            "XSS static reflection only; no browser execution measured",
                            "SSRF response simulation only; no actual fetch/OOB/cloud access",
                            "CMS positive means sensitive configuration exposure, not CMS presence",
                            "Error/incomplete rows are excluded from precision/recall, not treated safe",
                            "SQLite subset only; no other database/timing/WAF claims"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--mock-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("--runs must be between 1 and 10")
    async def run():
        rows = await run_mock_benchmark(args.runs)
        if not args.mock_only:
            rows.extend(await run_sqlite_benchmark(args.runs))
        return report(rows, args.runs)
    print(json.dumps(asyncio.run(run()), indent=2, allow_nan=False))


if __name__ == "__main__":
    # Support both direct CLI execution and namespace imports from repository root.
    sys.path.insert(0, str(ROOT))
    main()
