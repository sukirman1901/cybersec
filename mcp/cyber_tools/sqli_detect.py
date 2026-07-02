"""Test for SQL injection via URL parameters — error-based, time-based, UNION, boolean, JSON."""

import httpx
import re
import urllib.parse

SQLI_PAYLOADS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("or_true", "' OR '1'='1"),
    ("or_true_alt", "1 OR 1=1--"),
    ("union", "' UNION SELECT NULL--"),
    ("union_all", "' UNION ALL SELECT 1,2,3--"),
    ("sleep_mysql", "' AND SLEEP(3)--"),
    ("sleep_pg", "'; SELECT pg_sleep(3)--"),
    ("sleep_mssql", "'; WAITFOR DELAY '0:0:3'--"),
]

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Microsoft.*ODBC.*SQL Server",
    r"Driver.*SQL Server",
    r"SQLServer JDBC",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite",
    r"ORA-[0-9]{5}",
    r"Oracle.*driver",
    r"oracle\.jdbc",
    r"unclosed quotation mark",
    r"incorrect syntax near",
]

JSON_SQLI_HINTS = [
    r'"query"\s*:\s*"SELECT',
    r"SQL injection confirmed",
    r'"rows"\s*:\s*\[',
    r"UNION SELECT",
]


def _build_test_urls(target: str, param: str) -> list[tuple[str, str]]:
    """Build baseline URLs and param names to test."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    if params:
        names = [param] if param else list(params.keys())
        return [(base, p) for p in names]

    # No query string — probe common parameter names
    names = [param] if param else ["id", "q", "search", "page", "user", "cat", "item"]
    return [(base, p) for p in names]


async def sqli_detect(target: str, param: str = "") -> dict:
    """Test URL parameters for SQL injection vulnerabilities."""
    test_targets = _build_test_urls(target, param)
    results = []

    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        for base, p in test_targets:
            baseline_val = "1"
            baseline_params = {p: baseline_val}
            baseline_url = f"{base}?{urllib.parse.urlencode(baseline_params)}"
            try:
                baseline_resp = await client.get(baseline_url)
                baseline_body = baseline_resp.text
                baseline_len = len(baseline_body)
            except Exception:
                continue

            for payload_name, payload in SQLI_PAYLOADS:
                try:
                    test_params = {p: baseline_val + payload}
                    url = f"{base}?{urllib.parse.urlencode(test_params)}"
                    resp = await client.get(url)
                    body = resp.text

                    error_detected = any(re.search(err, body, re.I) for err in SQL_ERRORS)
                    json_sqli = any(re.search(h, body, re.I) for h in JSON_SQLI_HINTS)
                    boolean_diff = (
                        not error_detected
                        and abs(len(body) - baseline_len) > max(50, baseline_len * 0.15)
                        and payload_name.startswith("or_")
                    )
                    time_based = (
                        payload_name.startswith("sleep")
                        and resp.elapsed.total_seconds() >= 2.5
                    )

                    if error_detected or json_sqli or boolean_diff or time_based:
                        evidence = []
                        if error_detected:
                            evidence.append("sql_error_in_response")
                        if json_sqli:
                            evidence.append("json_query_leak")
                        if boolean_diff:
                            evidence.append("boolean_content_change")
                        if time_based:
                            evidence.append("time_delay")

                        results.append({
                            "param": p,
                            "payload": payload_name,
                            "payload_value": payload[:50],
                            "error_detected": error_detected,
                            "json_sqli": json_sqli,
                            "boolean_diff": boolean_diff,
                            "time_based": time_based,
                            "evidence": evidence,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                        })
                except Exception:
                    continue

    return {
        "target": target,
        "params_tested": [p for _, p in test_targets],
        "results": results,
        "vulnerable": len(results) > 0,
    }
