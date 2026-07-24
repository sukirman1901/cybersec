"""Deep IDOR detection — cross-user testing, response comparison, method variation, header auth, GraphQL."""

import httpx
import urllib.parse
import re
import json
import asyncio

# --- Common ID Parameter Patterns ---
ID_PATTERNS = [
    ("sequential", ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]),
    ("high_ids", ["100", "101", "200", "500", "1000"]),
    ("negative", ["-1", "0"]),
    ("uuid", ["550e8400-e29b-41d4-a716-446655440000", "00000000-0000-0000-0000-000000000001"]),
    ("hash_like", ["abc123", "deadbeef", "cafebabe"]),
]

# --- Path Conventions ---
PATH_CONVENTIONS = [
    "/{id}",
    "/{id}/",
    "/{id}/edit",
    "/{id}/view",
    "/{id}/details",
    "/{id}/info",
    "/{id}/profile",
    "/{id}/account",
    "/{id}/settings",
    "/api/{id}",
    "/api/v1/{id}",
    "/api/users/{id}",
    "/api/items/{id}",
    "/api/objects/{id}",
    "/api/resources/{id}",
    "/graphql?id={id}",
    "/user/{id}",
    "/users/{id}",
    "/item/{id}",
    "/items/{id}",
    "/order/{id}",
    "/orders/{id}",
    "/admin/{id}",
]

# --- HTTP Methods to Test ---
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# --- Header Auth Variants ---
AUTH_HEADERS = [
    {"Authorization": "Bearer test_token_123"},
    {"X-Auth-Token": "test_token_123"},
    {"X-API-Key": "test_api_key_123"},
    {"Cookie": "session=test_session_123"},
    {"X-User-ID": "1"},
    {"X-Account-ID": "1"},
    {"X-Customer-ID": "1"},
]

# --- Response Comparison Indicators ---
SENSITIVE_INDICATORS = [
    "email", "phone", "address", "password", "token", "secret",
    "credit_card", "ssn", "social_security", "bank", "account_number",
    "private", "confidential", "internal", "admin", "root",
]

# --- GraphQL IDOR ---
GRAPHQL_QUERIES = [
    '{"query":"query{user(id:1){id,email,name}}"}',
    '{"query":"query{user(id:2){id,email,name}}"}',
    '{"query":"query{order(id:1){id,total,items}}"}',
    '{"query":"query{profile(id:1){id,bio,avatar}}"}',
]


def _compare_responses(baseline: dict, candidate: dict) -> dict:
    """Compare baseline and candidate responses for IDOR indicators."""
    indicators = []

    # Status code difference
    if baseline["status"] != candidate["status"]:
        indicators.append(f"Status changed: {baseline['status']} → {candidate['status']}")

    # Size difference
    size_diff = abs(baseline["size"] - candidate["size"])
    if size_diff > 50:
        indicators.append(f"Size difference: {size_diff} bytes")

    # Sensitive data in candidate but not baseline
    for indicator in SENSITIVE_INDICATORS:
        if indicator in candidate["body"].lower() and indicator not in baseline["body"].lower():
            indicators.append(f"New sensitive data: '{indicator}'")

    # User-specific data patterns
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    baseline_emails = set(re.findall(email_pattern, baseline["body"]))
    candidate_emails = set(re.findall(email_pattern, candidate["body"]))
    new_emails = candidate_emails - baseline_emails
    if new_emails:
        indicators.append(f"New emails exposed: {list(new_emails)[:3]}")

    # JSON field differences
    try:
        baseline_json = json.loads(baseline["body"])
        candidate_json = json.loads(candidate["body"])
        if isinstance(baseline_json, dict) and isinstance(candidate_json, dict):
            for key in candidate_json:
                if key not in baseline_json:
                    indicators.append(f"New JSON field: '{key}'")
                elif baseline_json[key] != candidate_json[key]:
                    indicators.append(f"JSON field changed: '{key}'")
    except (json.JSONDecodeError, TypeError):
        pass

    return {
        "indicators": indicators,
        "has_differences": len(indicators) > 0,
        "severity": "CRITICAL" if any("email" in i or "password" in i or "token" in i for i in indicators) else "HIGH" if indicators else "NONE",
    }


async def idor_detect(target: str, ids: str = "1,2,3", param: str = "") -> dict:
    """Deep IDOR detection with cross-user testing, response comparison, method variation."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    test_ids = [i.strip() for i in ids.split(",") if i.strip()]
    if not test_ids:
        test_ids = ["1", "2", "3", "4", "5"]

    results = []
    idor_findings = []

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Get baseline with first ID
        baseline_body = ""
        baseline_status = 200
        baseline_size = 0
        try:
            baseline_resp = await client.get(target)
            baseline_body = baseline_resp.text
            baseline_status = baseline_resp.status_code
            baseline_size = len(baseline_body)
        except Exception:
            pass

        baseline = {"status": baseline_status, "size": baseline_size, "body": baseline_body}

        # --- Path-based IDOR ---
        for id_val in test_ids:
            for convention in PATH_CONVENTIONS:
                try:
                    path = convention.replace("{id}", id_val)
                    url = f"{base}{path}"
                    resp = await client.get(url)
                    candidate = {"status": resp.status_code, "size": len(resp.text), "body": resp.text}
                    comparison = _compare_responses(baseline, candidate)

                    if comparison["has_differences"] or (resp.status_code == 200 and resp.status_code != 404):
                        result = {
                            "technique": "path_idor",
                            "url": url,
                            "id": id_val,
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "comparison": comparison,
                            "idor_possible": resp.status_code == 200 and resp.status_code != 404,
                            "risk": comparison["severity"] if comparison["has_differences"] else "MEDIUM",
                        }
                        results.append(result)
                        if result["idor_possible"]:
                            idor_findings.append(result)
                except Exception:
                    continue

        # --- Query Parameter IDOR ---
        for id_val in test_ids[:3]:
            try:
                param_name = param or "id"
                url = f"{target}?{param_name}={id_val}"
                resp = await client.get(url)
                candidate = {"status": resp.status_code, "size": len(resp.text), "body": resp.text}
                comparison = _compare_responses(baseline, candidate)

                if comparison["has_differences"] or resp.status_code == 200:
                    result = {
                        "technique": "query_idor",
                        "url": url,
                        "id": id_val,
                        "param": param_name,
                        "status": resp.status_code,
                        "comparison": comparison,
                        "idor_possible": resp.status_code == 200,
                        "risk": comparison["severity"] if comparison["has_differences"] else "MEDIUM",
                    }
                    results.append(result)
                    if result["idor_possible"]:
                        idor_findings.append(result)
            except Exception:
                continue

        # --- HTTP Method Variation ---
        for method in HTTP_METHODS:
            try:
                resp = await client.request(method, target)
                if resp.status_code == 200 and method != "GET":
                    result = {
                        "technique": "method_variation",
                        "method": method,
                        "url": target,
                        "status": resp.status_code,
                        "idor_possible": True,
                        "risk": "HIGH",
                    }
                    results.append(result)
                    idor_findings.append(result)
            except Exception:
                continue

        # --- Auth Header IDOR ---
        for headers in AUTH_HEADERS:
            try:
                resp = await client.get(target, headers=headers)
                if resp.status_code == 200:
                    candidate = {"status": resp.status_code, "size": len(resp.text), "body": resp.text}
                    comparison = _compare_responses(baseline, candidate)
                    if comparison["has_differences"]:
                        result = {
                            "technique": "auth_header_idor",
                            "headers": list(headers.keys()),
                            "status": resp.status_code,
                            "comparison": comparison,
                            "idor_possible": True,
                            "risk": "CRITICAL",
                        }
                        results.append(result)
                        idor_findings.append(result)
                        break
            except Exception:
                continue

        # --- GraphQL IDOR ---
        for query in GRAPHQL_QUERIES:
            try:
                resp = await client.post(
                    f"{base}/graphql",
                    content=query,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200 and "data" in resp.text:
                    result = {
                        "technique": "graphql_idor",
                        "query": query[:100],
                        "status": resp.status_code,
                        "idor_possible": True,
                        "risk": "HIGH",
                    }
                    results.append(result)
                    idor_findings.append(result)
            except Exception:
                continue

        # --- Negative/Zero ID ---
        for id_val in ["0", "-1", "-100", "99999999"]:
            try:
                path = f"/{id_val}"
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200:
                    candidate = {"status": resp.status_code, "size": len(resp.text), "body": resp.text}
                    comparison = _compare_responses(baseline, candidate)
                    if comparison["has_differences"]:
                        result = {
                            "technique": "negative_id_idor",
                            "id": id_val,
                            "status": resp.status_code,
                            "comparison": comparison,
                            "idor_possible": True,
                            "risk": "HIGH",
                        }
                        results.append(result)
                        idor_findings.append(result)
            except Exception:
                continue

    return {
        "target": target,
        "test_ids": test_ids,
        "results": results,
        "idor_candidates": idor_findings,
        "total_findings": len(results),
        "idor_count": len(idor_findings),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }
