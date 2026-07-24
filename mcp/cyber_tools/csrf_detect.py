"""Deep CSRF detection — token analysis, SameSite, Origin validation, method variation, cookie security."""

import httpx
import re
import urllib.parse
import json
import hashlib
import asyncio

# --- CSRF Token Patterns ---
TOKEN_PATTERNS = [
    r'csrf[_-]?token',
    r'_token',
    r'authenticity[_-]?token',
    r'xsrf[_-]?token',
    r'__RequestVerificationToken',
    r'csrfmiddlewaretoken',
    r'anti[_-]?forgery[_-]?token',
    r'__VIEWSTATE',
    r'__EVENTVALIDATION',
    r'nonce',
    r'_csrf',
    r'csrf_token',
    r'verification[_-]?token',
    r'security[_-]?token',
]

# --- Cookie Security Patterns ---
COOKIE_FLAGS = [
    "httponly",
    "secure",
    "samesite",
    "samesite=strict",
    "samesite=lax",
    "samesite=none",
]

# --- State-Changing Methods ---
STATE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

# --- Common Form Fields That Should Be Protected ---
SENSITIVE_ACTIONS = [
    "password", "email", "transfer", "payment", "delete",
    "update", "create", "admin", "settings", "profile",
    "invite", "share", "grant", "revoke", "approve",
]


def _analyze_token(token_value: str) -> dict:
    """Analyze CSRF token for weaknesses."""
    analysis = {
        "length": len(token_value),
        "entropy": "low",
        "pattern": "unknown",
        "weaknesses": [],
    }

    # Check entropy
    if len(token_value) >= 32:
        analysis["entropy"] = "high"
    elif len(token_value) >= 16:
        analysis["entropy"] = "medium"
    else:
        analysis["entropy"] = "low"
        analysis["weaknesses"].append("Token too short (< 16 chars)")

    # Check pattern
    if re.match(r'^[0-9]+$', token_value):
        analysis["pattern"] = "numeric_only"
        analysis["weaknesses"].append("Numeric-only token (predictable)")
    elif re.match(r'^[a-f0-9]+$', token_value):
        analysis["pattern"] = "hex"
        if len(token_value) == 32:
            analysis["weaknesses"].append("MD5-like hash (32 hex chars)")
        elif len(token_value) == 40:
            analysis["weaknesses"].append("SHA1-like hash (40 hex chars)")
    elif re.match(r'^[A-Za-z0-9+/]+=*$', token_value):
        analysis["pattern"] = "base64"
        analysis["weaknesses"].append("Base64-encoded token (check for predictable data)")
    elif re.match(r'^[A-Za-z0-9_-]+$', token_value):
        analysis["pattern"] = "alphanumeric_safe"

    # Check for predictable patterns
    if len(set(token_value)) < 10:
        analysis["weaknesses"].append("Low character diversity (predictable)")
    if re.search(r'(0{8,}|1{8,}|a{8,})', token_value):
        analysis["weaknesses"].append("Repeating characters (weak entropy)")

    return analysis


def _analyze_cookies(set_cookie_header: str) -> dict:
    """Analyze cookie security flags."""
    if not set_cookie_header:
        return {"flags_present": [], "flags_missing": ["httponly", "secure", "samesite"], "risk": "HIGH"}

    lower_header = set_cookie_header.lower()
    flags_present = []
    flags_missing = []

    for flag in COOKIE_FLAGS:
        if flag in lower_header:
            flags_present.append(flag)
        else:
            flags_missing.append(flag)

    return {
        "flags_present": flags_present,
        "flags_missing": flags_missing,
        "risk": "HIGH" if "httponly" in flags_missing or "secure" in flags_missing else "MEDIUM",
    }


async def csrf_detect(target: str) -> dict:
    """Deep CSRF detection with token analysis, SameSite, Origin validation, method variation."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    results = []
    forms = []
    cookie_analysis = {}
    header_analysis = {}

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # --- Fetch main page ---
        try:
            resp = await client.get(target)
            body = resp.text
        except Exception:
            return {"target": target, "error": "Failed to fetch target"}

        # --- Analyze cookies ---
        set_cookie = resp.headers.get("set-cookie", "")
        cookie_analysis = _analyze_cookies(set_cookie)

        # --- Analyze security headers ---
        security_headers = {
            "X-Frame-Options": resp.headers.get("x-frame-options", ""),
            "X-Content-Type-Options": resp.headers.get("x-content-type-options", ""),
            "Strict-Transport-Security": resp.headers.get("strict-transport-security", ""),
            "Content-Security-Policy": resp.headers.get("content-security-policy", ""),
        }
        header_analysis = {k: bool(v) for k, v in security_headers.items()}

        # --- Find and analyze forms ---
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, body, re.DOTALL | re.IGNORECASE)

        for i, form_content in enumerate(form_matches):
            form_result = {
                "form_index": i + 1,
                "has_csrf_token": False,
                "token_details": None,
                "method": "GET",
                "action": "same page",
                "has_sensitive_fields": False,
                "sensitive_fields": [],
                "vulnerable": False,
            }

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.I)
            if method_match:
                form_result["method"] = method_match.group(1).upper()

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.I)
            if action_match:
                form_result["action"] = action_match.group(1)

            # Check for CSRF token
            for pattern in TOKEN_PATTERNS:
                token_match = re.search(
                    rf'name=["\']([^"\']*{pattern}[^"\']*)["\'].*?value=["\']([^"\']*)["\']',
                    form_content, re.I
                )
                if not token_match:
                    token_match = re.search(
                        rf'value=["\']([^"\']*)["\'].*?name=["\']([^"\']*{pattern}[^"\']*)["\']',
                        form_content, re.I
                    )
                if token_match:
                    form_result["has_csrf_token"] = True
                    token_value = token_match.group(2) or token_match.group(1)
                    form_result["token_details"] = _analyze_token(token_value)
                    break

            # Check meta tag tokens
            if not form_result["has_csrf_token"]:
                meta_match = re.search(
                    rf'<meta[^>]*name=["\'][^"\']*csrf[^"\']*["\'][^>]*content=["\']([^"\']*)["\']',
                    body, re.I
                )
                if meta_match:
                    form_result["has_csrf_token"] = True
                    form_result["token_details"] = _analyze_token(meta_match.group(1))

            # Check for sensitive fields
            for field_pattern in SENSITIVE_ACTIONS:
                if re.search(rf'name=["\'][^"\']*{field_pattern}[^"\']*["\']', form_content, re.I):
                    form_result["has_sensitive_fields"] = True
                    form_result["sensitive_fields"].append(field_pattern)

            # Determine vulnerability
            if form_result["method"] in STATE_METHODS and not form_result["has_csrf_token"]:
                form_result["vulnerable"] = True
                form_result["risk"] = "HIGH"
            elif form_result["has_csrf_token"] and form_result["token_details"] and form_result["token_details"]["weaknesses"]:
                form_result["vulnerable"] = True
                form_result["risk"] = "MEDIUM"

            forms.append(form_result)

        # --- Origin/Referer Validation Test ---
        origin_test = {
            "check": "Origin/Referer validation",
            "tests": [],
        }

        # Test with malicious origin
        for header_set in [
            {"Origin": "https://evil.com"},
            {"Referer": "https://evil.com/attack"},
            {"Origin": "https://evil.com", "Referer": "https://evil.com/attack"},
        ]:
            try:
                resp_with_evil = await client.get(target, headers=header_set)
                origin_test["tests"].append({
                    "headers": list(header_set.keys()),
                    "status": resp_with_evil.status_code,
                    "accepted": resp_with_evil.status_code == 200,
                })
            except Exception:
                pass

        origin_test["vulnerable"] = any(t["accepted"] for t in origin_test["tests"])
        results.append(origin_test)

        # --- SameSite Cookie Test ---
        samesite_test = {
            "check": "SameSite cookie attribute",
            "samesite_present": "samesite" in set_cookie.lower() if set_cookie else False,
            "cookie_flags": cookie_analysis,
        }
        results.append(samesite_test)

        # --- Token in URL Test (Token Leakage) ---
        token_leak_test = {
            "check": "CSRF token in URL (leakage via Referer)",
            "vulnerable": False,
        }
        url_patterns = [r'csrf=([a-zA-Z0-9+/=]+)', r'token=([a-zA-Z0-9+/=]+)', r'xsrf=([a-zA-Z0-9+/=]+)']
        for pattern in url_patterns:
            if re.search(pattern, target):
                token_leak_test["vulnerable"] = True
                token_leak_test["leaked_param"] = re.search(pattern, target).group(0).split("=")[0]
                break
        results.append(token_leak_test)

        # --- Double Submit Cookie Test ---
        double_submit_test = {
            "check": "Double-submit cookie pattern",
            "vulnerable": False,
        }
        cookies = resp.headers.get_list("set-cookie")
        for cookie in cookies:
            cookie_name = cookie.split("=")[0].strip().lower()
            if any(tp in cookie_name for tp in ["csrf", "xsrf", "token"]):
                # Check if same token appears in form or header
                if cookie.split("=")[1].split(";")[0].strip() in body:
                    double_submit_test["vulnerable"] = True
                    double_submit_test["cookie_name"] = cookie_name
                    break
        results.append(double_submit_test)

    # --- Summary ---
    csrf_vulnerable_forms = [f for f in forms if f.get("vulnerable")]
    has_vulnerabilities = len(csrf_vulnerable_forms) > 0 or any(
        r.get("vulnerable") for r in results if isinstance(r, dict)
    )

    return {
        "target": target,
        "forms": forms,
        "csrf_vulnerable_forms": csrf_vulnerable_forms,
        "security_checks": results,
        "cookie_analysis": cookie_analysis,
        "header_analysis": header_analysis,
        "csrf_vulnerable": has_vulnerabilities,
        "total_findings": len(csrf_vulnerable_forms) + sum(1 for r in results if isinstance(r, dict) and r.get("vulnerable")),
        "risk_summary": {
            "critical": sum(1 for f in csrf_vulnerable_forms if f.get("risk") == "CRITICAL"),
            "high": sum(1 for f in csrf_vulnerable_forms if f.get("risk") == "HIGH") + sum(1 for r in results if isinstance(r, dict) and r.get("vulnerable")),
            "medium": sum(1 for f in csrf_vulnerable_forms if f.get("risk") == "MEDIUM"),
        },
    }
