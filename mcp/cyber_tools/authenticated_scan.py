"""Authenticated scanning — scan behind login pages."""

import httpx
import json
import re
from datetime import datetime


def authenticated_scan(target: str, login_url: str = "", username: str = "", password: str = "", auth_type: str = "form", cookies: str = "", headers: str = "") -> str:
    """Scan a web target behind authentication.

    auth_type: form (username/password), cookie (session cookie), header (bearer/api key)
    cookies: JSON string of cookies for cookie auth
    headers: JSON string of headers for header auth
    """
    result = {
        "target": target,
        "login_url": login_url,
        "auth_type": auth_type,
        "scanned_at": datetime.now().isoformat(),
        "authenticated": False,
        "session": {},
        "findings": [],
    }

    session = httpx.Client(timeout=15, follow_redirects=True, verify=False)

    try:
        if auth_type == "form" and login_url and username and password:
            login_page = session.get(login_url)
            token_match = re.search(r'name=["\']?(csrf|_token|authenticity_token)["\']?\s+value=["\']([^"\']+)["\']', login_page.text, re.IGNORECASE)
            login_data = {"username": username, "password": password, "user": username, "pass": password, "email": username}
            if token_match:
                login_data[token_match.group(1)] = token_match.group(2)

            login_resp = session.post(login_url, data=login_data)

            if login_resp.status_code in (200, 302):
                if "logout" in login_resp.text.lower() or "dashboard" in login_resp.text.lower() or "welcome" in login_resp.text.lower():
                    result["authenticated"] = True
                    result["session"]["cookies"] = dict(session.cookies)
                else:
                    result["session"]["error"] = "Login may have failed — no success indicators found"
            else:
                result["session"]["error"] = f"Login returned status {login_resp.status_code}"

        elif auth_type == "cookie" and cookies:
            try:
                cookie_dict = json.loads(cookies)
                for name, value in cookie_dict.items():
                    session.cookies.set(name, value, domain=target)
                result["authenticated"] = True
            except json.JSONDecodeError:
                return json.dumps({"error": "Invalid cookies JSON. Use {\"name\": \"value\"}"}, indent=2)

        elif auth_type == "header" and headers:
            try:
                header_dict = json.loads(headers)
                session.headers.update(header_dict)
                result["authenticated"] = True
            except json.JSONDecodeError:
                return json.dumps({"error": "Invalid headers JSON. Use {\"Authorization\": \"Bearer xxx\"}"}, indent=2)

        else:
            return json.dumps({"error": "Insufficient auth parameters. See function docs."}, indent=2)

        if result["authenticated"]:
            findings = _scan_authenticated(session, target)
            result["findings"] = findings
            result["total_findings"] = len(findings)

    except httpx.RequestError as e:
        result["error"] = f"Request error: {e}"
    finally:
        session.close()

    return json.dumps(result, indent=2)


def _scan_authenticated(session: httpx.Client, target: str) -> list:
    findings = []

    resp = session.get(target)
    page = resp.text.lower()

    if "logout" not in page:
        findings.append({"type": "auth_verify", "severity": "high", "description": "Authentication may not be working — no logout link found"})

    security_headers = {
        "X-Content-Type-Options": "missing",
        "X-Frame-Options": "missing",
        "Strict-Transport-Security": "missing",
        "Content-Security-Policy": "missing",
        "Referrer-Policy": "missing",
    }
    for header, status in security_headers.items():
        if header not in resp.headers:
            findings.append({"type": "missing_header", "severity": "medium", "header": header})

    if "password" in page and "type=\"password\"" in page:
        findings.append({"type": "credential_form", "severity": "info", "description": "Password form found on authenticated page"})

    for pattern in ["admin", "debug", "settings", "config", "profile", "dashboard"]:
        if pattern in page:
            findings.append({"type": "authenticated_content", "severity": "info", "description": f"Found '{pattern}' in authenticated content"})

    idor_paths = ["/admin", "/users/1", "/api/users", "/api/v1/me", "/settings", "/account"]
    for path in idor_paths:
        try:
            test_url = target.rstrip("/") + path
            r = session.get(test_url)
            if r.status_code == 200 and len(r.text) > 200:
                findings.append({
                    "type": "idor",
                    "severity": "high",
                    "path": path,
                    "status_code": r.status_code,
                    "description": f"Accessible authenticated endpoint: {path}",
                })
        except httpx.RequestError:
            pass

    sensitive_patterns = ["api_key", "secret", "token", "private_key", "password", "ssid", "aws"]
    for pattern in sensitive_patterns:
        if pattern in page:
            idx = page.find(pattern)
            context = page[max(0, idx - 50):idx + len(pattern) + 50]
            findings.append({
                "type": "sensitive_data",
                "severity": "high",
                "pattern": pattern,
                "context": context[:200],
                "description": f"Sensitive pattern '{pattern}' found in response",
            })

    return findings