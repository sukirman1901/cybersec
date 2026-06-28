"""Auth macro runner — multi-step login, session chain, cookie persistence."""
import json
import urllib.request
import urllib.parse
import http.cookiejar
import re
import time

def auth_macro_runner(target: str, auth_type: str = "form", username: str = "", password: str = "", login_url: str = "", username_field: str = "username", password_field: str = "password", extra_fields: str = "", token_extract: str = "", steps_json: str = "") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    opener.addheaders = [("User-Agent", "CybersecAuthMacro/1.0")]

    result = {
        "target": target,
        "auth_type": auth_type,
        "steps": [],
        "session": {"cookies": {}, "headers": {}, "tokens": {}, "authenticated": False}
    }

    if steps_json:
        try:
            steps = json.loads(steps_json) if isinstance(steps_json, str) else steps_json
            for step in steps:
                r = _execute_step(opener, step, target, cj)
                result["steps"].append(r)
        except Exception as e:
            return json.dumps({"error": f"Steps error: {str(e)}"}, indent=2)
    elif auth_type == "form":
        r = _form_login(opener, target, login_url, username, password, username_field, password_field, extra_fields, token_extract)
        result["steps"].append(r)
    elif auth_type == "basic":
        r = _basic_login(opener, target, username, password)
        result["steps"].append(r)
    elif auth_type == "bearer":
        r = _bearer_login(opener, target, username, password, login_url)
        result["steps"].append(r)

    cookies_dict = {}
    for c in cj:
        cookies_dict[c.name] = c.value
    result["session"]["cookies"] = cookies_dict
    result["session"]["headers"] = dict(opener.addheaders)
    result["session"]["authenticated"] = any(
        s.get("authenticated", False) for s in result["steps"]
    )

    return json.dumps(result, indent=2)


def _execute_step(opener, step, target, cj):
    method = step.get("method", "GET").upper()
    url = step.get("url", target)
    if not url.startswith("http"):
        url = target.rstrip("/") + "/" + url.lstrip("/")

    headers = step.get("headers", {})
    body = step.get("body", "")
    extract = step.get("extract", {})

    try:
        data = body.encode() if body and method in ("POST", "PUT", "PATCH") else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        resp = opener.open(req, timeout=15)
        resp_body = resp.read().decode("utf-8", errors="ignore")
        result = {
            "step": step.get("name", f"{method} {url}"),
            "url": url,
            "method": method,
            "status": resp.status,
            "authenticated": resp.status not in (401, 403, 302, 301) and "login" not in resp_body.lower()[:500],
        }
        for var, pattern in extract.items():
            m = re.search(pattern, resp_body)
            if m:
                result[f"extracted_{var}"] = m.group(1) if m.groups() else m.group(0)
        return result
    except urllib.error.HTTPError as e:
        return {"step": step.get("name", f"{method} {url}"), "status": e.code, "authenticated": False, "error": str(e)[:100]}
    except Exception as e:
        return {"step": step.get("name", f"{method} {url}"), "error": str(e)[:100], "authenticated": False}


def _form_login(opener, target, login_url, username, password, ufield, pfield, extra, token_field):
    if not login_url:
        login_url = target.rstrip("/") + "/login"

    fields = {ufield: username, pfield: password}
    if extra:
        for pair in extra.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                fields[k.strip()] = v.strip()

    # First GET to extract CSRF token if needed
    if token_field:
        try:
            req = urllib.request.Request(login_url, headers={"User-Agent": "CybersecAuthMacro/1.0"})
            resp = opener.open(req, timeout=10)
            body = resp.read().decode("utf-8", errors="ignore")
            pattern = rf'name=["\']{token_field}["\'][^>]*value=["\']([^"\']+)["\']'
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                fields[token_field] = m.group(1)
        except Exception:
            pass

    data = urllib.parse.urlencode(fields).encode()
    try:
        req = urllib.request.Request(login_url, data=data, headers={"User-Agent": "CybersecAuthMacro/1.0", "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        resp = opener.open(req, timeout=15)
        resp_body = resp.read().decode("utf-8", errors="ignore")
        authenticated = "login" not in resp_body.lower()[:1000] and "password" not in resp_body.lower()[:500] and resp.status not in (401, 403)
        return {
            "step": "form_login",
            "url": login_url,
            "method": "POST",
            "status": resp.status,
            "authenticated": authenticated,
            "tokens_sent": list(fields.keys()),
        }
    except urllib.error.HTTPError as e:
        return {"step": "form_login", "url": login_url, "status": e.code, "authenticated": False, "error": str(e)[:100]}
    except Exception as e:
        return {"step": "form_login", "error": str(e)[:100], "authenticated": False}


def _basic_login(opener, target, username, password):
    auth_str = f"{username}:{password}"
    import base64
    b64 = base64.b64encode(auth_str.encode()).decode()
    opener.addheaders.append(("Authorization", f"Basic {b64}"))

    try:
        req = urllib.request.Request(target, headers={"User-Agent": "CybersecAuthMacro/1.0"})
        resp = opener.open(req, timeout=10)
        return {"step": "basic_auth", "url": target, "status": resp.status, "authenticated": resp.status not in (401, 403)}
    except urllib.error.HTTPError as e:
        return {"step": "basic_auth", "status": e.code, "authenticated": e.code not in (401, 403)}
    except Exception as e:
        return {"step": "basic_auth", "error": str(e)[:100], "authenticated": False}


def _bearer_login(opener, target, username, password, login_url):
    if not login_url:
        login_url = target.rstrip("/") + "/api/auth/login"
    payload = json.dumps({"username": username, "password": password, "email": username}).encode()
    try:
        req = urllib.request.Request(login_url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "CybersecAuthMacro/1.0"}, method="POST")
        resp = opener.open(req, timeout=10)
        body = json.loads(resp.read().decode("utf-8", errors="ignore"))
        token = body.get("token", body.get("access_token", body.get("jwt", "")))
        if token:
            opener.addheaders.append(("Authorization", f"Bearer {token}"))
            return {"step": "bearer_auth", "url": login_url, "status": resp.status, "authenticated": True, "token_type": "bearer", "token_prefix": token[:20] + "..."}
        return {"step": "bearer_auth", "url": login_url, "status": resp.status, "authenticated": False, "error": "No token in response"}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")[:200]
        return {"step": "bearer_auth", "url": login_url, "status": e.code, "authenticated": False, "error": body}
    except Exception as e:
        return {"step": "bearer_auth", "error": str(e)[:100], "authenticated": False}