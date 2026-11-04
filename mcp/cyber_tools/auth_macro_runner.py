"""Auth macro runner — multi-step login, session chain, cookie persistence."""
import json
import urllib.request
import urllib.parse
import http.cookiejar
import re
import time
from .http_guard import ScopeClampedRedirectHandler

def auth_macro_runner(target: str, auth_type: str = "form", username: str = "", password: str = "", login_url: str = "", username_field: str = "username", password_field: str = "password", extra_fields: str = "", token_extract: str = "", steps_json: str = "") -> str:
    """Return redacted request observations, not proof of an authenticated session."""
    def invalid():
        return json.dumps({"error_kind": "invalid_input", "error": "Invalid auth inputs or step budget exceeded"})

    def valid_url(value):
        try:
            url = urllib.parse.urlsplit(value)
            return (url.scheme in ("http", "https") and bool(url.hostname)
                    and url.username is None and url.password is None and url.port != 0
                    and not any(c.isspace() for c in value))
        except ValueError:
            return False

    values = (target, auth_type, username, password, login_url, username_field,
              password_field, extra_fields, token_extract, steps_json)
    if any(not isinstance(v, str) or len(v) > 65536 for v in values):
        return invalid()
    if not target.strip() or auth_type not in ("form", "basic", "bearer"):
        return invalid()
    target = target if "://" in target else "http://" + target
    if not valid_url(target) or (login_url and not valid_url(login_url)):
        return invalid()
    if not username_field.strip() or not password_field.strip():
        return invalid()
    if steps_json:
        try:
            steps = json.loads(steps_json)
        except ValueError:
            return invalid()
        if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
            return invalid()
        for step in steps:
            if not isinstance(step, dict):
                return invalid()
            if (not isinstance(step.get("method", "GET"), str)
                    or step.get("method", "GET").upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
                    or not isinstance(step.get("url", target), str)
                    or not isinstance(step.get("body", ""), str)
                    or not isinstance(step.get("headers", {}), dict)):
                return invalid()
            if not valid_url(urllib.parse.urljoin(target + "/", step.get("url", target))):
                return invalid()
            if any(not isinstance(k, str) or not isinstance(v, str) or '\n' in k + v or '\r' in k + v
                   for k, v in step.get("headers", {}).items()):
                return invalid()
            if step.get("extract"):
                return json.dumps({"error_kind": "unsupported", "error": "Unbounded extraction regex is unsupported"})
    try:
        raw = json.loads(_auth_macro_runner(target, auth_type, username, password, login_url,
                                          username_field, password_field, extra_fields, token_extract, steps_json))
    except Exception:
        return json.dumps({"error_kind": "runtime_error", "error": "Authentication runtime unavailable"})
    if "error" in raw:
        return json.dumps({"error_kind": "runtime_error", "error": "Authentication flow incomplete"})
    # Allowlist metadata: URLs, names, exceptions and response values may all hold secrets.
    observations = []
    for index, step in enumerate(raw["steps"]):
        observation = {"step": index + 1, "authenticated": False}
        if isinstance(step.get("status"), int):
            observation["status"] = step["status"]
        if "error" in step:
            observation["error"] = "Request failed; details withheld"
        observations.append(observation)
    return json.dumps({"auth_type": auth_type, "steps": observations,
                       "status": raw["status"], "error_kind": raw["error_kind"],
                       "skipped_steps": raw["skipped_steps"], "time_budget_seconds": 30,
                       "session": {"cookies": {"redacted_count": len(raw["session"]["cookies"])},
                                   "headers": {k: "[REDACTED]" for k in raw["session"]["headers"]},
                                   "tokens": {}, "authenticated": False, "verification": "unverified"},
                       "coverage": "HTTP status and token issuance do not verify session access. "
                                   "The aggregate deadline is cooperative: synchronous DNS, redirects and reads "
                                   "cannot be preempted; expiry is checked before and after I/O."})


class _DeadlineResponse:
    def __init__(self, response, budget):
        self.response = response
        self.budget = budget

    def __getattr__(self, name):
        return getattr(self.response, name)

    def read(self, size):
        self.budget.remaining()
        data = self.response.read(size)
        self.budget.remaining()
        return data


class _DeadlineOpener:
    """Cooperative aggregate budget; never claims to interrupt blocking sync I/O."""
    def __init__(self, opener, deadline):
        self.opener = opener
        self.deadline = deadline
        self.addheaders = opener.addheaders

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Aggregate deadline exceeded")
        return remaining

    def open(self, request, timeout):
        response = self.opener.open(request, timeout=min(timeout, self.remaining()))
        try:
            self.remaining()
        except TimeoutError:
            response.close()
            raise
        return _DeadlineResponse(response, self)


def _auth_macro_runner(target, auth_type, username, password, login_url, username_field, password_field, extra_fields, token_extract, steps_json):
    deadline = time.monotonic() + 30
    if not target.startswith("http"):
        target = "http://" + target

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(ScopeClampedRedirectHandler, urllib.request.HTTPCookieProcessor(cj))
    opener.addheaders = [("User-Agent", "CybersecAuthMacro/1.0")]
    opener = _DeadlineOpener(opener, deadline)

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
                if time.monotonic() >= deadline:
                    break
                r = _execute_step(opener, step, target, cj)
                result["steps"].append(r)
                if "error" in r:
                    break
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

    expired = time.monotonic() >= deadline
    result["skipped_steps"] = (len(steps) if steps_json else 1) - len(result["steps"])
    failed = expired or result["skipped_steps"] or any("error" in step for step in result["steps"])
    result["status"] = "incomplete" if failed else "unverified"
    result["error_kind"] = "deadline_exceeded" if expired else ("request_failed" if failed else None)
    cookies_dict = {}
    for c in cj:
        cookies_dict[c.name] = c.value
    result["session"]["cookies"] = cookies_dict
    result["session"]["headers"] = dict(opener.addheaders)
    result["session"]["authenticated"] = any(
        s.get("authenticated", False) for s in result["steps"]
    )

    return json.dumps(result, indent=2)


def _read_response(response):
    try:
        body = response.read(1048577)
        if len(body) > 1048576:
            raise ValueError("Response byte budget exceeded")
        return body.decode("utf-8", errors="ignore")
    finally:
        response.close()


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
        resp_body = _read_response(resp)
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
            body = _read_response(resp)
            pattern = rf'name=["\']{re.escape(token_field)}["\'][^>]*value=["\']([^"\']+)["\']'
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                fields[token_field] = m.group(1)
        except Exception:
            pass

    data = urllib.parse.urlencode(fields).encode()
    try:
        req = urllib.request.Request(login_url, data=data, headers={"User-Agent": "CybersecAuthMacro/1.0", "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        resp = opener.open(req, timeout=15)
        resp_body = _read_response(resp)
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
        resp.close()
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
        body = json.loads(_read_response(resp))
        token = body.get("token", body.get("access_token", body.get("jwt", "")))
        if token:
            opener.addheaders.append(("Authorization", f"Bearer {token}"))
            return {"step": "bearer_auth", "url": login_url, "status": resp.status, "authenticated": True, "token_type": "bearer", "token_prefix": token[:20] + "..."}
        return {"step": "bearer_auth", "url": login_url, "status": resp.status, "authenticated": False, "error": "No token in response"}
    except urllib.error.HTTPError as e:
        e.close()
        return {"step": "bearer_auth", "url": login_url, "status": e.code, "authenticated": False, "error": "HTTP request failed"}
    except Exception as e:
        return {"step": "bearer_auth", "error": str(e)[:100], "authenticated": False}
