import base64
import json
import urllib.parse
import httpx
import re

MAX_COOKIE_BYTES = 64 * 1024


def _oversize(value):
    return len(value) > MAX_COOKIE_BYTES or len(value.encode('utf-8')) > MAX_COOKIE_BYTES


def _analyze_value(value):
    """Return metadata only: even JSON keys can contain session secrets."""
    analysis = {"original_value": "[REDACTED]", "value_length": len(value), "decoded": {}}
    if _oversize(value):
        analysis["error"] = "Cookie exceeds 64 KiB analysis limit"
        return analysis
    decoded = analysis["decoded"]
    unquoted = urllib.parse.unquote(value)
    decoded["url_encoded"] = {"value": "[REDACTED]", "detected": unquoted != value,
                              "length": len(unquoted)}
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        decoded["base64"] = {"value": "[REDACTED]", "detected": True, "length": len(raw)}
    except ValueError:
        pass
    try:
        parsed = json.loads(unquoted)
        types = {dict: 'object', list: 'array', str: 'string', int: 'number',
                 float: 'number', bool: 'boolean', type(None): 'null'}
        metadata = {"value": "[REDACTED]", "type": types[type(parsed)]}
        if isinstance(parsed, (dict, list)):
            metadata['member_count'] = len(parsed)
            children = parsed.values() if isinstance(parsed, dict) else parsed
            metadata['value_types'] = sorted({types[type(child)] for child in children})
        decoded['json'] = metadata
    except (ValueError, RecursionError):
        pass
    return analysis

PRIVILEGE_ESCALATION_TESTS = [
    ("role", ["admin", "administrator", "user", "moderator", "editor", "superadmin"]),
    ("usertype", ["admin", "premium", "vip", "enterprise"]),
    ("group", ["admin", "admins", "administrators"]),
    ("permission", ["admin", "all", "*"]),
    ("account_type", ["admin", "pro", "unlimited"]),
]

async def cookie_editor(target: str, cookie_str: str = "", action: str = "analyze") -> dict:
    results = []
    if action not in ("analyze", "escalate"):
        return {"target": target, "error": "Unknown action", "actions": ["analyze", "escalate"]}
    if cookie_str:
        if action == "analyze" and _oversize(cookie_str):
            return {"target": target, "error": "Cookie exceeds 64 KiB analysis limit"}
        parts = cookie_str.split("=", 1)
        if len(parts) != 2 or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", parts[0].strip()) or any(c in cookie_str for c in "\r\n;"):
            return {"target": target, "error": "Expected one name=value cookie"}
        name, value = (part.strip() for part in parts)
        if action == "analyze":
            return {"target": target, "action": action, "cookie_name": name,
                    **_analyze_value(value), "results": []}

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # If no cookie provided, fetch from target
        if not cookie_str:
            resp = await client.get(target)
            raw_cookies = dict(resp.cookies)
            if not raw_cookies:
                return {"target": target, "error": "No cookies found", "cookies_found": []}
            for name, value in raw_cookies.items():
                analysis = {"name": name, **_analyze_value(value)}
                results.append(analysis)
            return {"target": target, "action": "fetch_and_analyze", "cookies_found": results}

        # Analyze provided cookie
        parts = cookie_str.split("=", 1)
        if len(parts) != 2:
            return {"target": target, "error": "Invalid cookie format (expected name=value)"}
        name, value = parts[0].strip(), parts[1].strip()

        decoded = {}
        try:
            decoded["base64"] = base64.b64decode(value + "==").decode(errors="replace")
        except Exception:
            pass
        try:
            decoded["json"] = json.loads(urllib.parse.unquote(value))
        except Exception:
            pass
        try:
            decoded["url_encoded"] = urllib.parse.unquote(value)
        except Exception:
            pass

        # Test privilege escalation
        if action == "escalate":
            for test_name, test_values in PRIVILEGE_ESCALATION_TESTS:
                if test_name in name.lower():
                    for test_val in test_values:
                        test_cookie = {name: test_val}
                        try:
                            tr = await client.get(target, cookies=test_cookie)
                            if tr.status_code in [200, 302] and "access" not in tr.text.lower()[:500]:
                                results.append({
                                    "test": "privilege_escalation",
                                    "cookie": f"{name}={test_val}",
                                    "status": tr.status_code,
                                    "note": f"Changed {name} to {test_val} - check if access was elevated",
                                    "response_snippet": tr.text[:100],
                                })
                        except Exception:
                            pass
                    break

        return {
            "target": target,
            "action": action,
            "cookie_name": name,
            "original_value": value[:50],
            "decoded": decoded,
            "results": results,
        }
