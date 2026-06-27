import base64
import json
import urllib.parse
import httpx
import re

PRIVILEGE_ESCALATION_TESTS = [
    ("role", ["admin", "administrator", "user", "moderator", "editor", "superadmin"]),
    ("usertype", ["admin", "premium", "vip", "enterprise"]),
    ("group", ["admin", "admins", "administrators"]),
    ("permission", ["admin", "all", "*"]),
    ("account_type", ["admin", "pro", "unlimited"]),
]

async def cookie_editor(target: str, cookie_str: str = "", action: str = "analyze") -> dict:
    results = []

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # If no cookie provided, fetch from target
        if not cookie_str:
            resp = await client.get(target)
            raw_cookies = dict(resp.cookies)
            if not raw_cookies:
                return {"target": target, "error": "No cookies found", "cookies_found": []}
            for name, value in raw_cookies.items():
                analysis = {"name": name, "original_value": value}
                # Try to decode
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
                if decoded:
                    analysis["decoded"] = decoded
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
        if action in ["analyze", "escalate"]:
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
