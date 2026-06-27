import httpx
import re


async def cookie_audit(target: str) -> dict:
    cookies = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp = await client.get(target)
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
        set_cookie_headers = [h for h in set_cookie_headers if h]
        if not set_cookie_headers:
            raw = resp.headers.get("set-cookie", "")
            if raw:
                set_cookie_headers = [raw]
        for header in set_cookie_headers:
            for part in header.split(","):
                part = part.strip()
                m = re.match(r'^([^=]+)=([^;]*)', part)
                if m:
                    name = m.group(1)
                    value = m.group(2)
                    flags = {
                        "httponly": "httponly" in part.lower(),
                        "secure": "secure" in part.lower(),
                        "samesite_lax": "samesite=lax" in part.lower(),
                        "samesite_strict": "samesite=strict" in part.lower(),
                        "samesite_none": "samesite=none" in part.lower(),
                        "path": "",
                    }
                    path_m = re.search(r'path=([^;]+)', part, re.I)
                    if path_m:
                        flags["path"] = path_m.group(1)
                    expires_m = re.search(r'expires=([^;]+)', part, re.I)
                    if expires_m:
                        flags["expires"] = expires_m.group(1)
                    max_age = re.search(r'max-age=(\d+)', part, re.I)
                    if max_age:
                        flags["max_age"] = max_age.group(1)
                    issues = []
                    if not flags.get("httponly"):
                        issues.append({"issue": "Missing HttpOnly flag — accessible via JavaScript", "severity": "high"})
                    if not flags.get("secure"):
                        issues.append({"issue": "Missing Secure flag — sent over HTTP", "severity": "high"})
                    if not flags.get("samesite_lax") and not flags.get("samesite_strict"):
                        if flags.get("samesite_none"):
                            issues.append({"issue": "SameSite=None — allows cross-site usage", "severity": "medium"})
                        else:
                            issues.append({"issue": "Missing SameSite flag — default behavior depends on browser", "severity": "medium"})
                    if flags.get("max_age") and flags["max_age"] == "0":
                        issues.append({"issue": "Max-Age=0 — session never expires", "severity": "critical"})
                    sensitive_cookies = ["session", "token", "auth", "sid", "jwt", "login", "api_key", "user"]
                    is_sensitive = any(s in name.lower() for s in sensitive_cookies)
                    cookies.append({
                        "name": name,
                        "value_preview": value[:20] + "..." if len(value) > 20 else value,
                        "flags": flags,
                        "issues": issues,
                        "sensitive": is_sensitive,
                    })
    return {"target": target, "cookies": cookies, "cookie_count": len(cookies), "total_issues": sum(len(c.get("issues", [])) for c in cookies)}
