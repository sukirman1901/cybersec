"""IDOR/BOLA access validation — multi-role, vertical/horizontal privilege escalation."""
import json
import urllib.request
import urllib.parse

def idor_access_validation(target: str, resource_ids: str = "1,2,3,4,5", user_a_cookie: str = "", user_b_cookie: str = "", param: str = "id", method: str = "get", role_a_header: str = "", role_b_header: str = "") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    ids = [i.strip() for i in resource_ids.split(",")]
    result = {
        "target": target,
        "param": param,
        "method": method,
        "tests": [],
        "idor_found": False,
        "bola_found": False,
    }

    # Test 1: Sequential enumeration (horizontal IDOR)
    for rid in ids[:10]:
        r = _request(target, param, rid, method, cookie=user_a_cookie, extra_header=role_a_header)
        result["tests"].append({
            "type": "horizontal_idor",
            "resource_id": rid,
            "status": r.get("status"),
            "body_size": r.get("body_size", 0),
            "accessible": r.get("accessible", False),
            "evidence": r.get("evidence", ""),
        })

    # Test 2: Cross-user access (if user_b provided)
    if user_b_cookie:
        for rid in ids[:3]:
            r = _request(target, param, rid, method, cookie=user_b_cookie, extra_header=role_b_header)
            result["tests"].append({
                "type": "cross_user_access",
                "resource_id": rid,
                "status": r.get("status"),
                "body_size": r.get("body_size", 0),
                "accessible": r.get("accessible", False),
                "evidence": r.get("evidence", ""),
            })

    # Test 3: Negative IDs
    for neg in ["-1", "0", "999999"]:
        r = _request(target, param, neg, method, cookie=user_a_cookie)
        result["tests"].append({
            "type": "negative_id",
            "resource_id": neg,
            "status": r.get("status"),
            "accessible": r.get("accessible", False),
        })

    # Test 4: Array/object bypass
    for bypass in ["id[]=1", "id[0]=1", "ids=1", "id=1&id=2"]:
        url = target
        if "?" in target:
            url = target + "&" + bypass
        else:
            url = target + "?" + bypass.replace("=", "=" + param + "=")
        # simplified: just try a few
        r = _request_raw(url, cookie=user_a_cookie)
        result["tests"].append({
            "type": "bypass_attempt",
            "payload": bypass,
            "status": r.get("status"),
            "accessible": r.get("accessible", False),
        })

    # Analyze
    accessible_count = sum(1 for t in result["tests"] if t.get("accessible"))
    total = len(result["tests"])
    if accessible_count > 0:
        result["idor_found"] = accessible_count > len(ids) * 0.5
        result["bola_found"] = any(t.get("type") == "cross_user_access" and t.get("accessible") for t in result["tests"])
        result["risk"] = "critical" if result["bola_found"] else ("high" if result["idor_found"] else "medium")
        result["summary"] = f"IDOR/BOLA risks detected: {accessible_count}/{total} resources accessible"
        result["remediation"] = "Implement proper access controls. Use session-based authorization for every resource access. Never trust user-supplied IDs. Use UUIDs instead of sequential IDs."
    else:
        result["risk"] = "info"
        result["summary"] = "No IDOR/BOLA detected in tested resources"

    return json.dumps(result, indent=2)


def _request(target, param, rid, method, cookie="", extra_header=""):
    if method == "get":
        url = f"{target}?{urllib.parse.urlencode({param: rid})}"
    else:
        url = target
    return _request_raw(url, cookie, extra_header, data=urllib.parse.urlencode({param: rid}).encode() if method == "post" else None)


def _request_raw(url, cookie="", extra_header="", data=None):
    headers = {"User-Agent": "CybersecIDOR/1.0"}
    if cookie:
        h = cookie.strip()
        if not h.startswith("Cookie") and not h.startswith("Authorization"):
            headers["Cookie"] = h
        else:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if extra_header:
        k, v = extra_header.split(":", 1)
        headers[k.strip()] = v.strip()

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="GET" if data is None else "POST")
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="ignore")
        return {
            "status": resp.status,
            "body_size": len(body),
            "accessible": resp.status == 200 and len(body) > 10,
            "evidence": f"HTTP {resp.status}, {len(body)} bytes",
        }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body_size": 0, "accessible": False, "evidence": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": 0, "body_size": 0, "accessible": False, "error": str(e)[:100]}