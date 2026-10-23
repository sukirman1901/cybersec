"""IDOR/BOLA access validation — multi-role, vertical/horizontal privilege escalation.

Dual-role differential is required for HIGH-confidence BOLA claims. Single-role
enumeration alone is LOW confidence with an explicit coverage gap.
"""
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request


def idor_access_validation(target: str, resource_ids: str = "1,2,3,4,5",
                           user_a_cookie: str = "", user_b_cookie: str = "",
                           param: str = "id", method: str = "get",
                           role_a_header: str = "", role_b_header: str = "") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    ids = [i.strip() for i in resource_ids.split(",") if i.strip()]
    dual_role = bool(user_a_cookie and user_b_cookie) or bool(role_a_header and role_b_header)
    coverage = []
    result = {
        "target": target,
        "param": param,
        "method": method,
        "tests": [],
        "idor_found": False,
        "bola_found": False,
        "dual_role_tested": dual_role,
        "confidence": "LOW",
        "coverage": "",
    }

    # Test 1: Sequential enumeration (horizontal IDOR) as role A
    for rid in ids[:10]:
        r = _request(target, param, rid, method, cookie=user_a_cookie, extra_header=role_a_header)
        result["tests"].append({
            "type": "horizontal_idor",
            "role": "a",
            "resource_id": rid,
            "status": r.get("status"),
            "body_size": r.get("body_size", 0),
            "body_hash": r.get("body_hash", ""),
            "accessible": r.get("accessible", False),
            "evidence": r.get("evidence", ""),
        })
    coverage.append(f"horizontal_ids={min(len(ids), 10)}")

    # Test 2: Cross-user / dual-role differential (required for BOLA HIGH)
    cross_diffs = 0
    if dual_role:
        for rid in ids[:5]:
            a = _request(target, param, rid, method, cookie=user_a_cookie, extra_header=role_a_header)
            b = _request(target, param, rid, method, cookie=user_b_cookie, extra_header=role_b_header)
            same_body = a.get("body_hash") and a.get("body_hash") == b.get("body_hash")
            both_ok = a.get("accessible") and b.get("accessible")
            differential = both_ok and same_body
            if differential:
                cross_diffs += 1
            result["tests"].append({
                "type": "cross_user_access",
                "resource_id": rid,
                "role_a_status": a.get("status"),
                "role_b_status": b.get("status"),
                "role_a_size": a.get("body_size", 0),
                "role_b_size": b.get("body_size", 0),
                "same_body_hash": same_body,
                "accessible": differential,
                "evidence": (
                    f"A={a.get('status')}/{a.get('body_size')} B={b.get('status')}/{b.get('body_size')} "
                    f"hash_match={same_body}"
                ),
            })
        coverage.append(f"dual_role_resources={min(len(ids), 5)}")
        coverage.append(f"dual_role_hash_matches={cross_diffs}")
    else:
        coverage.append("dual_role_not_tested — provide user_a_cookie+user_b_cookie (or role headers) for BOLA")

    # Test 3: Negative IDs
    for neg in ["-1", "0", "999999"]:
        r = _request(target, param, neg, method, cookie=user_a_cookie, extra_header=role_a_header)
        result["tests"].append({
            "type": "negative_id",
            "resource_id": neg,
            "status": r.get("status"),
            "accessible": r.get("accessible", False),
            "body_hash": r.get("body_hash", ""),
        })
    coverage.append("negative_ids=3")

    # Test 4: Array/object bypass (bounded)
    for bypass in ["id[]=1", "id[0]=1", "ids=1"]:
        url = target + ("&" if "?" in target else "?") + bypass
        r = _request_raw(url, cookie=user_a_cookie, extra_header=role_a_header)
        result["tests"].append({
            "type": "bypass_attempt",
            "payload": bypass,
            "status": r.get("status"),
            "accessible": r.get("accessible", False),
        })

    accessible_horizontal = sum(
        1 for t in result["tests"] if t.get("type") == "horizontal_idor" and t.get("accessible"))
    horizontal_total = sum(1 for t in result["tests"] if t.get("type") == "horizontal_idor")
    result["bola_found"] = dual_role and cross_diffs > 0
    result["idor_found"] = accessible_horizontal > max(1, horizontal_total * 0.5)

    if result["bola_found"]:
        result["confidence"] = "HIGH"
        result["risk"] = "critical"
        result["summary"] = (
            f"BOLA/IDOR dual-role differential: {cross_diffs} resources returned matching "
            f"bodies for role A and B"
        )
    elif result["idor_found"] and dual_role:
        result["confidence"] = "MEDIUM"
        result["risk"] = "high"
        result["summary"] = "Horizontal IDOR signals with dual-role session present but weak cross-role match"
    elif result["idor_found"]:
        result["confidence"] = "LOW"
        result["risk"] = "medium"
        result["summary"] = (
            "Single-role sequential access only — not sufficient for BOLA; retest with two roles"
        )
    else:
        result["confidence"] = "MEDIUM" if dual_role else "LOW"
        result["risk"] = "info"
        result["summary"] = "No IDOR/BOLA confirmed in tested resources"

    result["coverage"] = "; ".join(coverage)
    result["remediation"] = (
        "Enforce object-level authorization per role/session. Prefer opaque IDs. "
        "Never authorize solely by client-supplied identifiers."
    )
    return json.dumps(result, indent=2)


def _request(target, param, rid, method, cookie="", extra_header=""):
    if method == "get":
        url = f"{target}?{urllib.parse.urlencode({param: rid})}"
        return _request_raw(url, cookie, extra_header)
    return _request_raw(
        target, cookie, extra_header,
        data=urllib.parse.urlencode({param: rid}).encode(),
    )


def _request_raw(url, cookie="", extra_header="", data=None):
    headers = {"User-Agent": "CybersecIDOR/1.1"}
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
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read().decode("utf-8", errors="ignore")
        digest = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]
        return {
            "status": resp.status,
            "body_size": len(body),
            "body_hash": digest,
            "accessible": resp.status == 200 and len(body) > 10,
            "evidence": f"HTTP {resp.status}, {len(body)} bytes, hash={digest}",
        }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body_size": 0, "body_hash": "", "accessible": False,
                "evidence": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": 0, "body_size": 0, "body_hash": "", "accessible": False,
                "error": str(e)[:100]}
