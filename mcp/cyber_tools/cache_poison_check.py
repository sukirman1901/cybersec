"""Web cache poisoning detection — header manipulation, cache deception."""
import json
import urllib.request
import urllib.parse
import re

def cache_poison_check(target: str, cache_buster: str = "", test_headers: str = "X-Forwarded-Host,X-Forwarded-For,X-Original-URL,X-Rewrite-URL,X-Custom-IP-Authorization,X-Real-IP") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    cb = cache_buster or ("cb=" + str(hash(target))[:8])
    sep = "&" if "?" in target else "?"
    base_url = target + sep + cb

    result = {
        "target": target,
        "tests": [],
        "cache_detected": False,
        "poisonable": False,
    }

    # Baseline — no extra headers
    baseline = _fetch(base_url)
    if not baseline.get("success"):
        return json.dumps({"error": "Target unreachable", **result}, indent=2)

    result["baseline"] = {
        "status": baseline["status"],
        "headers": dict(baseline["headers"]),
        "body_size": baseline["body_size"],
        "cache_headers": baseline.get("cache_headers", {}),
    }
    result["cache_detected"] = baseline.get("cache_detected", False)

    # Test cache poisoning via headers
    header_list = [h.strip() for h in test_headers.split(",")]
    for hdr in header_list:
        test_val = "evil.com"
        r = _fetch(base_url, extra_headers={hdr: test_val})
        if r.get("success") and r["body_size"] != baseline["body_size"]:
            result["tests"].append({
                "type": "cache_poison",
                "header": hdr,
                "value": test_val,
                "status": r["status"],
                "body_size": r["body_size"],
                "baseline_size": baseline["body_size"],
                "poisoned": True,
                "evidence": f"Body changed from {baseline['body_size']} to {r['body_size']} bytes when using {hdr}: {test_val}",
            })
            result["poisonable"] = True
        elif r.get("success") and str(r.get("status")) != str(baseline["status"]):
            result["tests"].append({
                "type": "status_change",
                "header": hdr,
                "value": test_val,
                "baseline_status": baseline["status"],
                "test_status": r["status"],
                "poisoned": False,
                "evidence": f"Status changed from {baseline['status']} to {r['status']}",
            })

    # Test cache deception (static-like paths)
    deception_paths = ["/test.css", "/test.jpg", "/style.css", "/nonexistent.js"]
    for dp in deception_paths:
        url = target.rstrip("/") + dp + "?" + cb
        r = _fetch(url)
        if r.get("success") and "text/css" not in r.get("content_type", "") and "image/" not in r.get("content_type", ""):
            result["tests"].append({
                "type": "cache_deception",
                "path": dp,
                "status": r["status"],
                "content_type": r.get("content_type", ""),
                "poisoned": True,
                "evidence": f"Path {dp} returns non-static content (type: {r.get('content_type', '')})",
            })
            result["poisonable"] = True

    # Test cache key manipulation
    for hdr, val in [("X-Forwarded-Scheme", "http"), ("X-Forwarded-Proto", "http")]:
        r = _fetch(base_url, extra_headers={hdr: val})
        if r.get("success") and r["status"] != baseline["status"]:
            result["tests"].append({
                "type": "scheme_bypass",
                "header": hdr,
                "value": val,
                "poisoned": True,
                "evidence": f"Using {hdr}: {val} changed response from {baseline['status']} to {r['status']}",
            })
            result["poisonable"] = True

    result["total_tests"] = len(result["tests"])
    result["risk"] = "high" if result["poisonable"] else "info"
    result["remediation"] = "Cache key must include all input-determining headers. Use Vary headers appropriately. Disable caching for dynamic content. Implement cache key normalization."

    return json.dumps(result, indent=2)


def _fetch(url, extra_headers=None):
    headers = {"User-Agent": "CybersecCachePoison/1.0"}
    if extra_headers:
        headers.update(extra_headers)

    try:
        req = urllib.request.Request(url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="ignore")
        resp_headers = dict(resp.headers)

        header_map = {k.lower(): k for k in resp_headers}
        cache_headers = {}
        for ch in ["X-Cache", "Age", "Cf-Cache-Status", "X-Served-By", "X-Cache-Hits", "Cache-Control", "Pragma", "Expires", "X-Varnish", "Via"]:
            if ch.lower() in header_map:
                cache_headers[ch] = resp_headers[header_map[ch.lower()]]

        cache_detected = bool([v for k, v in cache_headers.items() if v.strip() and v not in ("no-cache", "no-store", "private", "0", "max-age=0")])

        return {
            "success": True,
            "status": resp.status,
            "headers": resp_headers,
            "body_size": len(body),
            "content_type": resp_headers.get("Content-Type", ""),
            "cache_headers": cache_headers,
            "cache_detected": cache_detected,
        }
    except urllib.error.HTTPError as e:
        return {"success": True, "status": e.code, "headers": dict(e.headers), "body_size": 0, "cache_headers": {}, "cache_detected": False}
    except Exception:
        return {"success": False}