"""CSRF token extraction — parse, decode, and test anti-CSRF tokens."""
import json
import urllib.request
import urllib.parse
import re
import base64

def csrf_extract(target: str, method: str = "get", param_hint: str = "") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    result = {
        "target": target,
        "tokens_found": [],
        "extraction_methods": [],
        "token_analysis": []
    }

    try:
        req = urllib.request.Request(target, headers={"User-Agent": "CybersecCSRF/1.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="ignore")
        result["status"] = resp.status
        result["content_type"] = resp.headers.get("Content-Type", "")
        result["body_size"] = len(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        result["status"] = e.code
        result["error"] = str(e)[:100]
        if e.code in (200, 403):
            pass
        else:
            return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

    # 1. Scan meta tags
    meta_patterns = [
        r'<meta\s+[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
        r'<meta\s+[^>]*name=["\']csrf-param["\'][^>]*content=["\']([^"\']+)["\']',
        r'<meta\s+[^>]*name=["\']_csrf["\'][^>]*content=["\']([^"\']+)["\']',
    ]
    for pat in meta_patterns:
        for m in re.finditer(pat, body, re.IGNORECASE):
            result["tokens_found"].append({"source": "meta_tag", "value": m.group(1)})
            result["extraction_methods"].append("meta_tag")

    # 2. Scan hidden inputs
    input_patterns = [
        r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*name=["\']token["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']',
    ]
    for pat in input_patterns:
        for m in re.finditer(pat, body, re.IGNORECASE):
            groups = m.groups()
            if len(groups) == 2:
                result["tokens_found"].append({"source": "hidden_input", "param": groups[0], "value": groups[1]})
            else:
                result["tokens_found"].append({"source": "hidden_input", "value": groups[0]})
            result["extraction_methods"].append("hidden_input")

    # 3. Scan for JS variables
    js_patterns = [
        r'csrf_token\s*[:=]\s*["\']([^"\']+)["\']',
        r'csrfToken\s*[:=]\s*["\']([^"\']+)["\']',
        r'__csrf\s*[:=]\s*["\']([^"\']+)["\']',
        r'"csrfToken"\s*:\s*"([^"]+)"',
        r"'csrfToken'\s*:\s*'([^']+)'",
    ]
    for pat in js_patterns:
        for m in re.finditer(pat, body, re.IGNORECASE):
            result["tokens_found"].append({"source": "js_variable", "value": m.group(1)})
            result["extraction_methods"].append("js_variable")

    # 4. Scan headers
    header_names = ["X-CSRF-Token", "X-CSRFToken", "CSRF-Token", "X-XSRF-Token"]
    for h in header_names:
        val = resp.headers.get(h) if hasattr(resp, 'headers') else None
        val = resp.headers.get(h) if hasattr(resp, 'headers') else None
    # Re-read headers from response
    for h in header_names:
        val = resp.headers.get(h) if hasattr(resp, 'headers') else None

    # 5. Scan cookies
    set_cookie = resp.headers.get("Set-Cookie", "") if hasattr(resp, 'headers') else ""
    cookie_patterns = [
        r'csrf[^=]*=([^;]+)',
        r'XSRF-TOKEN=([^;]+)',
        r'csrf-token=([^;]+)',
    ]
    for pat in cookie_patterns:
        m = re.search(pat, set_cookie, re.IGNORECASE)
        if m:
            result["tokens_found"].append({"source": "cookie_set-cookie", "value": m.group(1), "cookie_match": True})
            result["extraction_methods"].append("cookie")

    # Analyze tokens
    seen = set()
    for t in result["tokens_found"]:
        val = t.get("value", "")
        if val in seen or len(val) < 8:
            continue
        seen.add(val)
        analysis = {"value_length": len(val), "value_prefix": val[:20]}

        if re.match(r'^[A-Za-z0-9+/=]+$', val):
            try:
                decoded = base64.b64decode(val).decode("utf-8", errors="replace")
                analysis["encoding"] = "base64"
                analysis["decoded_preview"] = decoded[:50]
            except Exception:
                analysis["encoding"] = "base64_like"
        elif re.match(r'^[a-f0-9]{32,}$', val, re.IGNORECASE):
            analysis["encoding"] = "md5_like"
        elif re.match(r'^[a-f0-9]{40,}$', val, re.IGNORECASE):
            analysis["encoding"] = "sha1_like"
        elif re.match(r'^[a-f0-9]{64,}$', val, re.IGNORECASE):
            analysis["encoding"] = "sha256_like"
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.IGNORECASE):
            analysis["encoding"] = "uuid"
        else:
            analysis["encoding"] = "unknown"
        t["analysis"] = analysis
        result["token_analysis"].append(analysis)

    result["total_tokens"] = len(result["tokens_found"])
    result["extraction_summary"] = f"Extracted {len(result['tokens_found'])} CSRF tokens via {', '.join(set(result['extraction_methods']))}" if result["tokens_found"] else "No CSRF tokens found"
    result["csrf_protected"] = len(result["tokens_found"]) > 0
    result["remediation"] = "CSRF tokens found — ensure they are validated server-side and tied to session. Consider SameSite=Strict cookies."

    return json.dumps(result, indent=2)