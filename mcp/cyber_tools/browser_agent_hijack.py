"""Test browser-based AI agents for hijack vulnerabilities — prompt injection via web content, UI manipulation, data exfiltration."""

import httpx
import re
import urllib.parse


INJECTION_PATTERNS = [
    r"(ignore|disregard|forget)\s+(all|previous|above)",
    r"system\s*(prompt|message|instruction)",
    r"you\s+are\s+(now|a\s+)",
    r"act\s+as\s+",
    r"new\s+instruction",
    r"override",
    r"pretend",
]

SENSITIVE_KEYWORDS = [
    "password", "credential", "token", "secret", "api_key", "apikey",
    "authorization", "bearer", "session", "cookie", "jwt",
    "ssn", "credit.card", "bank", "routing",
    "internal", "confidential", "secret",
]


async def browser_agent_hijack(target: str, page_content: str = "") -> dict:
    findings = []
    base = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Test 1: Fetch the page and analyze for agent hijacking risks
        try:
            resp = await client.get(base, follow_redirects=True)
            html = resp.text
            headers = dict(resp.headers)

            # Check for hidden form fields that could trick agents
            hidden_inputs = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*>',
                html, re.I,
            )
            if hidden_inputs:
                for inp in hidden_inputs[:5]:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', inp)
                    val_match = re.search(r'value=["\']([^"\']+)["\']', inp)
                    if name_match and val_match:
                        findings.append({
                            "test": "hidden_form_fields",
                            "name": name_match.group(1),
                            "value": val_match.group(1)[:30],
                            "risk": "MEDIUM",
                            "note": "Hidden fields may trick agents into submitting unintended data",
                        })

            # Check for autofill-sensitive fields
            autofill_fields = re.findall(
                r'<input[^>]*(autocomplete=["\']?(password|cc-number|cc-csc|cc-exp)[^>]*)>',
                html, re.I,
            )
            if autofill_fields:
                findings.append({
                    "test": "autofill_sensitive_fields",
                    "count": len(autofill_fields),
                    "risk": "HIGH",
                    "note": "Sensitive autofill fields may leak credentials to agents",
                })

            # Check for inline scripts that manipulate agent behavior
            inline_scripts = re.findall(
                r'<script[^>]*>[\s\S]{0,500}?(redirect|location|fetch|XMLHttpRequest|postMessage)[\s\S]{0,500}?</script>',
                html, re.I,
            )
            if inline_scripts:
                findings.append({
                    "test": "agent_manipulation_scripts",
                    "count": len(inline_scripts),
                    "risk": "HIGH",
                    "note": "Inline scripts may attempt to redirect or exfiltrate agent actions",
                })

            # Check for clickjacking via invisible overlays
            overlay_styles = re.findall(
                r'(opacity["\']?\s*[:=]\s*["\']?0|display["\']?\s*[:=]\s*["\']?none|visibility["\']?\s*[:=]\s*["\']?hidden)',
                html, re.I,
            )
            if overlay_styles:
                findings.append({
                    "test": "invisible_overlays",
                    "count": len(overlay_styles),
                    "risk": "HIGH",
                    "note": f"Invisible elements may trick agents into clicking unintended targets ({len(overlay_styles)} found)",
                })

            # Check if page contains prompt injection patterns
            body_text = re.sub(r'<[^>]+>', ' ', html)
            for pattern in INJECTION_PATTERNS:
                matches = re.findall(pattern, body_text, re.I)
                if matches:
                    findings.append({
                        "test": "prompt_injection_content",
                        "pattern": pattern,
                        "count": len(matches),
                        "risk": "CRITICAL",
                        "note": "Page content contains prompt injection keywords that may hijack AI agents",
                    })
                    break

            # Check for iframes (cross-origin risk)
            iframes = re.findall(r'<iframe[^>]*src=["\'](https?://[^"\']+)["\']', html, re.I)
            if iframes:
                findings.append({
                    "test": "cross_origin_iframes",
                    "sources": iframes[:5],
                    "risk": "MEDIUM",
                    "note": f"Iframes from {len(iframes)} external sources may leak agent context",
                })

            # Check meta refresh redirects
            meta_refresh = re.findall(
                r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']\d+;\s*url=([^"\']+)["\']',
                html, re.I,
            )
            if meta_refresh:
                findings.append({
                    "test": "meta_refresh_redirect",
                    "url": meta_refresh[0][:80],
                    "risk": "MEDIUM",
                    "note": "Meta refresh redirect may hijack agent navigation",
                })

        except httpx.HTTPError as e:
            findings.append({"test": "page_fetch", "error": str(e)[:80], "risk": "INFO"})

        # Test 2: Analyze provided custom page content
        if page_content:
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, page_content, re.I):
                    findings.append({
                        "test": "custom_content_injection",
                        "pattern": pattern,
                        "risk": "CRITICAL",
                        "note": "Provided content contains prompt injection keywords",
                    })
                    break

            # Check for sensitive data patterns in custom content
            for kw in SENSITIVE_KEYWORDS:
                if re.search(kw, page_content, re.I):
                    findings.append({
                        "test": "sensitive_data_in_custom_content",
                        "keyword": kw,
                        "risk": "HIGH",
                        "note": f"Custom content contains sensitive keyword: {kw}",
                    })

        # Test 3: Check security headers that protect agents
        try:
            resp = await client.get(base)
            headers = dict(resp.headers)
            if "x-frame-options" not in headers:
                findings.append({
                    "test": "missing_x_frame_options",
                    "risk": "MEDIUM",
                    "note": "Missing X-Frame-Options — page can be iframed for clickjacking",
                })
            if "content-security-policy" not in headers:
                findings.append({
                    "test": "missing_csp",
                    "risk": "MEDIUM",
                    "note": "Missing Content-Security-Policy — agent may execute injected scripts",
                })
        except Exception:
            pass

    return {
        "target": target,
        "findings": findings,
        "vulnerable": any(f.get("risk") in ["CRITICAL", "HIGH"] for f in findings),
        "total_findings": len(findings),
    }
