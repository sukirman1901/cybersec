"""WAF detection via response analysis."""

import urllib.request
import ssl
import re

WAF_SIGNATURES = {
    "Cloudflare": [r"cloudflare", r"__cfduid", r"cf-ray"],
    "ModSecurity": [r"ModSecurity", r"NOYB"],
    "AWS WAF": [r"awselb", r"AWS"],
    "Akamai": [r"akamai", r"akamaid"],
    "Sucuri": [r"Sucuri", r"cloudproxy"],
    "Barracuda": [r"barracuda", r"BarracudaNet"],
    "F5 BIG-IP": [r"BigIP", r"F5"],
    "Imperva": [r"incapsula", r"Imperva"],
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def waf_detect(target: str) -> dict:
    """Detect WAF by analyzing response headers and content."""
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    result = {"target": target, "waf_detected": False, "waf_name": None, "signatures_found": [], "error": None}
    try:
        req = urllib.request.Request(f"https://{target}", method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
        except urllib.error.HTTPError as e:
            resp = e
        headers_text = str(resp.headers)
        body = resp.read().decode("utf-8", errors="replace")[:2000]
        resp.close()
        for waf_name, patterns in WAF_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, headers_text, re.IGNORECASE) or re.search(pattern, body, re.IGNORECASE):
                    result["waf_detected"] = True
                    result["waf_name"] = waf_name
                    result["signatures_found"].append(pattern)
                    break
            if result["waf_detected"]:
                break
    except Exception as e:
        result["error"] = str(e)
    return result
