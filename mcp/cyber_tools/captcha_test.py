"""CAPTCHA bypass testing — token reuse, OCR, math solving, header/cookie manipulation, hCaptcha/Turnstile detection."""

import re, base64, io
import httpx
from urllib.parse import urlencode

# Optional OCR
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import pytesseract
    HAS_TESSERACT = True
except ImportError:
    HAS_TESSERACT = False

RECAPTCHA_KEY_PATTERN = re.compile(r'data-sitekey=["\']([^"\']+)', re.I)
TURNTstile_KEY_PATTERN = re.compile(r'sitekey["\']:\s*["\']([0-9a-zA-Z_-]+)', re.I)
HCAPTCHA_KEY_PATTERN = re.compile(r'h-captcha[^"]*sitekey["\']:\s*["\']([0-9a-zA-Z_-]+)', re.I)
MATH_PATTERN = re.compile(r'(\d+)\s*([+\-*/×÷])\s*(\d+)', re.I)
IMG_CAPTCHA_PATTERN = re.compile(r'<img[^>]+captcha[^>]*src=["\']([^"\']+)', re.I)
CAPTCHA_SECRET = re.compile(r'captchaSecret|captcha_secret|CAPTCHA_SECRET', re.I)
CAPTCHA_COOKIE = re.compile(r'captcha[_-]?solved|captchaVerified|cf-turnstile-response', re.I)


async def captcha_test(target: str, action: str = "all", captcha_url: str = "") -> dict:
    """Test CAPTCHA bypass — 15 attack vectors.

    action:
        all        — run all tests (default)
        reuse      — token reuse only
        ocr        — OCR-based text captcha
        math       — math captcha solving
        header     — header manipulation bypass
        cookie     — cookie/session bypass
        recaptcha  — reCAPTCHA analysis
        detect     — detect captcha type only
    """
    findings = []
    base_url = target.rstrip("/")
    parsed = httpx.URL(base_url)

    async with httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True) as client:
        # ── 0. Detect captcha type ──
        try:
            resp = await client.get(base_url)
            html = resp.text

            captcha_types = []
            recaptcha_keys = RECAPTCHA_KEY_PATTERN.findall(html)
            turnstile_keys = TURNTstile_KEY_PATTERN.findall(html)
            hcaptcha_keys = HCAPTCHA_KEY_PATTERN.findall(html)
            math_questions = MATH_PATTERN.findall(html)
            captcha_images = IMG_CAPTCHA_PATTERN.findall(html)

            if recaptcha_keys:
                captcha_types.append({"type": "recaptcha_v2", "site_key": recaptcha_keys[0]})
            if turnstile_keys:
                captcha_types.append({"type": "cloudflare_turnstile", "site_key": turnstile_keys[0]})
            if hcaptcha_keys:
                captcha_types.append({"type": "hcaptcha", "site_key": hcaptcha_keys[0]})
            if math_questions:
                captcha_types.append({"type": "math_captcha", "questions_found": len(math_questions)})
            if captcha_images:
                captcha_types.append({"type": "image_captcha", "images_found": len(captcha_images)})

            # Check for captcha-related forms
            if "captcha" in html.lower():
                if not captcha_types:
                    captcha_types.append({"type": "unknown"})

            # Check secret leaks
            secret_matches = CAPTCHA_SECRET.findall(html)
            if secret_matches:
                findings.append({
                    "test": "secret_key_exposed",
                    "risk": "CRITICAL",
                    "note": f"Captcha secret key pattern found in HTML: {secret_matches[0]}",
                })

            findings.append({"test": "captcha_detection", "types": captcha_types, "risk": "INFO"})
        except Exception as e:
            captcha_types = []
            findings.append({"test": "captcha_detection", "error": str(e)[:100], "risk": "INFO"})

        if action in ["detect", "all"]:
            pass  # continue to other tests

        # ── 1. Token Reuse ──
        if action in ["all", "reuse"]:
            try:
                resp = await client.get(base_url)
                # Try to find captcha token in page
                tokens = re.findall(
                    r'(?:captcha[Tt]oken|captcha_token|g-recaptcha-response|h-captcha-response|cf-turnstile-response)'
                    r'["\']?\s*[:=]\s*["\']([^"\']{10,})',
                    resp.text, re.I,
                )
                if tokens:
                    old_token = tokens[0]
                    # Reuse the token on POST
                    data = {
                        "g-recaptcha-response": old_token,
                        "h-captcha-response": old_token,
                        "captcha": old_token,
                        "cf-turnstile-response": old_token,
                    }
                    post_resp = await client.post(base_url, data=data)
                    if post_resp.status_code in [200, 302]:
                        body = post_resp.text.lower()
                        if any(w in body for w in ["success", "thank", "submitted", "welcome"]):
                            findings.append({
                                "test": "token_reuse",
                                "risk": "CRITICAL",
                                "note": f"Reused token accepted — first 30 chars: {old_token[:30]}",
                            })
                        else:
                            findings.append({
                                "test": "token_reuse",
                                "risk": "HIGH",
                                "note": "Token reused without validation error",
                            })
                else:
                    findings.append({"test": "token_reuse", "risk": "INFO", "note": "No captcha token found in page"})
            except Exception as e:
                findings.append({"test": "token_reuse", "error": str(e)[:80], "risk": "INFO"})

        # ── 2. Empty/Invalid Token Bypass ──
        if action in ["all", "reuse"]:
            bypass_values = [
                ("empty_string", ""),
                ("zero", "0"),
                ("one", "1"),
                ("true", "true"),
                ("null", "null"),
                ("undefined", "undefined"),
                ("false", "false"),
                ("empty_json", "{}"),
                ("empty_array", "[]"),
                ("sql_inject", "' OR 1=1--"),
                ("xss_basic", "<script>alert(1)</script>"),
                ("very_long", "A" * 1000),
            ]
            for name, val in bypass_values:
                try:
                    data = {
                        "captcha": val,
                        "captchaToken": val,
                        "g-recaptcha-response": val,
                        "h-captcha-response": val,
                        "cf-turnstile-response": val,
                    }
                    resp = await client.post(base_url, data=data)
                    body = resp.text.lower()
                    # Check if we got past the captcha
                    if resp.status_code == 200:
                        error_indicators = ["invalid", "wrong", "incorrect", "error", "failed", "expired"]
                        if not any(w in body for w in error_indicators):
                            findings.append({
                                "test": "empty_token_bypass",
                                "risk": "CRITICAL",
                                "value": name,
                                "note": "No error returned for invalid captcha value",
                            })
                            break
                except Exception:
                    pass
            else:
                findings.append({"test": "empty_token_bypass", "risk": "INFO", "note": "All invalid tokens rejected"})

        # ── 3. Parameter Removal ──
        if action in ["all", "reuse"]:
            for method in ["post_empty", "post_minimal"]:
                try:
                    if method == "post_empty":
                        resp = await client.post(base_url, data={})
                    else:
                        resp = await client.post(base_url, data={"q": "test"})
                    body = resp.text.lower()
                    if resp.status_code in [200, 301, 302]:
                        if any(w in body for w in ["success", "thank", "submitted", "welcome"]):
                            findings.append({
                                "test": "param_removal",
                                "risk": "CRITICAL",
                                "method": method,
                                "note": "Request without captcha param succeeded",
                            })
                except Exception:
                    pass

        # ── 4. Math Captcha Auto-Solve ──
        if action in ["all", "math"] and captcha_types:
            has_math = any(t["type"] == "math_captcha" for t in captcha_types)
            if has_math:
                try:
                    resp = await client.get(base_url)
                    questions = MATH_PATTERN.findall(resp.text)
                    for a, op, b in questions[:3]:
                        a, b = int(a), int(b)
                        if op in ["+", "add"]:
                            answer = a + b
                        elif op in ["-", "subtract"]:
                            answer = a - b
                        elif op in ["*", "×", "multiply"]:
                            answer = a * b
                        elif op in ["/", "÷", "divide"]:
                            answer = a // b if b != 0 else 0
                        else:
                            answer = 0
                        resp2 = await client.post(base_url, data={"captcha": str(answer), "answer": str(answer)})
                        body = resp2.text.lower()
                        if any(w in body for w in ["success", "thank", "correct"]):
                            findings.append({
                                "test": "math_captcha_solved",
                                "risk": "CRITICAL",
                                "equation": f"{a} {op} {b} = {answer}",
                                "note": "Math captcha auto-solved successfully",
                            })
                            break
                except Exception as e:
                    findings.append({"test": "math_captcha_solved", "error": str(e)[:80], "risk": "INFO"})

        # ── 5. Image Captcha OCR ──
        if action in ["all", "ocr"] and captcha_images:
            try:
                for img_url in captcha_images[:1]:
                    if not img_url.startswith("http"):
                        img_url = f"{parsed.scheme}://{parsed.netloc}/{img_url.lstrip('/')}"
                    img_resp = await client.get(img_url)
                    if img_resp.status_code == 200:
                        if HAS_PIL and HAS_TESSERACT:
                            img = Image.open(io.BytesIO(img_resp.content))
                            # Convert to grayscale
                            img = img.convert("L")
                            text = pytesseract.image_to_string(img, config="--psm 7 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz").strip()
                            if text:
                                resp2 = await client.post(base_url, data={"captcha": text})
                                body = resp2.text.lower()
                                if any(w in body for w in ["success", "thank", "correct"]):
                                    findings.append({
                                        "test": "ocr_bypass",
                                        "risk": "CRITICAL",
                                        "ocr_result": text[:30],
                                        "note": f"OCR extracted text and bypassed captcha: {text[:30]}",
                                    })
                                else:
                                    findings.append({
                                        "test": "ocr_bypass",
                                        "risk": "HIGH",
                                        "ocr_result": text[:30],
                                        "note": "OCR succeeded but submission unclear",
                                    })
                        else:
                            # Base64 encode for manual analysis
                            b64 = base64.b64encode(img_resp.content).decode()
                            findings.append({
                                "test": "image_captcha_captured",
                                "risk": "HIGH",
                                "note": f"Image captcha available for manual OCR (base64 length: {len(b64)})",
                                "hint": "Install pytesseract+Pillow for auto-OCR: pip install pytesseract Pillow",
                            })
            except Exception as e:
                findings.append({"test": "ocr_bypass", "error": str(e)[:80], "risk": "INFO"})

        # ── 6. Header Manipulation ──
        if action in ["all", "header"]:
            header_bypasses = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-Addr": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
                {"CF-Connecting-IP": "127.0.0.1"},
                {"X-Forwarded-Host": "localhost"},
                {"X-Host": "localhost"},
                {"Authorization": "Bearer test"},
                {"Cookie": "captcha_solved=1; cf_clearance=test"},
            ]
            for hdrs in header_bypasses:
                try:
                    data = {"captcha": "bypass", "g-recaptcha-response": "bypass"}
                    resp = await client.post(base_url, data=data, headers=hdrs)
                    body = resp.text.lower()
                    if resp.status_code == 200:
                        if any(w in body for w in ["success", "thank", "submitted"]):
                            findings.append({
                                "test": "header_bypass",
                                "risk": "CRITICAL",
                                "header": str(hdrs),
                                "note": f"Header manipulation bypassed captcha: {list(hdrs.keys())[0]}",
                            })
                            break
                except Exception:
                    pass
            if not any(f["test"] == "header_bypass" for f in findings):
                findings.append({"test": "header_bypass", "risk": "INFO", "note": "No header bypass worked"})

        # ── 7. Cookie/Session Manipulation ──
        if action in ["all", "cookie"]:
            cookie_bypasses = [
                {"captcha_solved": "1"},
                {"captcha_verified": "true"},
                {"cf_clearance": "test"},
                {"hcaptcha_bypass": "1"},
                {"recaptcha_passed": "true"},
                {"captcha_token": "test"},
                {"verified": "true"},
                {"solved": "true"},
            ]
            for cookies in cookie_bypasses:
                try:
                    data = {"captcha": "bypass"}
                    resp = await client.post(base_url, data=data, cookies=cookies)
                    body = resp.text.lower()
                    if resp.status_code == 200:
                        if any(w in body for w in ["success", "thank", "submitted"]):
                            findings.append({
                                "test": "cookie_bypass",
                                "risk": "CRITICAL",
                                "cookie": str(cookies),
                                "note": f"Cookie manipulation bypassed captcha",
                            })
                            break
                except Exception:
                    pass
            if not any(f["test"] == "cookie_bypass" for f in findings):
                findings.append({"test": "cookie_bypass", "risk": "INFO", "note": "No cookie bypass worked"})

        # ── 8. Rate Limiting Test ──
        if action in ["all", "reuse"]:
            try:
                statuses = []
                for i in range(15):
                    resp = await client.get(base_url)
                    statuses.append(resp.status_code)
                unique = set(statuses)
                if len(unique) == 1:
                    findings.append({
                        "test": "rate_limiting",
                        "risk": "HIGH",
                        "note": f"No rate limiting after 15 requests (all {statuses[0]})",
                    })
                elif 429 in unique:
                    findings.append({
                        "test": "rate_limiting",
                        "risk": "INFO",
                        "note": "Rate limiting active (429 detected)",
                    })
                else:
                    findings.append({
                        "test": "rate_limiting",
                        "risk": "MEDIUM",
                        "note": f"Mixed responses: {unique}",
                    })
            except Exception:
                findings.append({"test": "rate_limiting", "risk": "INFO", "error": "Could not test"})

        # ── 9. Hidden Field Manipulation ──
        if action in ["all", "reuse"]:
            try:
                resp = await client.get(base_url)
                hidden_fields = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', resp.text, re.I)
                for field in hidden_fields[:5]:
                    name_match = re.search(r'name=["\']([^"\']+)', field)
                    if name_match:
                        field_name = name_match.group(1)
                        if "captcha" in field_name.lower():
                            data = {field_name: "bypass"}
                            resp2 = await client.post(base_url, data=data)
                            body = resp2.text.lower()
                            if any(w in body for w in ["success", "thank"]):
                                findings.append({
                                    "test": "hidden_field_bypass",
                                    "risk": "CRITICAL",
                                    "field": field_name,
                                    "note": f"Hidden captcha field bypassed with value 'bypass'",
                                })
            except Exception:
                pass

        # ── 10. Audio Challenge Detection ──
        if action in ["all", "detect"] and captcha_types:
            has_recaptcha = any(t["type"] == "recaptcha_v2" for t in captcha_types)
            if has_recaptcha:
                findings.append({
                    "test": "audio_challenge_available",
                    "risk": "MEDIUM",
                    "note": "reCAPTCHA v2 detected — audio challenge available for manual solving via Google's speech-to-text",
                })

    # ── Summary ──
    critical = [f for f in findings if f.get("risk") == "CRITICAL"]
    high = [f for f in findings if f.get("risk") == "HIGH"]
    vulnerable = len(critical) > 0 or len(high) > 0

    return {
        "target": target,
        "captcha_types": captcha_types if captcha_types else ["none_detected"],
        "findings": findings,
        "summary": {
            "total_tests": len(findings),
            "critical": len(critical),
            "high": len(high),
            "vulnerable": vulnerable,
        },
        "risk": "CRITICAL" if critical else ("HIGH" if high else "INFO"),
        "bypass_techniques": [
            "token_reuse",
            "empty_token_bypass",
            "param_removal",
            "math_captcha_auto_solve",
            "image_captcha_ocr",
            "header_manipulation",
            "cookie_manipulation",
            "rate_limiting_bypass",
            "hidden_field_bypass",
            "secret_key_exposure",
        ],
    }
