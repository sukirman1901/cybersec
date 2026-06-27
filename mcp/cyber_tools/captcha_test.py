"""Test CAPTCHA bypass — token reuse, empty values, parameter removal, rate limiting."""

import re
import httpx

SENSITIVE_LOG_KW = [
    "password", "error", "exception", "stacktrace",
    "sql", "select", "insert", "delete", "credentials",
    "token", "session",
]


async def captcha_test(
    target: str,
    captcha_param: str = "captcha",
    token_param: str = "captchaToken",
) -> dict:
    findings = []
    base_url = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Test 1: Reuse old CAPTCHA token
        try:
            resp = await client.get(base_url)
            # Try to find a captcha token in the page
            tokens = re.findall(
                r'captcha[Token]?["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                resp.text, re.I,
            )
            if tokens:
                old_token = tokens[0]
                data = {captcha_param: old_token, token_param: old_token}
                resp2 = await client.post(base_url, data=data)
                if resp2.status_code == 200:
                    findings.append({
                        "test": "captcha_reuse",
                        "vulnerable": True,
                        "note": f"Reused CAPTCHA token: {old_token[:30]}",
                    })
        except Exception:
            findings.append({
                "test": "captcha_reuse",
                "vulnerable": False,
                "note": "Could not extract token",
            })

        # Test 2: Empty/short values
        for val in ["", "0", "1", "true", "null", "undefined"]:
            try:
                data = {captcha_param: val, token_param: val}
                resp = await client.post(base_url, data=data)
                if resp.status_code == 200 and "invalid" not in resp.text.lower():
                    findings.append({
                        "test": "captcha_bypass_value",
                        "vulnerable": True,
                        "value_tried": val,
                    })
                    break
            except Exception:
                pass
        else:
            findings.append({
                "test": "captcha_bypass_value",
                "vulnerable": False,
            })

        # Test 3: Remove CAPTCHA parameter
        try:
            resp = await client.post(base_url, data={})
            if resp.status_code == 200 and (
                "success" in resp.text.lower() or "thank" in resp.text.lower()
            ):
                findings.append({
                    "test": "captcha_param_removal",
                    "vulnerable": True,
                })
        except Exception:
            findings.append({
                "test": "captcha_param_removal",
                "vulnerable": False,
            })

        # Test 4: Rate limit check
        try:
            responses = []
            for _ in range(10):
                resp = await client.get(base_url)
                responses.append(resp.status_code)
            if len(set(responses)) == 1:
                findings.append({
                    "test": "rate_limiting",
                    "vulnerable": True,
                    "note": "No rate limiting detected (10 requests all returned same status)",
                })
            else:
                findings.append({
                    "test": "rate_limiting",
                    "vulnerable": False,
                    "note": "Rate limiting may be active",
                })
        except Exception:
            findings.append({
                "test": "rate_limiting",
                "vulnerable": False,
                "error": "Could not test",
            })

    vulnerable = any(f.get("vulnerable") for f in findings)
    return {
        "target": target,
        "findings": findings,
        "vulnerable": vulnerable,
        "risk": "HIGH" if vulnerable else "INFO",
    }
