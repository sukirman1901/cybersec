import httpx
import re


async def csrf_detect(target: str) -> dict:
    findings = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp = await client.get(target)
        forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL)
        for i, form in enumerate(forms):
            has_csrf = bool(re.search(r'csrf|token|_token|authenticity_token', form, re.I))
            method = re.search(r'method=["\'](.*?)["\']', form)
            action = re.search(r'action=["\'](.*?)["\']', form)
            findings.append({
                "form": i + 1,
                "action": action.group(1) if action else "same page",
                "method": method.group(1).upper() if method else "GET",
                "has_csrf_token": has_csrf,
                "vulnerable": not has_csrf and (method and method.group(1).upper() in ("POST", "PUT", "DELETE")),
            })
        origin = resp.headers.get("origin", "")
        referer = "referer" in str(resp.headers).lower()
        findings.append({
            "check": "Origin/Referer headers",
            "origin_present": bool(origin),
            "referer_checked": referer,
            "note": "Web apps should validate Origin/Referer for state-changing requests" if not origin and not referer else ""
        })
        same_site = resp.headers.get("set-cookie", "")
        samesite_found = "samesite" in same_site.lower() if same_site else False
        findings.append({
            "check": "SameSite cookies",
            "samesite_set": samesite_found,
            "note": "Cookies should have SameSite=Lax or Strict" if not samesite_found else ""
        })
    return {"target": target, "findings": findings, "csrf_vulnerable": any(f.get("vulnerable") for f in findings)}
