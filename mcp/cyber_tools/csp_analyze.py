import httpx
import re


async def csp_analyze(target: str) -> dict:
    findings = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp = await client.get(target)
        csp = resp.headers.get("content-security-policy", "")
        if csp:
            directives = {}
            for d in csp.split(";"):
                d = d.strip()
                if " " in d:
                    key, val = d.split(" ", 1)
                    directives[key] = val.strip()
            issues = []
            if "'unsafe-inline'" in csp:
                issues.append({"directive": "script-src / style-src", "issue": "'unsafe-inline' weakens XSS protection", "severity": "high"})
            if "'unsafe-eval'" in csp:
                issues.append({"directive": "script-src", "issue": "'unsafe-eval' allows eval()", "severity": "medium"})
            if "https:" in csp or "http:" in csp:
                issues.append({"directive": "Various", "issue": "Scheme-allowlist (https:) too broad", "severity": "medium"})
            if "*" in csp:
                issue_dirs = [k for k in directives if directives[k] == "*"]
                for d in issue_dirs:
                    issues.append({"directive": d, "issue": "Wildcard (*) allows all sources", "severity": "high"})
            if "none" not in csp and "self" not in csp:
                issues.append({"issue": "CSP does not include 'self' as base", "severity": "low"})
            findings.append({"csp_present": True, "directives_count": len(directives), "directives": directives, "issues": issues, "severity": "info"})
        else:
            findings.append({"csp_present": False, "severity": "high", "note": "No Content-Security-Policy header — at risk of XSS"})
        xfo = resp.headers.get("x-frame-options", "")
        findings.append({"header": "X-Frame-Options", "value": xfo or "missing", "severity": "high" if not xfo else "info"})
        xcto = resp.headers.get("x-content-type-options", "")
        findings.append({"header": "X-Content-Type-Options", "value": xcto or "missing", "severity": "medium" if not xcto else "info"})
        rp = resp.headers.get("referrer-policy", "")
        findings.append({"header": "Referrer-Policy", "value": rp or "missing", "severity": "low" if not rp else "info"})
        hsts = resp.headers.get("strict-transport-security", "")
        findings.append({"header": "Strict-Transport-Security", "value": hsts or "missing", "severity": "medium" if not hsts else "info"})
    return {"target": target, "findings": findings, "count": len(findings)}
