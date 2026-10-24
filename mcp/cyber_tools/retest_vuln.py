"""Retest vulnerability — re-run scan to confirm fix."""

import httpx
import json
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

RETEST_CHECKS = {
    "sqli": {
        "payloads": ["'", "' OR '1'='1", "' UNION SELECT NULL--", "1' AND SLEEP(5)--"],
        "indicators": ["sql", "syntax", "mysql", "error", "warning"],
        "success_indicators": ["union select", "information_schema", "sleep"],
    },
    "xss": {
        "payloads": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "indicators": ["<script>", "onerror=", "alert(", "javascript:"],
        "success_indicators": ["<script>", "alert(", "onerror="],
    },
    "lfi": {
        "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/etc/passwd", "....//....//etc/passwd"],
        "indicators": ["root:", "daemon:", "[extensions]", "[fonts]"],
        "success_indicators": ["root:x:", "daemon:", "[boot loader]"],
    },
    "ssrf": {
       "payloads": ["http://169.254.169.254/latest/meta-data/", "http://[::1]/", "file:///etc/passwd"],
        "indicators": ["instance-id", "ami-id", "root:", "security-credentials"],
        "success_indicators": ["instance-id", "ami-id", "security-credentials"],
    },
    "open_redirect": {
        "payloads": ["//evil.com", "https://evil.com", "//evil.com/", "javascript:alert(1)"],
        "indicators": ["location: evil.com", "location: //evil", "redirect.*evil"],
        "success_indicators": ["location: evil.com", "location: //evil"],
    },
    "ssti": {
        "payloads": ["{{7*7}}", "${7*7}", "#{7*7}", "{{49}}", "{{pwn}}"],
        "indicators": ["49", "1337", "pwn"],
        "success_indicators": ["49", "1337"],
    },
    "log4j": {
        "payloads": ["${jndi:ldap://test}", "${jndi:dns://test}", "${lower:j}ndi"],
        "indicators": ["jndi", "lookup", "dns", "ldap"],
        "success_indicators": ["jndi", "lookup"],
    },
}


def retest_vuln(target: str, vuln_type: str, param: str = "", original_payload: str = "") -> str:
    """Retest a previously found vulnerability to confirm if it's fixed.

    Re-runs the original vulnerability test against the target.
    Returns retest result with before/after comparison.
    """
    vuln_type = vuln_type.lower()

    result = {
        "target": target,
        "vuln_type": vuln_type,
        "param": param,
        "retest_at": datetime.now().isoformat(),
        "status": "unknown",
        "verdict": "",
        "tests": [],
        "recommendation": "",
    }

    checks = RETEST_CHECKS.get(vuln_type)
    if not checks:
        result["error"] = f"Unknown vuln type: {vuln_type}. Supported: {', '.join(RETEST_CHECKS.keys())}"
        return json.dumps(result, indent=2)

    payloads = [original_payload] if original_payload else checks["payloads"]
    still_vulnerable = False
    incomplete = False
    result["verified_fixed"] = False

    for payload in payloads:
        test = {"payload": payload, "vulnerable": False, "evidence": ""}
        parts = urlsplit(target)
        key = param or "test"
        query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
        query.append((key, payload))
        test_url = urlunsplit(parts._replace(query=urlencode(query), fragment=""))
        try:
            resp = httpx.get(test_url, timeout=10, follow_redirects=False, verify=False)
            body = resp.text.lower()
            if resp.status_code >= 400:
                test["incomplete"] = True
                incomplete = True
                test["status_code"] = resp.status_code
                result["tests"].append(test)
                continue
            if 300 <= resp.status_code < 400:
                test["incomplete"] = True
                incomplete = True

            for indicator in checks["success_indicators"]:
                if indicator.lower() in body:
                    test["vulnerable"] = True
                    test["evidence"] = f"Found '{indicator}' in response"
                    still_vulnerable = True
                    break

            if not test["vulnerable"] and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "").lower()
                for indicator in checks["success_indicators"]:
                    if indicator.lower() in location:
                        test["vulnerable"] = True
                        test["evidence"] = f"Found '{indicator}' in redirect Location header"
                        still_vulnerable = True
                        break

            test["status_code"] = resp.status_code
        except httpx.RequestError as e:
            test["error"] = str(e)
            incomplete = True

        result["tests"].append(test)

    if still_vulnerable:
        result["status"] = "still_vulnerable"
        result["verdict"] = f"VULNERABILITY NOT FIXED — {vuln_type} still exploitable"
        result["recommendation"] = "The fix has not resolved the vulnerability. Review the remediation and reapply."
    elif incomplete:
        result["status"] = "inconclusive"
        result["verdict"] = "Retest incomplete: network errors or blocked/error responses"
        result["recommendation"] = "Restore equivalent access and replay the original evidence before deciding remediation status."
    else:
        result["status"] = "not_reproduced"
        result["verdict"] = "Original indicators were not reproduced in the tested coverage; remediation is not verified."
        result["recommendation"] = "Compare with the original request, session and baseline before marking the finding fixed."

    return json.dumps(result, indent=2)
