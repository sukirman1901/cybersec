"""
Vulnerability scanner via security header checks, path probes, and CVE pattern matching.
Pure Python, no external binaries.
"""

import re
from typing import Dict, List

SECURITY_CHECKS = {
    "missing-x-frame-options": {
        "name": "Missing X-Frame-Options Header",
        "severity": "medium",
        "description": "X-Frame-Options header is not set, may allow clickjacking.",
        "check": lambda h: "x-frame-options" not in {k.lower() for k in h},
    },
    "missing-csp": {
        "name": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "description": "CSP header is not set, may allow XSS attacks.",
        "check": lambda h: "content-security-policy" not in {k.lower() for k in h},
    },
    "missing-hsts": {
        "name": "Missing Strict-Transport-Security Header",
        "severity": "low",
        "description": "HSTS header is not set, may allow downgrade attacks.",
        "check": lambda h: "strict-transport-security" not in {k.lower() for k in h},
    },
    "missing-x-content-type-options": {
        "name": "Missing X-Content-Type-Options Header",
        "severity": "low",
        "description": "X-Content-Type-Options header is not set.",
        "check": lambda h: "x-content-type-options" not in {k.lower() for k in h},
    },
    "missing-x-xss-protection": {
        "name": "Missing X-XSS-Protection Header",
        "severity": "info",
        "description": "X-XSS-Protection header is not set.",
        "check": lambda h: "x-xss-protection" not in {k.lower() for k in h},
    },
    "server-header-disclosure": {
        "name": "Server Header Information Disclosure",
        "severity": "info",
        "description": "Server header reveals software information.",
        "check": lambda h: "server" in {k.lower() for k in h},
    },
    "x-powered-by-disclosure": {
        "name": "X-Powered-By Header Information Disclosure",
        "severity": "info",
        "description": "X-Powered-By header reveals technology information.",
        "check": lambda h: "x-powered-by" in {k.lower() for k in h},
    },
}

PATH_CHECKS = [
    {"path": "/.git/config", "name": "Git Config Exposure", "severity": "high",
     "pattern": r"\[core\]|\[remote"},
    {"path": "/.env", "name": "Environment File Exposure", "severity": "critical",
     "pattern": r"(DB_|API_|SECRET|PASSWORD|KEY)="},
    {"path": "/robots.txt", "name": "Robots.txt Exposure", "severity": "info",
     "pattern": r"(Disallow|Allow):"},
    {"path": "/.htaccess", "name": "Htaccess File Exposure", "severity": "medium",
     "pattern": r"(RewriteRule|RewriteCond|AuthType)"},
    {"path": "/wp-config.php.bak", "name": "WordPress Config Backup", "severity": "critical",
     "pattern": r"(DB_NAME|DB_USER|DB_PASSWORD)"},
    {"path": "/server-status", "name": "Apache Server Status", "severity": "medium",
     "pattern": r"Apache Server Status"},
    {"path": "/phpinfo.php", "name": "PHP Info Exposure", "severity": "medium",
     "pattern": r"PHP Version|phpinfo\(\)"},
    {"path": "/debug", "name": "Debug Endpoint", "severity": "medium",
     "pattern": r"(debug|stack|trace|error)"},
    {"path": "/admin", "name": "Admin Panel", "severity": "info",
     "pattern": r"(login|admin|dashboard)"},
    {"path": "/backup.sql", "name": "SQL Backup Exposure", "severity": "critical",
     "pattern": r"(CREATE TABLE|INSERT INTO)"},
    {"path": "/config.json", "name": "Config JSON Exposure", "severity": "high",
     "pattern": r'("password"|"secret"|"api_key")'},
    {"path": "/.DS_Store", "name": "DS_Store File Exposure", "severity": "low",
     "pattern": r"Bud1"},
]

CVE_PATTERNS = [
    {"pattern": r"Apache/(2\.4\.[0-9]|2\.4\.[1-3][0-9]|2\.4\.4[0-8])\b",
     "cve": "CVE-2021-44790", "name": "Apache HTTP Server Buffer Overflow", "severity": "high",
     "description": "Apache <2.4.52 vulnerable to buffer overflow."},
    {"pattern": r"nginx/(1\.1[0-8]|1\.19\.[0-9]|1\.20\.0)\b",
     "cve": "CVE-2021-23017", "name": "nginx DNS Resolver Vulnerability", "severity": "high",
     "description": "nginx <1.20.1 vulnerable to DNS resolver issues."},
    {"pattern": r"PHP/(5\.|7\.[0-3]\.|7\.4\.[0-9]|7\.4\.[1][0-9]|7\.4\.2[0-5])\b",
     "cve": "CVE-2022-31626", "name": "PHP Buffer Overflow", "severity": "high",
     "description": "PHP versions vulnerable to buffer overflow in mysqlnd."},
    {"pattern": r"WordPress/(4\.|5\.[0-7]\.)",
     "cve": "CVE-2022-21661", "name": "WordPress SQL Injection", "severity": "high",
     "description": "WordPress <5.8.3 vulnerable to SQL injection."},
    {"pattern": r"jQuery/(1\.|2\.|3\.[0-4]\.)",
     "cve": "CVE-2020-11023", "name": "jQuery XSS Vulnerability", "severity": "medium",
     "description": "jQuery <3.5.0 vulnerable to XSS."},
]


async def scan_vulnerabilities(target: str) -> Dict:
    """Scan a target for common vulnerabilities (header checks, path probes, CVE patterns)."""
    import httpx

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    vulnerabilities: List[Dict] = []

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
            try:
                response = await client.get(target)
                headers = response.headers
                content = response.text

                for check_id, check in SECURITY_CHECKS.items():
                    if check["check"](headers):
                        vulnerabilities.append({
                            "name": check["name"], "severity": check["severity"],
                            "description": check["description"], "matched_at": target,
                            "type": "misconfiguration",
                        })

                combined = str(headers) + content
                for cve in CVE_PATTERNS:
                    if re.search(cve["pattern"], combined, re.IGNORECASE):
                        vulnerabilities.append({
                            "name": cve["name"], "severity": cve["severity"],
                            "description": cve["description"], "matched_at": target,
                            "type": "cve", "cve": cve["cve"],
                        })
            except httpx.HTTPError:
                pass

            for pc in PATH_CHECKS:
                try:
                    path_url = target.rstrip("/") + pc["path"]
                    pr = await client.get(path_url)
                    if pr.status_code == 200 and re.search(pc["pattern"], pr.text, re.IGNORECASE):
                        vulnerabilities.append({
                            "name": pc["name"], "severity": pc["severity"],
                            "description": pc["description"], "matched_at": path_url,
                            "type": "exposure",
                        })
                except httpx.HTTPError:
                    continue

    except Exception as e:
        return {"vulnerabilities": [], "error": str(e)}

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulnerabilities:
        s = v["severity"]
        if s in by_severity:
            by_severity[s] += 1

    return {
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "by_severity": by_severity,
    }
