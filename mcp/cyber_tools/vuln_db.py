"""CVE lookup via NVD API. Also contains built-in known vuln patterns."""

import urllib.request
import json

KNOWN_VULNS = {
    "apache 2.4.49": [{"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Path traversal and file disclosure in Apache HTTP Server 2.4.49"}],
    "apache 2.4.50": [{"id": "CVE-2021-42013", "severity": "CRITICAL", "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.50"}],
    "openssh 7.2": [{"id": "CVE-2016-10009", "severity": "HIGH", "description": "OpenSSH agent hijacking via forwarded agent"}],
    "php 7.4": [{"id": "CVE-2024-4577", "severity": "CRITICAL", "description": "PHP CGI argument injection on Windows"}],
    "wordpress": [{"id": "MULTIPLE", "severity": "VARIES", "description": "WordPress core and plugin vulnerabilities. Always check latest version."}],
}

def cve_lookup(service: str, version: str = "") -> list[dict]:
    """Look up CVEs for a service. Checks built-in DB + NVD API."""
    query = f"{service} {version}".strip().lower()
    results = []

    for pattern, vulns in KNOWN_VULNS.items():
        if pattern in query or query in pattern:
            results.extend(vulns)

    try:
        search = urllib.request.quote(f"{service} {version}")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search}&resultsPerPage=5"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    break
            results.append({
                "id": cve.get("id", ""),
                "severity": severity,
                "description": cve.get("descriptions", [{}])[0].get("value", "")[:200],
            })
    except Exception:
        pass

    return results
