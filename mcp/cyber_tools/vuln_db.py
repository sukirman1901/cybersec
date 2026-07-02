"""CVE lookup via NVD API. Also contains built-in known vuln patterns."""

import urllib.request
import json

KNOWN_VULNS = {
    "apache 2.4.49": [{"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Path traversal and file disclosure in Apache HTTP Server 2.4.49"}],
    "apache 2.4.50": [{"id": "CVE-2021-42013", "severity": "CRITICAL", "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.50"}],
    "apache 2.4.29": [{"id": "EOL", "severity": "HIGH", "description": "Apache 2.4.29 is end-of-life; upgrade to supported 2.4.x branch"}],
    "nginx 1.18": [{"id": "CVE-2021-23017", "severity": "HIGH", "description": "1-byte memory overwrite in nginx resolver (1.18.0-1.20.0)"}],
    "nginx 1.22": [{"id": "CVE-2023-44487", "severity": "HIGH", "description": "HTTP/2 Rapid Reset DoS affecting nginx with HTTP/2 enabled"}],
    "nginx 1.24": [{"id": "CVE-2024-7347", "severity": "MEDIUM", "description": "Buffer overread in nginx QUIC module"}],
    "openssh 7.2": [{"id": "CVE-2016-10009", "severity": "HIGH", "description": "OpenSSH agent hijacking via forwarded agent"}],
    "php 5.6": [{"id": "EOL", "severity": "CRITICAL", "description": "PHP 5.6 reached end-of-life; no security patches"}],
    "php 7.4": [{"id": "CVE-2024-4577", "severity": "CRITICAL", "description": "PHP CGI argument injection on Windows"}],
    "php 8.0": [{"id": "EOL", "severity": "HIGH", "description": "PHP 8.0 is end-of-life; upgrade to 8.2+"}],
    "wordpress": [{"id": "MULTIPLE", "severity": "VARIES", "description": "WordPress core and plugin vulnerabilities. Always check latest version."}],
}


def _match_known(query: str) -> list[dict]:
    """Match service/version against KNOWN_VULNS with prefix tolerance."""
    results: list[dict] = []
    seen: set[str] = set()
    for pattern, vulns in KNOWN_VULNS.items():
        parts = pattern.split()
        service = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        if service not in query:
            continue
        if version and version not in query:
            continue
        for v in vulns:
            vid = v.get("id", "")
            if vid not in seen:
                seen.add(vid)
                results.extend([v])
    return results

def cve_lookup(service: str, version: str = "") -> list[dict]:
    """Look up CVEs for a service. Checks built-in DB + NVD API."""
    query = f"{service} {version}".strip().lower()
    results = _match_known(query)

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
