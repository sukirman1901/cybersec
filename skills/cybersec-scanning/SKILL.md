---
name: cybersec-scanning
description: Use when user asks to scan ports, detect services, or fingerprint a target
---

## Port Scanning Methodology

1. **Port Scan** — Call `port_scan(target)` with common ports first
2. **Analyze Results** — Identify which ports are open and their services
3. **Service Detection** — For each open port, identify the service and version
4. **Web Services** — If web ports found (80, 443, 8080, 8443), call `http_probe_target(target)`
5. **SSL Check** — If HTTPS detected, call `ssl_check(target)` to analyze certificate
6. **CVE Lookup** — For detected services, call `cve_search(service, version)` to find known vulnerabilities

**Output:** Table of open ports with services, versions, and associated CVEs.
