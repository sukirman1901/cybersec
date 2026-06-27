---
name: cybersec-vulns
description: Use when user asks to find vulnerabilities, check CVEs, or assess security weaknesses
---

## Vulnerability Assessment Methodology

1. **Service Inventory** — Make sure you have list of services from scanning phase
2. **CVE Lookup** — For each service+version, call `cve_search(service, version)`
3. **Web Vulnerabilities** — If web app detected:
   - Call `dir_bruteforce(target)` to find hidden paths
   - Check for admin panels, backup files, exposed configs
4. **SSL Issues** — If `ssl_check` found weak ciphers, note them
5. **Prioritize by Severity** — Sort findings by CRITICAL > HIGH > MEDIUM > LOW

**Output:** Prioritized vulnerability list with CVSS scores and remediation guidance.
