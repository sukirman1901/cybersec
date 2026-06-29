---
name: cybersec-vulns
description: Use when user asks to find vulnerabilities, check CVEs, or assess security weaknesses
---

## Vulnerability Assessment Methodology

### Checklist

Execute tools immediately. Don't ask for confirmation. Just run the tools and show output.

1. **CVE Lookup** — For each detected service + version, call `cve_search(service, version)` for known vulnerabilities
2. **Vulnerability Scan** — Call `vuln_scan(target)` for common vulnerability patterns
3. **CVE Cross-Reference** — For software with multiple CVEs, check severity and public exploit availability
4. **Tech Detection** — Call `tech_detect(target)` to identify CMS/framework versions for known vulns
5. **SSL Issues** — If ssl_check found weaknesses, document: weak ciphers, expired cert, missing HSTS
6. **Prioritize Findings** — Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
7. **Exploit Research** — For critical/high findings, check if public PoC exists via `cve_search`

### Tools Available
`cve_search`, `vuln_scan`, `tech_detect`, `ssl_check`, `crt_search`, `dork_search`

### Output
Prioritized vulnerability list with: CVE ID, CVSS score, affected service, description, and known exploit status.

### Next Skill
If web services found, load `cybersec-web` skill for web-specific testing.
Otherwise load `cybersec-exploit` skill directly.
