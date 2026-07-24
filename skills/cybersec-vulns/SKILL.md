---
name: cybersec-vulns
description: Use when user asks to find vulnerabilities, check CVEs, or assess security weaknesses
---

## Vulnerability Assessment Methodology

### Checklist

Create a todo list from the checklist below, then execute all steps immediately. Don't ask for confirmation — just run the tools and mark items complete as you go.

1. **CVE Lookup** — For each detected service + version, call `cve_search(service, version)` for known vulnerabilities
2. **Vulnerability Scan** — Call `vuln_scan(target)` for common vulnerability patterns
3. **CVE Cross-Reference** — For software with multiple CVEs, check severity and public exploit availability
4. **CRLF Injection Scan** — Call `crlf_inject(target)` for HTTP header injection vulnerabilities
5. **LDAP Injection Scan** — If LDAP endpoints found, call `ldap_inject(target)` for LDAP query manipulation
6. **Deserialization Check** — If Python app: call `pickle_deserialize(target)`. If API: call `mass_assignment(target)` for privilege escalation
7. **Tech Detection** — Call `tech_detect(target)` to identify CMS/framework versions for known vulns
8. **SSL Issues** — If ssl_check found weaknesses, document: weak ciphers, expired cert, missing HSTS
9. **Prioritize Findings** — Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
10. **Exploit Research** — For critical/high findings, check if public PoC exists via `cve_search`

### Tools Available
`cve_search`, `vuln_scan`, `tech_detect`, `ssl_check`, `crt_search`, `dork_search`, `crlf_inject`, `ldap_inject`, `pickle_deserialize`, `mass_assignment`

### Output
Prioritized vulnerability list with: CVE ID, CVSS score, affected service, description, and known exploit status.

### Next Skill
If web services found, load `cybersec-web` skill for web-specific testing.
Otherwise load `cybersec-exploit` skill directly.
