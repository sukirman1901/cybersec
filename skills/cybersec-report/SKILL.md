---
name: cybersec-report
description: Use when user asks for a security report, remediation plan, or fix recommendations
---

## Reporting Methodology

### Checklist

Create a todo list from the checklist below, then execute all steps immediately. Don't ask for confirmation — just run the tools and mark items complete as you go.

1. **Compile Findings** — Gather all data from current session:
   - Recon results (domains, subdomains, tech stack, network info)
   - Scan results (open ports, services, banners)
   - Vulnerability findings (CVEs, weaknesses, misconfigs)
   - Web findings (paths, API issues, input vulns)
   - Exploit results (successful exploits, data accessed)

2. **Risk Assessment** — Rate each finding:
   - CRITICAL: Remote code execution, data breach, auth bypass
   - HIGH: SQL injection, privilege escalation, sensitive data exposure
   - MEDIUM: XSS, directory listing, missing security headers
   - LOW: Information disclosure, outdated versions without known exploits

3. **Generate Report** — Call `generate_report(target, findings, "markdown")` with structured findings JSON:
   ```json
   {
     "target": "example.com",
     "recon": { ... },
     "scanning": { ... },
     "vulnerabilities": [ ... ],
     "web": [ ... ],
     "exploitation": [ ... ],
     "remediation": [ ... ]
   }
   ```

4. **Generate Remediation Code** — For each vulnerability:
   - Run `generate_report(target, findings_json)` — tool auto-generates fix code
   - Verify fix code is correct for the target's tech stack
   - If finding type isn't auto-matched, write custom fix code manually:
     - LFI: Path validation + allowlist pattern
     - SQLi: Parameterized queries / ORM
     - XSS: HTML escaping + CSP headers
     - SSRF: URL allowlist + IP blacklist
     - Open ports: Firewall rules
     - Weak SSL: TLS config snippet
     - Missing headers: Security header config

5. **Review Report** — Verify:
   - All findings are documented
   - Risk ratings are justified
   - Remediation steps are actionable with code snippets
   - Fix code is copy-pasteable (correct syntax, no placeholders missing)
   - Executive summary explains business impact

6. **Remediation Plan** — Create prioritized fix list:
   - Immediate (24h): Critical vulnerabilities, exposed credentials
   - Short-term (1 week): High vulnerabilities, missing patches
   - Medium-term (2 weeks): Medium vulnerabilities, config hardening
   - Long-term (1 month): Low vulnerabilities, best practices

7. **Compliance Mapping** — Map findings to frameworks (SOC2, ISO27001, GDPR, PCI-DSS, NIST 800-53) via `compliance_map`
8. **Schema & Packaging** — Validate/convert/meld findings with `report_schema_v2` (v1→v2, evidence chain); batch-team or client variants via `branded_report` (white-label logo/colors/company)
9. **Executive Summary** — Auto-generate risk posture, severity breakdown, top findings with `executive_summary`

### Tools Available
`generate_report`, `cve_search`, `dork_search`, `compliance_map`, `report_schema_v2`, `branded_report`, `executive_summary`

### Output
Professional security report with: executive summary, methodology, detailed findings with evidence, risk ratings, prioritized remediation plan, and copy-pasteable fix code per vulnerability.
