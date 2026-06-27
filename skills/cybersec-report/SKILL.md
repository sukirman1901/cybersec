---
name: cybersec-report
description: Use when user asks for a security report, remediation plan, or fix recommendations
---

<HARD-GATE>
Do NOT generate final report before all testing phases are complete (unless user explicitly asks for interim report).
Must have findings from all previous phases before generating executive report.
Report MUST include: executive summary, methodology, findings, risk ratings, and remediation plan.
</HARD-GATE>

## Reporting Methodology

### Checklist

Create a TodoWrite for each item and complete in order:

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

4. **Review Report** — Verify:
   - All findings are documented
   - Risk ratings are justified
   - Remediation steps are actionable
   - Executive summary explains business impact

5. **Remediation Plan** — Create prioritized fix list:
   - Immediate (24h): Critical vulnerabilities, exposed credentials
   - Short-term (1 week): High vulnerabilities, missing patches
   - Medium-term (2 weeks): Medium vulnerabilities, config hardening
   - Long-term (1 month): Low vulnerabilities, best practices

### Tools Available
`generate_report`, `cve_search`, `dork_search`

### Output
Professional security report with: executive summary, methodology, detailed findings with evidence, risk ratings, and prioritized remediation plan.
