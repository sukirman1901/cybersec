---
name: cybersec-report
description: Use when user asks for a security report, remediation plan, or fix recommendations
---

## Reporting Methodology

1. **Compile Findings** — Gather all data from current session
2. **Generate Report** — Call `generate_report(target, findings, format)` with findings JSON
3. **Review Results** — Check the report is complete and accurate
4. **Remediation Priority** — Recommend fixes by severity:
   - CRITICAL: Fix immediately
   - HIGH: Fix within 48 hours
   - MEDIUM: Fix within 2 weeks
   - LOW: Fix when convenient

**Output:** Professional security report with executive summary, findings, and remediation plan.
