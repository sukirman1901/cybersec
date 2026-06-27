---
name: cybersec-crisis
description: Use when user reports an active incident, breach, or security emergency
---

## Incident Response Methodology

1. **Triage** — Determine scope: what's affected, what's the impact
2. **Containment** — Immediate actions:
   - Identify compromised systems via `port_scan(ip)`
   - Check for open backdoors or unknown services
3. **Forensic Collection** — Gather evidence without destroying it
4. **Analysis** — Determine entry point and attack vector
5. **Remediation** — Steps to close the hole:
   - Patch identified vulnerabilities
   - Rotate exposed credentials
   - Review access logs
6. **Post-Incident** — Recommendations to prevent recurrence

**Output:** Incident response timeline, findings, and remediation steps.
