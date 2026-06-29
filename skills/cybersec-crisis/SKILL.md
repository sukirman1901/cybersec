---
name: cybersec-crisis
description: Use when user reports an active incident, breach, or security emergency — override normal workflow
---

## Incident Response Methodology

### Checklist

Create a todo list from the checklist below, then execute all steps immediately. Don't ask for confirmation — just run the tools and mark items complete as you go.

1. **Triage** — Determine scope:
   - What systems are affected? Call `port_scan(target)` to check for unknown services
   - What's the impact? Data breach? Ransomware? Defacement?
   - When was it detected? How long has it been ongoing?

2. **Containment** — Immediate actions:
   - Identify compromised systems via open ports and unknown services
   - Check for backdoors: unusual ports, unknown processes
   - Call `gitleaks_check(path)` if git repo to check for leaked secrets
   - Recommend network isolation for affected systems

3. **Forensic Collection** — Gather evidence:
   - Service fingerprints for attacker entry point analysis
   - CVE lookup on exposed services to find exploit vector
   - DNS records for C2 communication check
   - Certificate Transparency logs for suspicious certs

4. **Analysis** — Determine entry point:
   - Which vulnerability was exploited? Cross-reference with `cve_search`
   - What data was accessed? Log analysis indicators
   - Is attacker still active? Check for persistence mechanisms

5. **Remediation** — Close the holes:
   - Patch identified vulnerabilities
   - Rotate exposed credentials immediately
   - Review and restrict access logs
   - Close unnecessary open ports

6. **Post-Incident** — Report and prevent:
   - Document incident timeline
   - Generate incident report via `generate_report`
   - Recommend security improvements
   - Load `cybersec-report` skill for formal documentation

### Tools Available
`port_scan`, `service_fingerprint`, `dns_lookup`, `gitleaks_check`, `cve_search`, `crt_search`, `ssl_check`, `ssh_audit`, `smtp_enum`, `smb_enum`, `snmp_enum`, `generate_report`

### Output
Incident response report with: timeline, affected systems, entry point, data accessed, containment actions, and remediation steps.
