---
name: cybersec-ctem
description: Use when user asks about continuous threat exposure management, attack surface monitoring, or ongoing security posture
---

# CTEM — Continuous Threat Exposure Management

## Overview

CTEM is a continuous loop: **Discovery → Validation → Prioritization → Remediation**. Unlike one-time pentests, CTEM runs continuously to catch new exposures as they emerge.

## Prerequisites

- **Ensure authorization** — only test targets you own or have permission to test
- **Establish scope** — define which assets, IP ranges, domains are in scope

## Phase 1: Discovery (Continuous)

### Checklist

- [ ] Run `subdomain_enum` on target domain
- [ ] Run `dns_lookup` to get A/AAAA/MX/NS records
- [ ] Run `port_scan` on discovered hosts (all common ports)
- [ ] Run `http_probe_target` on web services
- [ ] Run `tech_detect` to identify technologies
- [ ] Run `crt_search` for certificate transparency data
- [ ] Run `shodan_lookup` for exposed services
- [ ] Run `whois_lookup` for registration data
- [ ] Store results with `continuous_monitor` (action: record)
- [ ] Build attack surface with `attack_surface_map`

### MCP Tools

`subdomain_enum`, `dns_lookup`, `port_scan`, `http_probe_target`, `tech_detect`, `crt_search`, `shodan_lookup`, `whois_lookup`, `continuous_monitor`, `attack_surface_map`

### Output

JSON attack surface map + stored monitoring snapshot

---

## Phase 2: Validation

### Checklist

- [ ] Run `vuln_scan` on discovered web services
- [ ] Run specific vuln tests based on technologies found:
  - Web: `sqli_detect`, `xss_detect`, `ssti_detect`, `lfi_detect`, `ssrf_detect`, `xxe_detect`
  - Auth: `authenticated_scan` if login endpoints found
  - Headers: `cors_check`, `csp_analyze`, `cookie_audit`
  - Advanced: `bypass_403`, `smuggling_check`, `log4j_scan`, `jwt_forgery`
- [ ] For each finding, run `vuln_validate` to confirm exploitability
- [ ] Filter out false positives (vuln_validate returns is_false_positive)
- [ ] Add confirmed findings to `findings_manager` (action: add)
- [ ] If exploit DB available, run `exploit_db_search` for known exploits

### MCP Tools

`vuln_scan`, `sqli_detect`, `xss_detect`, `ssti_detect`, `lfi_detect`, `ssrf_detect`, `xxe_detect`, `authenticated_scan`, `cors_check`, `csp_analyze`, `cookie_audit`, `bypass_403`, `smuggling_check`, `log4j_scan`, `jwt_forgery`, `vuln_validate`, `findings_manager`, `exploit_db_search`

### Output

Validated findings with confidence scores, stored in findings database

---

## Phase 3: Prioritization

### Checklist

- [ ] For each confirmed finding, run `risk_score` with appropriate asset value
- [ ] Sort findings by risk_score (highest first)
- [ ] Identify findings with:
  - Critical risk score (9-10) → immediate action
  - High risk score (7-8.9) → fix within 7 days
  - Medium risk score (4-6.9) → fix within 30 days
  - Low risk score (1-3.9) → fix when possible
- [ ] Check for public exploits with `exploit_db_search` (increases priority)
- [ ] Update findings_manager status to "confirmed" for validated findings
- [ ] Present prioritized list to user with risk scores

### MCP Tools

`risk_score`, `exploit_db_search`, `findings_manager` (action: update), `vuln_validate`

### Output

Prioritized findings list with risk scores and remediation timeline

---

## Phase 4: Remediation & Retesting

### Checklist

- [ ] Generate remediation plan using `report_export` (format: html)
- [ ] For each finding, provide specific fix recommendations
- [ ] After fixes are applied, run `retest_vuln` to confirm fix
- [ ] Run `vuln_diff` comparing before/after scan results
- [ ] Update `findings_manager` status:
  - "fixing" → when remediation in progress
  - "fixed" → when vuln no longer exploitable
  - "retested" → after successful retest
  - "wont_fix" → if risk accepted
- [ ] Record new scan with `continuous_monitor` (action: record)
- [ ] Generate final report with `report_export`

### MCP Tools

`report_export`, `retest_vuln`, `vuln_diff`, `findings_manager` (action: update), `continuous_monitor` (action: record)

### Output

Remediation report, retest results, updated findings database

---

## Continuous Loop

After Phase 4, the cycle restarts:

1. **Schedule** next discovery scan (daily/weekly/monthly based on risk)
2. **Record** new scan with `continuous_monitor`
3. **Diff** against previous scan with `continuous_monitor` (action: diff)
4. **Validate** any new findings with `vuln_validate`
5. **Score** new findings with `risk_score`
6. **Remediate** critical/high findings immediately
7. **Retest** to confirm fixes

### Automated Workflow

Use `pentest_workflow` with templates:
- `recon-full` → comprehensive discovery
- `web-audit` → web application testing
- `network-scan` → network security
- `bugbounty` → quick bug bounty sweep
- `cloud-audit` → cloud security audit

### Bulk Operations

- `bulk_scan` → scan multiple targets at once (max 50)
- `findings_manager` (action: stats) → dashboard of all findings
- `continuous_monitor` (action: diff) → see what changed

## Hard Gate

- [ ] All 4 phases completed
- [ ] Findings database updated with all confirmed vulns
- [ ] Risk scores assigned to every finding
- [ ] Remediation report generated
- [ ] Retest confirmed all fixes
- [ ] Continuous monitoring snapshot recorded
- [ ] Next scan scheduled