---
name: cybersec-verification
description: Use when about to claim scan results, found vulnerabilities, or completed security testing - run tools and show output before making claims
---

# Cybersec Verification

## Principle

Run the tool. Show the output. Then state the finding.

## How To Verify

```
BEFORE claiming any security finding:

1. RUN: Execute the tool (fresh output)
2. READ: Check status codes, count findings
3. REPORT: State findings WITH the output as evidence
```

## Verification Table

| Claim | How to verify |
|-------|---------------|
| Port is open | `port_scan` output showing "open" |
| Vulnerability found | `vuln_scan` or `nuclei_scan` output |
| Hash identified | `hash_analyze` output |
| S3 bucket public | `s3_scanner` output: 200 + listing |
| Subdomain found | DNS resolution or `crt_search` confirms |
| CVE exists | `cve_search` output |
| Exploit works | Actual exploit output |
| Fix applied | Re-run scan shows issue resolved |

## Quick Examples

**Port scan:**
```
[port_scan] → port 443 open → "Port 443 is open"
```

**Vulnerability:**
```
[nuclei_scan] → critical CVE-2024-XXXX → "Critical CVE detected"
```

**Hash:**
```
[hash_analyze] → bcrypt, mode 3200 → "Hash is bcrypt"
```

## When To Apply

Before reporting findings, moving to next phase, or writing final report.
