---
name: cybersec-verification
description: Use when about to claim scan results, found vulnerabilities, or completed security testing - requires running actual tools and confirming output before making any success claims
---

# Cybersec Verification Before Completion

## Overview

Claiming a port is open without seeing scan output is dishonesty, not efficiency.

**Core principle:** Evidence before claims, always.

**Violating the letter of this rule is violating the spirit of this rule.**

## The Iron Law

```
NO SECURITY CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE
```

If you haven't run the tool in this message, you cannot claim the result.

## The Gate Function

```
BEFORE claiming any security finding or status:

1. IDENTIFY: What tool/runs proves this claim?
2. RUN: Execute the FULL command (fresh, complete output)
3. READ: Full output, check status codes, count findings
4. VERIFY: Does output confirm the claim?
   - If NO: State actual findings with evidence
   - If YES: State claim WITH evidence
5. ONLY THEN: Make the claim

Skip any step = lying, not verifying
```

## Security Testing Verification Table

| Claim | Requires | Not Sufficient |
|-------|----------|----------------|
| Port is open | Scan output showing port + "open" | "Should be open" |
| Vulnerability found | Tool output showing positive detection | Previous run, "looks vulnerable" |
| Hash identified | hash_analyze output with match | "Looks like MD5" |
| S3 bucket public | s3_scanner output: 200 + file listing | "Probably accessible" |
| Subdomain found | DNS resolution or crt.sh confirms | "Might exist" |
| CVE exists | cve_search output with entry | "I've seen this before" |
| Scan complete | Tool returned results (even if 0) | Tool timed out / no output |
| Exploit works | Actual exploit output (not in prod) | "Theoretically should work" |
| Remediation applied | Re-run scan shows issue resolved | "I applied the fix" |

## Red Flags - STOP

- Using "should", "probably", "seems to", "might be"
- Saying "Done!" before seeing output
- Claiming findings from memory not tools
- Trusting previous scan results without re-running
- Relying on partial output
- Thinking "just this once"
- **ANY wording implying success without having run verification**

## Rationalization Prevention

| Excuse | Reality |
|--------|---------|
| "Port 443 should be open" | RUN nmap_scan and show it |
| "I've seen this CVE before" | RUN cve_search and show it |
| "The scan worked last time" | RUN it now, fresh results |
| "I'm confident it's vulnerable" | Confidence ≠ evidence |
| "Partial output is enough" | Partial proves nothing |
| "Tool timed out, probably secure" | Timeout = unknown, not secure |
| "Trust me, I know this target" | No exceptions |

## Key Patterns

**Port scan:**
```
✅ [Run nmap_scan] [See: port 443 open] "Port 443 is open"
❌ "Should be open" / "It's a web server"
```

**Vulnerability:**
```
✅ [Run nuclei_scan] [See: critical found] "Critical CVE-2024-XXXX detected"
❌ "Looks vulnerable to Log4j"
```

**Hash cracking:**
```
✅ [Run hash_analyze] [See: bcrypt, hashcat mode 3200] "Hash is bcrypt"
❌ "Looks like bcrypt based on length"
```

**Agent delegation:**
```
✅ Agent reports success → Check tool output → Verify findings → Report actual state
❌ Trust agent report
```

## When To Apply

**ALWAYS before:**
- Claiming a port is open/closed/filtered
- Reporting a vulnerability exists
- Stating a hash type or CVE match
- Saying a scan or test is complete
- Moving to next testing phase
- Writing the final report

**Rule applies to all communication about findings.**

## The Bottom Line

**No shortcuts for verification in security testing.**

Run the tool. Read the output. THEN claim the finding.

False positives waste time. False negatives miss breaches. Either is unacceptable.
