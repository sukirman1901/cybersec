---
name: cybersec-review
description: Use when receiving peer review of security findings, tool outputs, or testing methodology - requires technical verification, not performative agreement
---

# Security Review Reception

## Overview

Security review requires technical verification, not agreement theater.

**Core principle:** Verify findings before reporting. Question assumptions. False positives waste time, false negatives miss breaches.

## The Response Pattern

```
WHEN receiving review of security findings:

1. READ: Complete feedback without reacting
2. UNDERSTAND: Restate the finding/concern
3. VERIFY: Re-run the tool or check the output
4. EVALUATE: Is this a real finding or false positive?
5. RESPOND: Technical acknowledgment or reasoned pushback
6. IMPLEMENT: Fix methodology, re-scan, or document limitation
```

## Forbidden Responses

**NEVER:**
- "You're right, it's vulnerable!" (without re-running tool)
- "Good catch!" (performative — re-run the scan instead)
- "Let me report that now" (before verification)

**INSTEAD:**
- Restate the technical finding
- Re-run the tool to confirm
- Push back with evidence if false positive
- Just re-scan and show the actual output

## Handling Unclear Findings

```
IF any finding is unclear:
  STOP - do not report anything yet
  RE-RUN the tool with more parameters
  ASK: "Finding on port X is ambiguous. Output shows Y. Should I investigate further?"

WHY: Reporting unverified findings pollutes the report.
```

**Example:**
```
Reviewer: "Port 8080 looks vulnerable to path traversal"
You: Re-run lfi_detect on port 8080
Output: No LFI detected (all requests returned 403)
✅ "Re-ran lfi_detect on 8080 — all requests returned 403. False positive. Marking as tested."
❌ "You're right! Let me add that to the report."
```

## Source-Specific Handling

### From Peer Security Team
- **Verify independently** — don't trust their output, re-run yourself
- **Still question** if methodology is sound
- **No performative agreement**
- **Share counter-evidence** if finding differs

### From Automated Tools (nuclei, nikto)
```
BEFORE reporting:
  1. Check: Is the template accurate for this target?
  2. Verify: Re-run with --validate or manual check
  3. Check: False positive rate for this template
  4. Document: Confidence level based on verification

IF medium/low confidence:
  Manual verification required before reporting
```

### From AI Agent / Previous Session
```
ALWAYS re-verify previous session findings:
  1. Result may be stale (target changed)
  2. Tool may have false positive
  3. Context may be different now
  4. Never trust "we found this before"
```

## False Positive Verification

```
FOR EACH finding before reporting:

1. RE-RUN the tool (fresh output)
2. CHECK output for false positive indicators:
   - Is the response what we expect for a real vuln?
   - Could WAF/firewall be causing false reading?
   - Is this a known false positive template?
3. MANUAL VERIFY if possible (curl, browser)
4. ASSIGN confidence: high / medium / low
5. DOCUMENT: "Confirmed via [tool] on [date]: [output summary]"
```

**Examples:**

```
nuclei found "Apache Tomcat CVE-2020-1938"
✅ Verified: Ran again with -validate, got same result.
   Manual: curl http://target:8009/ — AJP responder confirmed
   Confidence: HIGH

nikto found "Server leaks inodes via ETags"
❌ RE-RAN: Same warning, but this is informational, not exploitable.
   Confidence: LOW — Informational only, no impact

Recon report says "target uses Cloudflare"
✅ Verified: ssl_check shows CF headers + dns_lookup shows CF IPs
   Confidence: HIGH
```

## YAGNI for Security Testing

```
IF reviewer suggests testing additional targets:
  Check scope:
    ✅ In scope: Proceed with testing
    ❌ Out of scope: "This target is out of scope per engagement boundary"

IF reviewer suggests additional tools:
  Check tool availability:
    ✅ Available as MCP tool: Run it
    ❌ CLI only: "Requires [tool] CLI which isn't installed. Should we install it?"

IF reviewer suggests deep-dive on low-priority finding:
  Check severity:
    ✅ Critical/High: Investigate further
    ❌ Info/Low: "This is informational. Current remaining critical items: [list]. Prioritize?"
```

## Implementation Order for Multi-Finding Review

```
FOR multi-finding feedback:
  1. Clarify ambiguous findings FIRST
  2. Then re-verify in this order:
     - Critical/High severity (actual risk)
     - Medium severity
     - Low/Info (likely false positives)
  3. Document confidence for each
  4. Re-scan any fixed/mitigated issues
```

## When To Push Back

Push back when:
- Finding is a known false positive for the tool/template
- Reviewer didn't consider WAF/CDN interference
- Finding requires out-of-scope access
- Methodology issue (scanning wrong port/protocol)
- Result is stale (target has changed)
- Report inflates low-severity issue

**How to push back:**
```
✅ "Re-ran [tool] on [target]. Output shows [X]. This is a known false positive for this template because [reason]. Not reporting."
✅ "Verified [finding] — it's informational only. Tool flags this on every Apache install. Marking as informational with no impact."
❌ "I disagree" (needs evidence)
```

## Acknowledging Correct Findings

When finding IS correct:
```
✅ "Re-ran and confirmed. [Specific vuln] on [port/service]. Adding to report."
✅ "Verified — this is a real issue. [Tool] output shows [evidence]. Filing as [severity]."
✅ [Re-run tool, show output, add to report — no words needed]
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Reporting without re-running | Re-run tool, show fresh output |
| Trusting automated tool blindly | Manual verify critical findings |
| Inflating severity | Match severity to real impact |
| Ignoring false positive patterns | Document known FPs for future |
| Reporting out-of-scope findings | Check scope boundaries first |
| Assuming previous results still valid | Re-scan everything fresh |

## The Bottom Line

**Security findings are hypotheses until verified.**

Re-run the tool. Show the output. THEN report.

False positives waste remediation time. False negatives leave vulnerabilities open. Verify everything.
