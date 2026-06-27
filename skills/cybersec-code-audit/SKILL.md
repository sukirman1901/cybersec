---
name: cybersec-code-audit
description: Code security audit methodology — SAST, secret scanning, manual review patterns
---

<HARD-GATE>
You MUST load this skill using the `skill` tool before any source code security review.
Create a TodoWrite item for each step below. Do NOT skip steps.
</HARD-GATE>

## Code Security Audit Methodology

### 1. Secret Discovery
- Run `secret_scanner` with regex + entropy detection across repository
- Focus: API keys, passwords, tokens, private keys, database URLs
- Verify each finding — regex can produce false positives

### 2. Static Analysis (SAST)
- Run `sast_review` for pattern-based dangerous function detection
- Run `bandit_scan` on Python files for CWE-level findings
- Run `semgrep_scan` with auto rules for multi-language coverage

### 3. Manual Review Patterns
- Check for injection vectors (SQLi, NoSQL, command injection)
- Review authentication logic, session handling, authorization checks
- Look for insecure deserialization, SSRF, path traversal
- Review file upload handling, input validation

### 4. Dependency Audit
- Check exposed dependency files (package.json, requirements.txt, go.mod)
- Look for known vulnerable versions, supply chain risks
- Use `supply_chain` tool for manifest analysis

### 5. Reporting
- Prioritize findings by severity (CRITICAL → INFO)
- Include exact file:line references, code snippets
- Suggest remediation per finding
- Transition to `cybersec-report`

## Tools
- `secret_scanner`, `sast_review`, `bandit_scan`, `semgrep_scan`, `supply_chain`, `exposed_git`
