---
name: cybersec-code-audit
description: Code security audit methodology — SAST, secret scanning, manual review patterns
---

## Code Security Audit Methodology

For source-only requests, use the supplied repository path/files and no remote
probes. Select relevant languages/tools; inspect the live schema for path/code
inputs instead of substituting a URL. Before separately requested active target
probes require `engagement_gate` `init` + `authorize`; confirmed `extend` only for
additional user-approved resources, not URLs found in source. Record coverage and
missing dependencies; redact secrets in file:line evidence, never validate leaked
credentials against services. No clean verdict from pattern scans alone.

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
- Trace Python pickle deserialization from untrusted input to sink in supplied source; `pickle_deserialize` is a remote test and is not part of source-only review
- Review file upload handling, input validation

### 4. Dependency Audit
- Check exposed dependency files (package.json, requirements.txt, go.mod)
- Look for known vulnerable versions, supply chain risks
- Review local manifests/lockfiles with offline dependency tools; use `supply_chain` only if its live schema supports the requested input (its target mode is remote)

### 5. CI/CD Pipeline Audit
- Review supplied CI/CD config files (GitHub Actions, GitLab CI, Jenkins, CircleCI) locally; `ci_cd_scan(target)` checks remote endpoints and is not a source-only tool
- Look for secrets exposure, insecure environment injection, privileged runners

### 6. Reporting
- Prioritize findings by severity (CRITICAL → INFO)
- Include exact file:line references, code snippets
- Suggest remediation per finding
- Transition to `cybersec-report`

## Tools
- `secret_scanner`, `sast_review`, `bandit_scan`, `semgrep_scan`, `supply_chain`, `exposed_git`, `pickle_deserialize`, `ci_cd_scan`
