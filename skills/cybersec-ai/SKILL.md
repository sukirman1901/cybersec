---
name: cybersec-ai
description: AI/LLM security testing methodology — prompt injection, guardrails, model DoS, data exposure, agent hijack
---

## AI/LLM Testing Methodology

Select relevant tests for the specified endpoint/model, not all categories.
Offline prompt review needs no engagement. Before active target probes require
`engagement_gate` `init` + `authorize`; confirmed `extend` is only for additional
user-approved resources, never discovered tools/services. Stop blocked branches,
record coverage and redact secrets/PII from prompts and responses. Use synthetic
canaries and test accounts; DoS needs explicit load approval, request/token/cost
limits and cancellation criteria, not automatic context escalation. Suspected
memorization is not proof of training provenance or private-data extraction.

### 1. Reconnaissance
- Identify LLM endpoint, API version, model name
- Document accepted input format, auth method, rate limits
- Use `prompt_injection` to test basic prompt leak

### 2. Injection Testing
- Test system prompt extraction via `prompt_injection` with multiple payloads
- Test output sanitization via `llm_guardrails` (XSS, markdown injection)
- Document all injection points (system, user, context, tool descriptions)

### 3. Denial of Service
- Test model stability via `llm_model_dos` with escalating context size
- Document rate limits, context window limits, crash behavior

### 4. Data Exposure
- Test training data leakage via `llm_data_exposure` with PII extraction prompts
- Check for memorized content, verbatim training data reproduction

### 5. Agent Hijack
- Test function call injection via `llm_agent_hijack`
- Check tool misuse, data exfiltration, privilege escalation
- Verify agent routing and safety boundaries

### 6. Reporting
- Use `generate_report` to generate findings with OWASP AI Top 10 mapping
- Include evidence (prompts, responses) and remediation per finding
- Transition to `cybersec-report` for final documentation

## Tools
- `prompt_injection`, `llm_guardrails`, `llm_model_dos`, `llm_data_exposure`, `llm_agent_hijack`
