---
name: cybersec-ai
description: AI/LLM security testing methodology — prompt injection, guardrails, model DoS, data exposure, agent hijack
---

<HARD-GATE>
You MUST load this skill using the `skill` tool before any AI/LLM security testing.
Create a TodoWrite item for each step below. Do NOT skip steps.
</HARD-GATE>

## AI/LLM Testing Methodology

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
- Use `report` to generate findings with OWASP AI Top 10 mapping
- Include evidence (prompts, responses) and remediation per finding
- Transition to `cybersec-report` for final documentation

## Tools
- `prompt_injection`, `llm_guardrails`, `llm_model_dos`, `llm_data_exposure`, `llm_agent_hijack`
