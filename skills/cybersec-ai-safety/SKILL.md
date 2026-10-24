---
name: cybersec-ai-safety
description: AI Safety Bug Bounty methodology — OpenAI Safety BB scope covering prompt injection, agent hijack, MCP abuse, data exfiltration, anti-automation
---

## AI Safety Bug Bounty Methodology

Use only the relevant category allowed by the program's current published scope;
this skill does not establish eligibility, reward amounts or permission. Before
active target probes require `engagement_gate` `init` + `authorize`; confirmed
`extend` is only for additional user-approved resources, not discovered endpoints.
Offline review needs no engagement. Bound requests, cost and accounts; stop on
denial, throttling or unintended effects. Record coverage and redact secrets/PII.
Use synthetic canaries, not real victim data. CAPTCHA bypass, load, account trust
manipulation and platform-integrity checks are separate opt-in branches, never
automatic consequences of a prompt-injection result.

### 1. Prompt Injection & Agent Hijack
- Test third-party prompt injection via `prompt_injection` — system prompt extraction, instruction override
- Test agent hijack via `llm_agent_hijack` — function call injection, tool misuse
- Test browser agent hijack via `browser_agent_hijack` — web content injection, hidden fields, autofill steal
- Measure reproducibility with trial count, model/version and conditions; verify current program requirements separately
- Document: injection vector, success rate, exfiltrated data

### 2. Data Exfiltration
- Test training data leakage via `llm_data_exposure` — PII extraction, proprietary info leak
- Test reasoning chain leakage — model returning proprietary reasoning
- Test context leakage via prompt injection payloads
- Document: leaked data type, extraction prompt, response evidence

### 3. MCP Abuse
- Test MCP server via `mcp_abuse_test` — method enumeration, dangerous tool discovery, JSON-RPC injection
- Check for exposed shell/file/network tools that allow arbitrary actions
- Test tool description prompt injection (agent confusion via tool names)
- Document: exposed methods, dangerous tools, injection vectors

### 4. Anti-Automation & Account Integrity
- Test CAPTCHA bypass via `captcha_test` — token reuse, empty values, param removal
- Test rate limiting only within the approved request budget and stop on throttling
- Review account trust signals using authorized test accounts; no suspension evasion
- Document: bypass method, success rate, impact scale

### 5. Platform Integrity
- Test authentication bypass via `jwt_forgery`, `oauth_scan`, `api_auth`
- Test privilege escalation via `bypass_403`, `idor_detect`
- Test session manipulation, authorization gaps
- Document: vulnerable endpoint, impact, reproduction steps

### 6. Reporting
- Each finding must include: clear reproduction steps, impact assessment, recommended mitigations
- Check current program eligibility and disclosure terms; do not promise rewards
- Use `generate_report` to generate structured findings
- Transition to `cybersec-report` for final submission

## Tools
- `prompt_injection`, `llm_agent_hijack`, `browser_agent_hijack`, `mcp_abuse_test`
- `llm_data_exposure`, `llm_guardrails`, `llm_model_dos`
- `captcha_test`, `jwt_forgery`, `oauth_scan`, `api_auth`
- `bypass_403`, `idor_detect`, `misplaced_files`
