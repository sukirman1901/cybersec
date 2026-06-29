---
name: cybersec-ai-safety
description: AI Safety Bug Bounty methodology — OpenAI Safety BB scope covering prompt injection, agent hijack, MCP abuse, data exfiltration, anti-automation
---

## AI Safety Bug Bounty Methodology

Scope covers OpenAI Safety BB + general AI safety scenarios.

### 1. Prompt Injection & Agent Hijack
- Test third-party prompt injection via `prompt_injection` — system prompt extraction, instruction override
- Test agent hijack via `llm_agent_hijack` — function call injection, tool misuse
- Test browser agent hijack via `browser_agent_hijack` — web content injection, hidden fields, autofill steal
- Verify reproducibility >= 50% (per OpenAI BB rules)
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
- Test rate limiting — mass requests without throttling
- Test account trust signal manipulation, suspension evasion
- Document: bypass method, success rate, impact scale

### 5. Platform Integrity
- Test authentication bypass via `jwt_forgery`, `oauth_scan`, `api_auth`
- Test privilege escalation via `bypass_403`, `idor_detect`
- Test session manipulation, authorization gaps
- Document: vulnerable endpoint, impact, reproduction steps

### 6. Reporting
- Each finding must include: clear reproduction steps, impact assessment, recommended mitigations
- Rewards up to $7,500 for high severity with clear fixes
- Use `report` to generate structured findings
- Transition to `cybersec-report` for final submission

## Tools
- `prompt_injection`, `llm_agent_hijack`, `browser_agent_hijack`, `mcp_abuse_test`
- `llm_data_exposure`, `llm_guardrails`, `llm_model_dos`
- `captcha_test`, `jwt_forgery`, `oauth_scan`, `api_auth`
- `bypass_403`, `idor_detect`, `misplaced_files`
