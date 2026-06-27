# Cybersec Phase 3: Fill Coverage Gaps

**Date:** 2026-06-28

## Objective

Fill 5 remaining security testing domains to achieve full coverage:
AI/LLM, iOS Mobile, Desktop App, Code Security Audit, and deepened Cloud testing.

## Approach

Hybrid: Pure Python for domains without mature CLI tooling (AI/LLM, Desktop),
CLI wrapper for domains with pip-installable standards (iOS, SAST, Cloud).

## Tools (21 total)

### AI & LLM Testing (5) — Pure Python / httpx

| Tool | Description | Approach |
|------|-------------|---------|
| `prompt_injection` | Test prompt leak / token manipulation via API | httpx to LLM endpoint, detect system prompt extraction |
| `llm_guardrails` | Check if LLM output is sanitized (XSS, markdown) | Analyze response for unescaped HTML/JS |
| `llm_model_dos` | Test excessive token consumption | Send expanding context, detect crash/rate-limit |
| `llm_data_exposure` | Check for training data leakage (PII, memorized) | Craft extraction prompts, check for verbatim data |
| `llm_agent_hijack` | Test function call / tool misuse injection | Inject malicious tool descriptions, test agent routing |

### iOS Mobile (5) — Static: Pure Python, Dynamic: CLI

| Tool | Description | Approach |
|------|-------------|---------|
| `ipa_analyze` | IPA metadata, entitlements, plist, permissions | Pure Python zipfile + plistlib |
| `ios_data_storage` | Check NSUserDefaults, CoreData, encryption flags | Pure Python plist inspection |
| `ios_objection` | Runtime inspection, keychain dump | CLI wrapper (objection) |
| `ios_frida` | SSL pinning bypass detection, method tracing | CLI wrapper (frida) |
| `ios_signing` | Check app signing, provisioning profile, team ID | Pure Python (codesign parse) |

### Desktop App (5) — Pure Python (static analysis)

| Tool | Description | Approach |
|------|-------------|---------|
| `desktop_strings` | Extract strings from PE/ELF/Mach-O, find secrets | Binary string extraction + regex patterns |
| `desktop_electron` | Unpack ASAR, inspect preload, check IPC safety | ASAR extraction + JS AST analysis |
| `desktop_config` | Scan for saved creds, .env, insecure permissions | File walking + entropy check |
| `desktop_packages` | Check bundled package versions for known vulns | Package manifest parse + CVE lookup |
| `desktop_entitlements` | macOS entitlements, Windows manifest, Linux caps | XML/plist parsing |

### Code Security Audit (4) — Pure Python + pip-installable wrappers

| Tool | Description | Approach |
|------|-------------|---------|
| `secret_scanner` | Regex + entropy secret detection | Pure Python (pattern + Shannon entropy) |
| `sast_review` | Pattern-based code review (eval, exec, serialize) | Pure Python AST parsing |
| `bandit_scan` | Python SAST scanner | CLI wrapper (pip package) |
| `semgrep_scan` | Multi-language SAST | CLI wrapper (pip package) |

### Cloud Deepen (2) — CLI wrappers (pip-installable)

| Tool | Description | Approach |
|------|-------------|---------|
| `cloud_iam_audit` | IAM policy analysis: overly permissive, public | CLI wrapper (prowler/pipal) |
| `cloud_infra` | Service config audit: open security groups, unencrypted storage | CLI wrapper (scoutsuite) |

## Registration

All 21 tools registered in `mcp/server.py` with wrapper pattern:
```python
@mcp.tool()
def prompt_injection(target: str, prompt: str = "") -> str:
    return json.dumps(_run(_prompt_injection(target, prompt)), indent=2)
```

## Skills Needed

- `cybersec-ai` — methodology for AI/LLM security testing
- `cybersec-desktop` — methodology for desktop app assessment
- `cybersec-code-audit` — methodology for source code review

## Total After Phase 3

- **111 MCP tools** (90 + 21)
- **20 skills** (17 + 3)
- Full coverage of all 8 domains listed in requirements
