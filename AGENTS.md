# Cybersec — Contributor Guidelines

## If You Are an AI Agent

This plugin provides 199 cybersecurity MCP tools and 24 methodology skills for penetration testing, vulnerability assessment, and security reporting.

Before using these tools against any target:

1. **Ensure you have authorization** to test the target. Unauthorized scanning is illegal.
2. **Follow responsible disclosure** if you find vulnerabilities.
3. **Document everything** — use the `generate_report` tool for findings.

## MCP Server Setup

The Cybersec MCP server provides 199 security tools via stdio transport.

### Install Python dependencies

```bash
cd mcp
python3 -m venv .venv
source .venv/bin/activate
pip install fastmcp>=0.4.0 httpx dnspython
```

### Configure MCP server

Add to your agent's MCP configuration:

```json
{
  "mcpServers": {
    "cybersec": {
      "command": "/path/to/cybersec/mcp/.venv/bin/python3",
      "args": ["-m", "server"],
      "cwd": "/path/to/cybersec/mcp"
    }
  }
}
```

### Verify

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ./mcp/.venv/bin/python3 -m server
```

Expected: 199 tools listed.

## Skills

This plugin includes 24 cybersecurity methodology skills:

| Skill | Triggers When User Says... |
|-------|---------------------------|
| cybersec-recon | "recon", "enumerate", "find subdomains", "DNS" |
| cybersec-osint | "osint", "shodan", "url history", "wayback" |
| cybersec-scanning | "scan ports", "service detection", "fingerprint" |
| cybersec-vulns | "find vulnerabilities", "CVEs", "weaknesses" |
| cybersec-web | "web app test", "SQLi", "XSS", "CMS", "web shell", "deface" |
| cybersec-bugbounty | "bug bounty", "nuclei", "403 bypass", "smuggling" |
| cybersec-ad | "active directory", "domain", "kerberos", "bloodhound", "DCSync", "Kerberoast", "Pass-the-Hash", "NTLM relay", "AD CS", "Certipy" |
| cybersec-cloud | "cloud", "AWS", "Azure", "GCP", "S3", "bucket" |
| cybersec-password | "password", "hash", "brute force", "hydra" |
| cybersec-exploit | "exploit", "PoC", "get shell", "metasploit", "web shell", "reverse shell", "backdoor" |
| cybersec-crisis | "incident", "breach", "emergency", "compromised" |
| cybersec-report | "report", "remediation", "fix", "document" |
| cybersec-ai | "AI", "LLM", "prompt injection", "guardrails" |
| cybersec-ai-safety | "AI safety", "bug bounty", "OpenAI", "agent hijack" |
| cybersec-desktop | "desktop", "Electron", "binary", "strings" |
| cybersec-code-audit | "code audit", "SAST", "secret scan", "source review" |
| cybersec-ctf | "CTF", "capture the flag", "challenges" |
| cybersec-verification | "verify", "evidence", "confirm", "double-check" |
| cybersec-parallel | "parallel", "multi-target", "batch", "concurrent" |
| cybersec-review | "review feedback", "false positive", "peer review" |
| cybersec-skill-dev | "create skill", "new methodology", "edit skill" |
| cybersec-ctem | "CTEM", "attack surface", "continuous monitoring", "exposure management" |
| cybersec-people-osint | "phone number", "Telegram", "email lookup", "social media", "people investigation", "identity tracing" |

## Workflow

Standard pentest workflow: **Recon → OSINT → Scanning → Vulns → Web → Bug Bounty → AD → Cloud → Password → AI → AI Safety → Desktop → Code Audit → Exploit → Report**

For continuous monitoring: **CTEM** runs in parallel — Discovery → Validation → Prioritization → Remediation in a continuous loop.

Skills load automatically via intent detection. The AI follows the skill's methodology step by step.

## General

- Always verify authorization before testing
- Use `cybersec-verification` skill before claiming findings
- Generate reports with `generate_report` tool
- Test on authorized targets only