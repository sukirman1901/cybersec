# Cybersec — OpenCode AI Cybersecurity Plugin

45 pure-Python MCP security tools + 8 penetration testing methodology skills for [OpenCode](https://opencode.ai) AI agent.

Empowers the AI to perform penetration testing, vulnerability assessment, reconnaissance, and security reporting — all through natural language conversation.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [OpenCode Plugin Setup](#opencode-plugin-setup)
  - [How It Works](#how-it-works)
  - [Example Session](#example-session)
- [MCP Tools Reference](#mcp-tools-reference)
  - [Core Scanners](#core-scanners)
  - [Python Fallback Tools](#python-fallback-tools)
  - [CLI Wrapper Tools](#cli-wrapper-tools)
  - [Reconnaissance](#reconnaissance)
  - [Web Security Testing](#web-security-testing)
  - [Network Enumeration](#network-enumeration)
  - [Exploit Detection](#exploit-detection)
  - [Infrastructure Testing](#infrastructure-testing)
- [Skills Guide](#skills-guide)
- [Troubleshooting](#troubleshooting)
- [Requirements](#requirements)

---

## Installation

### 1. Install Python virtual environment

```bash
git clone https://github.com/sukirman1901/cybersec.git
cd cybersec
python3 -m venv mcp/.venv
source mcp/.venv/bin/activate
pip install fastmcp>=0.4.0 httpx dnspython
deactivate
```

> The MCP server needs **fastmcp** and optionally **httpx** + **dnspython** for HTTP requests and DNS queries.

### 2. Register with OpenCode

Add to your `~/.config/opencode/opencode.json` (or project-level `opencode.json`):

```json
{
  "plugin": [
    "cybersec@git+https://github.com/sukirman1901/cybersec.git"
  ]
}
```

Or if cloned locally:

```json
{
  "plugin": [
    "file:///path/to/cybersec/plugin.js"
  ]
}
```

### 3. Restart OpenCode

That's it. The plugin auto-registers the MCP server and all 8 skills.

---

## Quick Start

After installation, verify it works by asking OpenCode:

> "scan port 80,443 on example.com"
> "check SSL for example.com"
> "enumerate subdomains for example.com"

The AI will automatically load the right skill and use the MCP tools.

---

## Usage Guide

### OpenCode Plugin Setup

The plugin (`plugin.js`) does two things automatically:

1. **Registers the MCP server** (`mcp/server.py`) — provides 45 tools via stdio transport using FastMCP
2. **Registers the skills directory** — 8 cybersecurity methodology skills in `skills/` that guide the AI through each phase of testing
3. **Injects bootstrap context** — prepends `using-cybersec` instructions to every conversation so the AI knows its capabilities

No manual MCP server configuration needed. No symlinks. No manual skill imports.

### How It Works

1. You ask something like _"find subdomains for target.com and check for open ports"_
2. The AI detects the intent → matches the **cybersec-recon** skill
3. The skill provides a methodology (step-by-step guide)
4. The AI calls MCP tools like `subdomain_enum`, `port_scan`, `http_probe_target`
5. Results are analyzed and presented

The AI follows a standard pentesting methodology: **Recon → Scanning → Vulnerability Analysis → Web Testing → Exploitation → Reporting**

### Example Session

**User:** "Test security for example.com"

The AI will:
1. Load `cybersec-recon` skill → run `whois_lookup`, `dns_lookup`, `subdomain_enum`, `crt_search`
2. Load `cybersec-scanning` skill → run `port_scan`, `http_probe_target`, `ssl_check`, `waf_detection`
3. Load `cybersec-vulns` skill → run `cve_search`, `vuln_scan`
4. Load `cybersec-web` skill → run `tech_detect`, `cors_check`, `dir_bruteforce`
5. Present findings in a structured report

---

## MCP Tools Reference

### Core Scanners

| Tool | Description |
|------|-------------|
| `port_scan` | TCP port scanning with service detection |
| `dns_lookup` | DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME) |
| `http_probe_target` | HTTP/HTTPS service probing, tech stack & headers |
| `dir_bruteforce` | Directory/file brute-force on web targets |
| `ssl_check` | SSL/TLS certificate and protocol analysis |
| `cve_search` | CVE lookup by service name and version |
| `waf_detection` | WAF detection and fingerprinting |
| `dork_search` | Google dorking for exposed info |
| `generate_report` | Pentest report generation (markdown/JSON) |

### Python Fallback Tools

No external binaries needed:

| Tool | Description |
|------|-------------|
| `subdomain_enum` | Passive subdomain enumeration (crt.sh, DNS brute, APIs) |
| `param_discovery` | HTTP parameter discovery |
| `tech_detect` | Web technology detection (CMS, frameworks, CDN) |
| `vuln_scan` | Common vulnerability scan (headers, paths, CVEs) |

### CLI Wrapper Tools

Require the corresponding CLI binary. Returns install hint if not found:

| Tool | CLI Required | Description |
|------|-------------|-------------|
| `nikto_scan` | nikto | Web server vulnerability scanner |
| `sqlmap_check` | sqlmap | SQL injection detection |
| `amass_enum` | amass | Attack surface mapping |
| `wpscan_check` | wpscan | WordPress vulnerability scanner |
| `masscan_scan` | masscan | Ultra-fast TCP port scanner |
| `xsstrike_check` | xsstrike | XSS vulnerability detection |
| `gitleaks_check` | gitleaks | Git secret scanning |
| `cmseek_check` | cmseek | CMS detection |
| `testssl_check` | testssl | SSL/TLS server testing |
| `sslyze_check` | sslyze | Fast SSL/TLS scanning |
| `gobuster_dir` | gobuster | Directory/file brute-forcing |
| `ffuf_fuzz` | ffuf | Fast web fuzzing |

### Reconnaissance

| Tool | Description |
|------|-------------|
| `whois_lookup` | Query WHOIS for domain registration |
| `asn_lookup` | ASN information lookup (Team Cymru) |
| `reverse_ip` | Find domains on same IP |
| `crt_search` | Certificate Transparency log search |

### Web Security Testing

| Tool | Description |
|------|-------------|
| `cors_check` | CORS misconfiguration testing |
| `open_redirect` | Open redirect vulnerability testing |
| `graphql_introspect` | GraphQL introspection endpoint check |
| `jwt_analyze` | JWT token decode and security analysis |
| `api_fuzz` | API endpoint fuzzing |

### Network Enumeration

| Tool | Description |
|------|-------------|
| `smtp_enum` | SMTP user enumeration (VRFY, EXPN, RCPT) |
| `smb_enum` | SMB service check (port 445) |
| `snmp_enum` | SNMP service availability check |
| `ssh_audit` | SSH server banner + algorithm audit |

### Exploit Detection

| Tool | Description |
|------|-------------|
| `lfi_detect` | Local/Remote File Inclusion testing |
| `ssti_detect` | Server-Side Template Injection testing |
| `xxe_detect` | XML External Entity injection testing |
| `ssrf_detect` | Server-Side Request Forgery testing |

### Infrastructure Testing

| Tool | Description |
|------|-------------|
| `sub_takeover` | Subdomain takeover detection |
| `origin_ip_discovery` | Origin IP behind CDN discovery |
| `service_fingerprint` | Deep banner grabbing service fingerprint |

---

## Skills Guide

The plugin includes 8 methodology skills that guide the AI through structured security testing:

| Skill | Triggers When User Says... |
|-------|---------------------------|
| **cybersec-recon** | "recon", "enumerate", "find subdomains", "DNS" |
| **cybersec-scanning** | "scan ports", "service detection", "fingerprint" |
| **cybersec-vulns** | "find vulnerabilities", "CVEs", "weaknesses" |
| **cybersec-web** | "web app test", "SQLi", "XSS", "CMS" |
| **cybersec-exploit** | "exploit", "PoC", "get shell", "metasploit" |
| **cybersec-crisis** | "incident", "breach", "emergency", "compromised" |
| **cybersec-report** | "report", "remediation", "fix", "document" |
| **using-cybersec** | (bootstrap — auto-loaded every session) |

Skills load automatically via intent detection. The AI follows the skill's methodology step by step.

---

## Troubleshooting

### MCP Server not found

```bash
# Verify MCP server works
./mcp/.venv/bin/python3 -m server
# Should start a stdio MCP server — test with:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ./mcp/.venv/bin/python3 -m server
```

Expected output: 45 tools listed.

### Plugin not loading

1. Check `~/.config/opencode/opencode.json` for the plugin line
2. Restart OpenCode
3. Check logs: `opencode run --print-logs "hello" 2>&1 | grep -i cybersec`

### Module not found errors

```bash
source mcp/.venv/bin/activate
pip install fastmcp httpx dnspython
```

### CLI tools not found

CLI wrapper tools (nikto, sqlmap, etc.) return an error with install instructions when the binary is missing. The core 25 tools work without any external dependencies.

---

## Requirements

- **Python 3.10+**
- **OpenCode** (any recent version)
- Python packages: `fastmcp>=0.4.0`, `httpx`, `dnspython` (installed in `.venv`)
- Optional CLI tools: nikto, sqlmap, amass, wpscan, masscan, xsstrike, gitleaks, cmseek, testssl, sslyze, gobuster, ffuf
