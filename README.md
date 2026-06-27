# Cybersec — AI Cybersecurity Plugin

**125+ pure-Python MCP security tools** + **22 pentesting methodology skills** for AI coding agents.

Works with: **Claude Code**, **Cursor**, **Codex**, **Gemini CLI**, **GitHub Copilot CLI**, **Kimi Code**, **OpenCode**, **Pi**.

Empowers the AI to perform penetration testing, vulnerability assessment, reconnaissance, and security reporting — all through natural language conversation.

---

## Table of Contents

- [Installation](#installation)
  - [Claude Code](#claude-code)
  - [Cursor](#cursor)
  - [Codex (App + CLI)](#codex)
  - [Gemini CLI](#gemini-cli)
  - [GitHub Copilot CLI](#github-copilot-cli)
  - [Kimi Code](#kimi-code)
  - [OpenCode](#opencode)
  - [Pi](#pi)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [MCP Server Setup](#mcp-server-setup)
- [MCP Tools Reference](#mcp-tools-reference)
- [Skills Guide](#skills-guide)
- [Troubleshooting](#troubleshooting)
- [Requirements](#requirements)

---

## Installation

Installation differs by harness. If you use more than one, install Cybersec separately for each one.

### Python Prerequisites (all platforms)

```bash
git clone https://github.com/sukirman1901/cybersec.git
cd cybersec
python3 -m venv mcp/.venv
source mcp/.venv/bin/activate
pip install fastmcp>=0.4.0 httpx dnspython
deactivate
```

> The MCP server needs **fastmcp** and optionally **httpx** + **dnspython** for HTTP requests and DNS queries.

### Claude Code

#### Official Marketplace

- Install the plugin from Anthropic's official marketplace:
  ```
  /plugin install cybersec@claude-plugins-official
  ```

#### Cybersec Marketplace

- Register the marketplace:
  ```
  /plugin marketplace add sukirman1901/cybersec
  ```
- Install the plugin:
  ```
  /plugin install cybersec@cybersec
  ```

#### Manual MCP Config

Create or edit `.mcp.json` in your project root:

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

### Cursor

- In Cursor Agent chat, install from marketplace:
  ```
  /add-plugin cybersec
  ```
- Or search for "cybersec" in the plugin marketplace.

The plugin auto-registers skills and hooks. You also need to add the MCP server to Cursor's MCP settings.

### Codex

Available via the official Codex plugin marketplace.

#### Codex App

- In the Codex app, click on **Plugins** in the sidebar.
- Search for `Cybersec` in the Security section.
- Click the `+` next to Cybersec and follow the prompts.

#### Codex CLI

- Open the plugin search interface:
  ```
  /plugins
  ```
- Search for Cybersec:
  ```
  cybersec
  ```
- Select `Install Plugin`.

### Gemini CLI

- Install the extension:
  ```bash
  gemini extensions install https://github.com/sukirman1901/cybersec
  ```
- Update later:
  ```bash
  gemini extensions update cybersec
  ```

The `GEMINI.md` file auto-loads the bootstrap context and tool mapping.

### GitHub Copilot CLI

- Register the marketplace:
  ```bash
  copilot plugin marketplace add sukirman1901/cybersec
  ```
- Install the plugin:
  ```bash
  copilot plugin install cybersec@cybersec
  ```

### Kimi Code

Available in Kimi Code's plugin marketplace.

- Open Kimi Code's plugin manager:
  ```
  /plugins
  ```
- Go to `Marketplace` > `Cybersec` and install it.

- Or install directly from this repository:
  ```
  /plugins install https://github.com/sukirman1901/cybersec
  ```

### OpenCode

OpenCode uses its own plugin install. The plugin auto-registers the MCP server and all skills — no manual MCP config needed.

- Tell OpenCode:
  ```
  Fetch and follow instructions from https://raw.githubusercontent.com/sukirman1901/cybersec/refs/heads/main/.opencode/INSTALL.md
  ```

Add to your `opencode.json`:

```json
{
  "plugin": ["cybersec@git+https://github.com/sukirman1901/cybersec.git"]
}
```

To pin a specific version:

```json
{
  "plugin": ["cybersec@git+https://github.com/sukirman1901/cybersec.git#v1.0.0"]
}
```

Restart OpenCode. The plugin auto-registers the MCP server, skills directory, and bootstrap context.

### Pi

Install Cybersec as a Pi package from this repository:

```bash
pi install git:github.com/sukirman1901/cybersec
```

For local development:

```bash
pi -e /path/to/cybersec
```

The Pi extension (`.pi/extensions/cybersec.ts`) loads skills and injects the bootstrap at session startup.

---

## Quick Start

After installation, verify it works by asking your agent:

> "scan port 80,443 on example.com"
> "check SSL for example.com"
> "enumerate subdomains for example.com"

The AI will automatically load the right skill and use the MCP tools.

---

## How It Works

1. You ask something like _"find subdomains for target.com and check for open ports"_
2. The AI detects the intent → matches the **cybersec-recon** skill
3. The skill provides a methodology (step-by-step guide)
4. The AI calls MCP tools like `subdomain_enum`, `port_scan`, `http_probe_target`
5. Results are analyzed and presented

The AI follows a standard pentesting methodology: **Recon → OSINT → Scanning → Vulnerability Analysis → Web Testing → Bug Bounty → AD → Cloud → Password → AI → AI Safety → Desktop → Code Audit → Exploitation → Reporting**

### Example Session

**User:** "Test security for example.com"

The AI will:
1. Load `cybersec-recon` skill → run `whois_lookup`, `dns_lookup`, `subdomain_enum`, `crt_search`
2. Load `cybersec-scanning` skill → run `port_scan`, `http_probe_target`, `ssl_check`, `waf_detection`
3. Load `cybersec-vulns` skill → run `cve_search`, `vuln_scan`
4. Load `cybersec-web` skill → run `tech_detect`, `cors_check`, `dir_bruteforce`, **auto-CAPTCHA detection**
5. Present findings in a structured report

---

## MCP Server Setup

The Cybersec MCP server provides 125+ security tools via stdio transport using FastMCP.

### For Non-OpenCode Platforms

On platforms that don't auto-register the MCP server (Claude Code, Cursor, Codex, Gemini, etc.), add the MCP server to your platform's MCP configuration:

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

### Verify MCP Server

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ./mcp/.venv/bin/python3 -m server
```

Expected: 125+ tools listed.

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
| `subdomain_enum` | Passive subdomain enumeration (crt.sh, DNS brute, APIs) |
| `param_discovery` | HTTP parameter discovery |
| `tech_detect` | Web technology detection (CMS, frameworks, CDN) |
| `vuln_scan` | Common vulnerability scan (headers, paths, CVEs) |
| `whois_lookup` | Query WHOIS for domain registration |
| `asn_lookup` | ASN information lookup (Team Cymru) |
| `reverse_ip` | Find domains on same IP |
| `crt_search` | Certificate Transparency log search |
| `cors_check` | CORS misconfiguration testing |
| `open_redirect` | Open redirect vulnerability testing |
| `graphql_introspect` | GraphQL introspection endpoint check |
| `jwt_analyze` | JWT token decode and security analysis |
| `api_fuzz` | API endpoint fuzzing |
| `smtp_enum` | SMTP user enumeration (VRFY, EXPN, RCPT) |
| `smb_enum` | SMB service check (port 445) |
| `snmp_enum` | SNMP service availability check |
| `ssh_audit` | SSH server banner + algorithm audit |
| `lfi_detect` | Local/Remote File Inclusion testing |
| `ssti_detect` | Server-Side Template Injection testing |
| `xxe_detect` | XML External Entity injection testing |
| `ssrf_detect` | Server-Side Request Forgery testing |
| `sub_takeover` | Subdomain takeover detection |
| `origin_ip_discovery` | Origin IP behind CDN discovery |
| `service_fingerprint` | Deep banner grabbing service fingerprint |

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
| `nuclei_scan` | nuclei | Template-based vulnerability scanner |
| `nmap_scan` | nmap | Full network scan with service detection |
| `hydra_brute` | hydra | Online password brute forcing |
| `searchsploit` | searchsploit | Search exploit-db |

### Web Vulnerability Testing

| Tool | Description |
|------|-------------|
| `sqli_detect` | SQL injection detection (error-based, time-based, UNION) |
| `xss_detect` | Active XSS injection testing |
| `cmd_injection` | Command injection testing |
| `nosql_inject` | NoSQL injection testing |
| `csrf_detect` | CSRF token validation |
| `idor_detect` | Insecure Direct Object Reference testing |
| `upload_bypass` | File upload filter bypass |
| `host_header_injection` | Host header injection testing |
| `race_condition` | Race condition testing |
| `prototype_pollution` | Prototype pollution testing |
| `smuggling_check` | HTTP request smuggling |
| `bypass_403` | 403 bypass techniques |
| `log4j_scan` | Log4j JNDI injection |
| `graphql_injection` | GraphQL injection testing |
| `jwt_forgery` | JWT forgery testing |
| `cookie_audit` | Cookie security audit |
| `cookie_editor` | Cookie manipulation and forging |
| `csp_analyze` | Content-Security-Policy analysis |
| `websocket_test` | WebSocket endpoint testing |

### CMS & Framework Scanners

| Tool | Description |
|------|-------------|
| `wordpress_scan` | WordPress security scan |
| `joomla_scan` | Joomla CMS scanner |
| `drupal_scan` | Drupal security scan |
| `magento_scan` | Magento security scan |
| `laravel_scan` | Laravel app scan |
| `nextjs_scan` | Next.js security scan |
| `django_scan` | Django security scan |
| `rails_scan` | Ruby on Rails scan |
| `express_scan` | Express.js scan |
| `spring_scan` | Spring Boot actuator scan |
| `sharepoint_scan` | SharePoint scanner |

### Deserialization & Injection

| Tool | Description |
|------|-------------|
| `php_deserialize` | PHP deserialization testing |
| `java_deserialize` | Java deserialization testing |

### Exploit-DB & GHDB

| Tool | Description |
|------|-------------|
| `exploit_db_search` | Search Exploit-DB for CVEs, types, platforms |
| `exploit_db_detail` | Get Exploit-DB exploit details with code |
| `exploit_db_download` | Download exploit code from Exploit-DB |
| `ghdb_search` | Search Google Hacking Database |

### Reconnaissance & OSINT

| Tool | Description |
|------|-------------|
| `shodan_lookup` | Shodan search for exposed devices |
| `wayback_urls` | Wayback Machine URL history |
| `vhost_discovery` | Virtual host discovery |
| `amass_enum` | Attack surface mapping |
| `oob_test` | Blind OOB interaction test |

### Active Directory

| Tool | Description |
|------|-------------|
| `bloodhound_collect` | Collect AD data for BloodHound |
| `ldap_enum` | LDAP anonymous bind enumeration |

### Cloud Security

| Tool | Description |
|------|-------------|
| `cloud_enum` | Enumerate cloud storage (S3, Azure, GCP) |
| `s3_scanner` | Check S3 bucket public access |
| `cloud_iam_audit` | Audit cloud IAM policies |
| `cloud_infra` | Enumerate cloud infra config |
| `k8s_scan` | Kubernetes API scan |
| `docker_scan` | Docker socket exposure scan |

### Code Audit

| Tool | Description |
|------|-------------|
| `bandit_scan` | Python bandit SAST scanner |
| `semgrep_scan` | Semgrep multi-language SAST |
| `sast_review` | Pattern-based code review |
| `secret_scanner` | Regex + entropy secret scanning |
| `gitleaks_check` | Git secret scanning |
| `ci_cd_scan` | CI/CD config scan |
| `supply_chain` | Dependency vulnerability check |

### AI & LLM Security

| Tool | Description |
|------|-------------|
| `prompt_injection` | LLM prompt injection testing |
| `llm_guardrails` | LLM safety guardrails check |
| `llm_model_dos` | LLM DoS via token generation |
| `llm_data_exposure` | LLM training data leakage test |
| `llm_agent_hijack` | LLM agent function call injection |
| `mcp_abuse_test` | MCP server abuse testing |
| `browser_agent_hijack` | Browser AI agent hijack test |
| `captcha_test` | CAPTCHA bypass testing |

### Mobile & Desktop

| Tool | Description |
|------|-------------|
| `apk_analyze` | Android APK analysis |
| `ipa_analyze` | iOS IPA analysis |
| `ios_data_storage` | iOS local data storage check |
| `ios_frida` | Frida iOS runtime analysis |
| `ios_objection` | Objection iOS exploration |
| `ios_signing` | iOS app signing check |
| `desktop_electron` | Electron app analysis |
| `desktop_entitlements` | Desktop entitlements check |
| `desktop_config` | Desktop config file scan |
| `desktop_packages` | Desktop package CVE check |
| `desktop_strings` | Desktop binary string extraction |
| `binary_checksec` | Binary security analysis |
| `stego_detect` | Steganography detection |

### Other Tools

| Tool | Description |
|------|-------------|
| `hash_analyze` | Hash type identification |
| `hash_detect` | Hash type detection (20+ types) |
| `redis_enum` | Redis server enumeration |
| `metrics_check` | Exposed metrics endpoint check |
| `log_exposure` | Exposed log file scan |
| `exposed_git` | Exposed .git folder check |
| `exposed_backup` | Exposed backup file scan |
| `misplaced_files` | Misplaced sensitive file scan |
| `oauth_scan` | OAuth/OIDC endpoint scan |
| `ssl_pinning_check` | SSL pinning behavior check |
| `oob_test` | OOB blind interaction test |

---

## Skills Guide

The plugin includes **22** methodology skills that guide the AI through structured security testing:

| Skill | Triggers When User Says... |
|-------|---------------------------|
| **cybersec-recon** | "recon", "enumerate", "find subdomains", "DNS" |
| **cybersec-osint** | "osint", "shodan", "url history", "wayback" |
| **cybersec-scanning** | "scan ports", "service detection", "fingerprint" |
| **cybersec-vulns** | "find vulnerabilities", "CVEs", "weaknesses" |
| **cybersec-web** | "web app test", "SQLi", "XSS", "CMS" |
| **cybersec-bugbounty** | "bug bounty", "nuclei", "403 bypass", "smuggling" |
| **cybersec-ad** | "active directory", "domain", "kerberos", "bloodhound" |
| **cybersec-cloud** | "cloud", "AWS", "Azure", "GCP", "S3", "bucket" |
| **cybersec-password** | "password", "hash", "brute force", "hydra" |
| **cybersec-exploit** | "exploit", "PoC", "get shell", "metasploit" |
| **cybersec-crisis** | "incident", "breach", "emergency", "compromised" |
| **cybersec-report** | "report", "remediation", "fix", "document" |
| **cybersec-ai** | "AI", "LLM", "prompt injection", "guardrails" |
| **cybersec-ai-safety** | "AI safety", "bug bounty", "OpenAI", "agent hijack" |
| **cybersec-desktop** | "desktop", "Electron", "binary", "strings" |
| **cybersec-code-audit** | "code audit", "SAST", "secret scan", "source review" |
| **cybersec-ctf** | "CTF", "capture the flag", "challenges" |
| **cybersec-verification** | "verify", "evidence", "confirm", "double-check" |
| **cybersec-parallel** | "parallel", "multi-target", "batch", "concurrent" |
| **cybersec-review** | "review feedback", "false positive", "peer review" |
| **cybersec-skill-dev** | "create skill", "new methodology", "edit skill" |
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

Expected output: 125+ tools listed.

### OpenCode plugin not loading

1. Check `~/.config/opencode/opencode.json` for the plugin line
2. Restart OpenCode
3. Check logs: `opencode run --print-logs "hello" 2>&1 | grep -i cybersec`

### Claude Code plugin not loading

1. Check `.mcp.json` MCP server config
2. Restart Claude Code
3. Verify: `/plugin list` should show cybersec

### Module not found errors

```bash
source mcp/.venv/bin/activate
pip install fastmcp httpx dnspython
```

### CLI tools not found

CLI wrapper tools (nikto, sqlmap, etc.) return an error with install instructions when the binary is missing. The core 25+ tools work without any external dependencies.

---

## Requirements

- **Python 3.10+**
- Any supported AI coding agent (Claude Code, Cursor, Codex, Gemini CLI, Copilot CLI, Kimi Code, OpenCode, Pi)
- Python packages: `fastmcp>=0.4.0`, `httpx`, `dnspython` (installed in `.venv`)
- Optional CLI tools: nikto, sqlmap, amass, wpscan, masscan, xsstrike, gitleaks, cmseek, testssl, sslyze, gobuster, ffuf, nuclei, nmap, hydra, searchsploit

---

## License

MIT License - see LICENSE file for details.