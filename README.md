<p align="center">
  <img src="logo-cybersec.png" alt="Cybersec Logo" width="300" />
</p>

# Cybersec — AI Cybersecurity Plugin

**172+ pure-Python MCP security tools** + **23 pentesting methodology skills** for AI coding agents.

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
  - [Enterprise Tools (HackerOne / Pentest-Tools.com inspired)](#enterprise-tools)
  - [Advanced Tools](#advanced-tools-16-new)
- [Agents (OpenCode)](#agents-opencode)
  - [Pentester (Primary)](#pentester-primary)
  - [Recon (Subagent)](#recon-subagent)
  - [Vuln Analyst (Subagent)](#vuln-analyst-subagent)
  - [Report Writer (Subagent)](#report-writer-subagent)
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
> "audit example.com and generate a report"

The AI will automatically load the right skill and use the MCP tools.

### OpenCode Agents

On OpenCode, press **Tab** to switch to the **Pentester** agent (red), then:

```
audit example.com
```

Or invoke subagents directly:

```
@recon gather intelligence on example.com
@vuln-analyst scan for vulnerabilities
@report-writer generate a report
```

---

## How It Works

1. You ask something like _"find subdomains for target.com and check for open ports"_
2. The AI detects the intent → matches the **cybersec-recon** skill
3. The skill provides a methodology (step-by-step guide)
4. The AI calls MCP tools like `subdomain_enum`, `port_scan`, `http_probe_target`
5. Results are analyzed and presented

The AI follows a standard pentesting methodology: **Recon → OSINT → Scanning → Vulnerability Analysis → Web Testing → Bug Bounty → AD → Cloud → Password → AI → AI Safety → Desktop → Code Audit → Exploitation → Reporting**

For continuous monitoring: **CTEM** runs in parallel — Discovery → Validation → Prioritization → Remediation in a continuous loop.

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

The Cybersec MCP server provides 172+ security tools via stdio transport using FastMCP.

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

Expected: 172+ tools listed.

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

### Enterprise Tools

Inspired by HackerOne and Pentest-Tools.com — workflow orchestration, findings management, continuous monitoring, and risk scoring.

| Tool | Description |
|------|-------------|
| `attack_surface_map` | Aggregate scan results into an attack surface graph |
| `findings_manager` | Centralized findings DB — add, list, update status, stats, export, clear. Deduplicates by hash |
| `vuln_validate` | Verify exploitability, filter false positives with confidence score |
| `pentest_workflow` | Chain tools with conditions. 5 templates: web-audit, recon-full, network-scan, bugbounty, cloud-audit |
| `continuous_monitor` | Track target changes over time with snapshot diffing |
| `retest_vuln` | Re-run scan to confirm fix. Supports sqli, xss, lfi, ssrf, open_redirect, ssti, log4j |
| `bulk_scan` | Scan multiple targets at once (port_scan, http_probe, ssl_check, vuln_scan). Max 50 |
| `vuln_diff` | Compare 2 scan results — new, resolved, changed findings + port changes |
| `authenticated_scan` | Scan behind login (form/cookie/header auth). Detects IDOR, sensitive data, missing headers |
| `report_export` | Export to HTML, CSV, markdown, JSON. HTML includes styled executive summary |
| `risk_score` | CVSS + business impact + likelihood scoring |

### Advanced Tools (16 new)

Automated exploitation, workflow management, OSINT, reporting, and integrations.

| Tool | Description |
|------|-------------|
| `auto_exploit` | Auto-exploit chain: detect → verify → exploit (sqli, xss, lfi, ssrf, open_redirect) |
| `scan_template` | Pre-defined tool combos: quick-recon, web-full, network-audit, api-security, cloud-audit, ad-pentest, code-audit, ctf |
| `executive_summary` | Auto-generate executive summary — risk posture, severity breakdown, top findings, recommendations |
| `compliance_map` | Map findings to SOC2, ISO27001, GDPR, PCI-DSS, NIST 800-53 control IDs |
| `notify_webhook` | Send findings to Slack, Discord, or Microsoft Teams via webhook |
| `jira_create` | Create Jira issue from security finding — custom project, labels, priority |
| `people_osint` | Individual OSINT — GitHub profile, social media presence, email analysis |
| `password_audit` | Multi-protocol password audit — SSH, FTP, SMTP, HTTP form, RDP with default wordlist |
| `cloud_audit` | Comprehensive cloud audit — S3 public, K8s API, Docker socket, IAM, infra |
| `sqli_exploit` | Generate PoC SQLi exploit payloads (error, union, boolean, time, stacked) |
| `xss_exploit` | Generate PoC XSS exploit links (reflected, stored, DOM, WAF bypass, cookie steal) |
| `http_logger` | Persistent HTTP request/response logger with search, stats, and export |
| `branded_report` | White-label pentest reports — custom logo, colors, company name, disclaimer |
| `vuln_database` | Local vulnerability database — add, search, update, delete, tags, import/export |
| `github_issue` | Create GitHub issue from security finding — labels, severity, evidence |
| `custom_wordlist` | Custom wordlist manager — create, merge, generate, import, upload |
| `auth_macro_runner` | Multi-step auth session chain — form login, basic auth, bearer token, cookie persistence, custom step sequences |
| `csrf_extract` | Extract and analyze anti-CSRF tokens from meta tags, hidden inputs, JS variables, cookies, and headers |
| `idor_access_validation` | Multi-role IDOR/BOLA validation — sequential enum, cross-user access, negative/array bypass |
| `injection_validator` | Unified injection validator — SQLi, XSS, NoSQL, CMD, LDAP, SSTI, XXE with multi-technique payloads |
| `oast_callback_server` | OAST callback correlation for blind SSRF/XXE/OOB — generate, poll, status, retry |
| `upload_exploit_chain` | Upload → Verify → Execute chain — PHP/JSP/ASP/SVG/PY/SH payloads with execution validation |
| `cache_poison_check` | Web cache poisoning detection — header injection, cache deception, scheme bypass, key manipulation |
| `cmd_oast_helper` | Blind command injection OAST — OOB callback correlation + time-based detection |
| `report_schema_v2` | Standardized report schema v2 — validate, convert v1→v2, merge, create with evidence chain hash |
| `vuln_validate` | **[UPGRADED]** Confidence engine v2 — evidence scoring, FP signal detection, reproducibility check, severity-adjusted recommendations |

---

## Skills Guide

The plugin includes **23** methodology skills that guide the AI through structured security testing:

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
| **cybersec-ctem** | "CTEM", "attack surface", "continuous monitoring", "exposure management" |
| **using-cybersec** | (bootstrap — auto-loaded every session) |

Skills load automatically via intent detection. The AI follows the skill's methodology step by step.

---

## Agents (OpenCode)

OpenCode-compatible agents are included in `.opencode/agents/`. These agents have tailored permissions and prompts for different security testing phases.

### Pentester (Primary)

**File:** `.opencode/agents/pentester.md`
**Mode:** Primary (cycle with Tab: Build → Plan → Pentester)
**Color:** Red (`#DC2626`)
**Permissions:** Full access (edit, bash, read, all MCP tools)

The default pentesting agent. Load this when you want the AI to act as a security tester. It has access to all 172+ MCP tools, can edit files, run bash commands, and dispatch subagents.

**Usage:**
1. Press **Tab** in OpenCode until you see **Pentester** (red)
2. Ask: `"audit example.com"` or `"find vulnerabilities in this codebase"`

**Flow:**
```
User: "audit example.com"
  → Pentester auto-loads cybersec-recon skill
  → Calls @recon subagent for passive intel
  → Calls @vuln-analyst subagent for active scanning
  → Calls @report-writer subagent for report
  → Output: Full penetration testing report
```

### Recon (Subagent)

**File:** `.opencode/agents/recon.md`
**Mode:** Subagent (invoke with `@recon`)
**Color:** Blue (`#3B82F6`)
**Permissions:** Read-only (no edit, no bash)

Passive reconnaissance and OSINT specialist. Gathers intelligence without actively probing the target.

**Skills:** `cybersec-recon`, `cybersec-osint`

**Tools:** `subdomain_enum`, `dns_lookup`, `whois_lookup`, `crt_search`, `shodan_lookup`, `wayback_urls`, `dork_search`, `ghdb_search`, `reverse_ip`, `asn_lookup`

**Usage:**
```
@recon gather intelligence on example.com
@recon find subdomains for target.com
@recon run OSINT on this domain
```

### Vuln Analyst (Subagent)

**File:** `.opencode/agents/vuln-analyst.md`
**Mode:** Subagent (invoke with `@vuln-analyst`)
**Color:** Amber (`#F59E0B`)
**Permissions:** Bash + read (no file editing)

Active vulnerability analyst. Scans, fingerprints, and tests for vulnerabilities. Can run bash commands and MCP tools but cannot edit project files.

**Skills:** `cybersec-scanning`, `cybersec-vulns`, `cybersec-web`, `cybersec-bugbounty`, `cybersec-ad`, `cybersec-cloud`, `cybersec-password`, `cybersec-ai`, `cybersec-ai-safety`, `cybersec-desktop`, `cybersec-code-audit`, `cybersec-ctf`, `cybersec-exploit`

**Tools:** `port_scan`, `nmap_scan`, `ssl_check`, `vuln_scan`, `sqli_detect`, `xss_detect`, `nuclei_scan`, `nikto_scan`, `sqlmap_check`, `exploit_db_search`, `cloud_enum`, `s3_scanner`, `bloodhound_collect`, `ldap_enum`, `bandit_scan`, `semgrep_scan`, `prompt_injection`, `apk_analyze`, `ipa_analyze`, and 80+ more

**Usage:**
```
@vuln-analyst scan ports on example.com
@vuln-analyst test for SQL injection in this URL
@vuln-analyst run nuclei scan on target
@vuln-analyst audit this codebase for vulnerabilities
```

### Report Writer (Subagent)

**File:** `.opencode/agents/report-writer.md`
**Mode:** Subagent (invoke with `@report-writer`)
**Color:** Green (`#10B981`)
**Permissions:** Edit + read (no bash)

Security report writer. Verifies findings and generates professional penetration testing reports with remediation plans.

**Skills:** `cybersec-report`, `cybersec-verification`, `cybersec-review`

**Tools:** `generate_report`, plus all read-only MCP tools for verification

**Usage:**
```
@report-writer generate a pentest report from these findings
@report-writer verify these vulnerabilities and write a report
@report-writer create a remediation plan for these issues
```

**Report structure:**
```
# Penetration Testing Report
## Executive Summary
## Scope
## Methodology
## Findings (sorted by severity: Critical → High → Medium → Low → Info)
  - Description, Evidence, Reproduction, Impact, Remediation
## Remediation Summary
## References (CVEs, OWASP, etc.)
```

### Agent Workflow Diagram

```
                    ┌─────────────────────────────────┐
                    │       PENTESTER (primary)       │
                    │   Tab → Build → Plan → Pentester │
                    │     Full access, all skills     │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
             ┌──────────┐  ┌─────────────┐  ┌──────────────┐
             │  @recon  │  │@vuln-analyst│  │@report-writer│
             │ read-only│  │ bash + read │  │  edit + read │
             │ passive  │  │   active    │  │    report    │
             │ OSINT    │  │  scanning   │  │  verify+write│
             └──────────┘  └─────────────┘  └──────────────┘
```

### Creating Custom Agents

You can create your own agents by adding markdown files to `.opencode/agents/`:

```markdown
---
description: Custom security analyst for your workflow
mode: subagent
permission:
  edit: deny
  bash: allow
---
Your custom prompt here.
```

See the [OpenCode Agents documentation](https://opencode.ai/docs/agents/) for full reference.

---

## Troubleshooting

### MCP Server not found

```bash
# Verify MCP server works
./mcp/.venv/bin/python3 -m server
# Should start a stdio MCP server — test with:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ./mcp/.venv/bin/python3 -m server
```

Expected output: 172+ tools listed.

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