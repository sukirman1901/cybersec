# Cybersec — OpenCode AI Cybersecurity Plugin

45 pure-Python MCP security tools + 8 penetration testing methodology skills for [OpenCode](https://opencode.ai) AI agent.

## Features

- **45 MCP Tools** — port scanning, DNS recon, HTTP probing, dir brute-force, SSL analysis, CVE lookup, WAF detection, Google dorking, subdomain enumeration, parameter discovery, tech detection, vulnerability scanning, and more
- **8 Methodology Skills** — guides the AI agent through Recon, Scanning, Exploit, Web, Vuln Research, Crisis, Report phases
- **Zero binary dependency** — 25 tools are pure Python (stdlib + httpx/dnspython)
- **CLI wrapper tools** — 12 tools wrap popular CLI tools (nikto, sqlmap, amass, etc.) with helpful guidance when not installed

## Tool Categories

| Category | Tools |
|----------|-------|
| **Recon** (4) | whois_lookup, asn_lookup, reverse_ip, crt_search |
| **Web Security** (5) | cors_check, open_redirect, graphql_introspect, jwt_analyze, api_fuzz |
| **Network Enum** (4) | smtp_enum, smb_enum, snmp_enum, ssh_audit |
| **Exploit Detection** (4) | lfi_detect, ssti_detect, xxe_detect, ssrf_detect |
| **Infrastructure** (3) | sub_takeover, origin_ip_discovery, service_fingerprint |

**Full list:** port_scan, dns_lookup, http_probe_target, dir_bruteforce, ssl_check, cve_search, waf_detection, dork_search, generate_report, subdomain_enum, param_discovery, tech_detect, vuln_scan, nikto_scan, sqlmap_check, amass_enum, wpscan_check, masscan_scan, xsstrike_check, gitleaks_check, cmseek_check, testssl_check, sslyze_check, gobuster_dir, ffuf_fuzz, whois_lookup, asn_lookup, reverse_ip, crt_search, cors_check, open_redirect, graphql_introspect, jwt_analyze, api_fuzz, smtp_enum, smb_enum, snmp_enum, ssh_audit, lfi_detect, ssti_detect, xxe_detect, ssrf_detect, sub_takeover, origin_ip_discovery, service_fingerprint

## Installation

```bash
git clone https://github.com/sukirman1901/cybersec.git
cd cybersec
python3 -m venv mcp/.venv
source mcp/.venv/bin/activate
pip install -r mcp/requirements.txt
```

## Usage with OpenCode

Add to your OpenCode config (`~/.config/opencode/opencode.json`):

```json
{
  "plugin": [
    "file:///path/to/cybersec/plugin.js"
  ]
}
```

Restart OpenCode. The AI agent will have full access to all 45 MCP security tools and 8 methodology skills.

## Requirements

- Python 3.10+
- [fastmcp](https://pypi.org/project/fastmcp/) (installed in venv)
- Optional CLI tools: nikto, sqlmap, amass, wpscan, masscan, xsstrike, gitleaks, cmseek, testssl, sslyze, gobuster, ffuf
