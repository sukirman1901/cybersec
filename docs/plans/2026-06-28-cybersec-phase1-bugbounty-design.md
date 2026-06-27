# Cybersec Plugin — Phase 1: Bug Bounty Expansion

## Goal
Add 7 new MCP tools + 2 new methodology skills for bug bounty hunting workflows.

## New Skills
1. `cybersec-osint` — Advanced OSINT & recon (trigger: "osint", "shodan", "recon advanced")
2. `cybersec-bugbounty` — Bug hunting methodology (trigger: "bug bounty", "nuclei", "403 bypass")

## New Tools
1. `shodan_lookup` — Python `httpx`, search Shodan API for exposed devices/services
2. `wayback_urls` — Python `httpx`, fetch URL history from archive.org Wayback Machine
3. `nuclei_scan` — CLI wrapper for nuclei template-based scanner
4. `bypass_403` — Python `httpx`, 403 bypass via headers/methods/paths
5. `smuggling_check` — Python `socket`, HTTP request smuggling (CL.TE, TE.CL)
6. `gf_patterns` — Python, regex pattern matching on URLs for sensitive endpoints
7. `oob_test` — Python `httpx`, blind OOB interaction testing (interact.sh style)

## Files to Create/Modify
- `mcp/cyber_tools/shodan_lookup.py` (new)
- `mcp/cyber_tools/wayback_urls.py` (new)
- `mcp/cyber_tools/nuclei_scan.py` (new)
- `mcp/cyber_tools/bypass_403.py` (new)
- `mcp/cyber_tools/smuggling_check.py` (new)
- `mcp/cyber_tools/gf_patterns.py` (new)
- `mcp/cyber_tools/oob_test.py` (new)
- `mcp/server.py` (update: register 7 tools)
- `skills/cybersec-osint/SKILL.md` (new)
- `skills/cybersec-bugbounty/SKILL.md` (new)
- `skills/using-cybersec/SKILL.md` (update: add 2 new skills to bootstrap)

## Workflow Chain Update
```
Recon → [OSINT] → Scanning → Vulns → Web → [Bug Bounty] → Exploit → Report
```

OSINT: advanced recon after basic recon, before scanning
Bug Bounty: specialized web testing after general web testing
