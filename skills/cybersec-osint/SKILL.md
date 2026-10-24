---
name: cybersec-osint
description: Use when user asks for advanced OSINT, shodan search, URL history, or deep reconnaissance
---

## OSINT & Advanced Recon Methodology

### Execution Rule
Select relevant intelligence sources from the requested domain/query/input.
Read-only intelligence and offline URL filtering need no engagement. Before active
target probes require `engagement_gate` `init` + `authorize`; confirmed `extend`
only for additional user-approved resources. Discovery is not authorization.
Record coverage/source dates and redact secrets/PII; archive entries are historical,
not evidence of a currently reachable vulnerable service.

### Quick Dorking
For dork results only, use `dork_hunt(category=category, target=domain, probe=False, validate=False)`
or `dork_search`. Do not enable probes/validation or `dork_and_scan` unless the user
requested active testing and every resulting resource is authorized. Preserve
scope denials rather than replacing a bounded query with global target discovery.

### Full OSINT Checklist
Choose applicable branches for a full OSINT request; do not run remote directory/API scans for intelligence-only requests:

1. `shodan_lookup(query=query)` — exposed devices, services, ports, CVEs
2. `wayback_urls(domain=domain)` — historical URLs, hidden endpoints
3. `gf_patterns(urls)` — sensitive endpoints from wayback results
4. `dir_bruteforce(target)` + `api_fuzz(target)` — hidden paths
5. `crt_search(domain=domain)` — certificate transparency, subdomains
6. `dork_gen(category=category, target=domain)` → `dork_scan(dorks=dorks)` — retain a target-bound intelligence query; discovered URLs require separate scope approval before probing
7. For people investigation: `phone_osint` / `telegram_osint` / `social_osint` / `email_osint`

### Tools Available
`shodan_lookup`, `wayback_urls`, `gf_patterns`, `crt_search`, `dir_bruteforce`, `api_fuzz`, `dork_search`, `dork_gen`, `dork_scan`, `dork_hunt`, `dork_and_scan`, `people_osint`

### Output
OSINT report: exposed services, historical URLs, sensitive endpoints, leaked info, attack surface expansion.

### Next Skill
Stop after the requested intelligence summary. Load `cybersec-scanning` or
`cybersec-bugbounty` only for separately requested active testing within approved
scope; an unfinished pentest checklist is not authorization to continue.
