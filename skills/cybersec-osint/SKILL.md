---
name: cybersec-osint
description: Use when user asks for advanced OSINT, shodan search, URL history, or deep reconnaissance
---

## OSINT & Advanced Recon Methodology

### Execution Rule
**Create a todo list from the checklist, then execute all steps immediately. Don't ask for confirmation. Just run the tools and mark items complete as you go.**

### Quick Dorking
If user says "dorking" with a target or category, run `dork_hunt(category, target, probe=True, validate=True)` immediately. One call = full pipeline.

### Full OSINT Checklist
Run in order when doing full recon:

1. `shodan_lookup(target)` — exposed devices, services, ports, CVEs
2. `wayback_urls(target)` — historical URLs, hidden endpoints
3. `gf_patterns(urls)` — sensitive endpoints from wayback results
4. `dir_bruteforce(target)` + `api_fuzz(target)` — hidden paths
5. `crt_search(target)` — certificate transparency, subdomains
6. `dork_gen(category, target)` → `dork_scan(dorks)` — or just `dork_hunt()` for full pipeline
7. For people investigation: `phone_osint` / `telegram_osint` / `social_osint` / `email_osint`

### Tools Available
`shodan_lookup`, `wayback_urls`, `gf_patterns`, `crt_search`, `dir_bruteforce`, `api_fuzz`, `dork_search`, `dork_gen`, `dork_scan`, `dork_hunt`, `people_osint`

### Output
OSINT report: exposed services, historical URLs, sensitive endpoints, leaked info, attack surface expansion.

### Next Skill
If scanning not yet done, load `cybersec-scanning`. If scanning done, load `cybersec-bugbounty`.
