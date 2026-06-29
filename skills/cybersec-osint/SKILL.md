---
name: cybersec-osint
description: Use when user asks for advanced OSINT, shodan search, URL history, or deep reconnaissance
---

## OSINT & Advanced Recon Methodology

### Checklist

Create a TodoWrite for each item and complete in order:

1. **Shodan Search** — Call `shodan_lookup(target)` to find exposed devices, services, open ports, and CVEs
2. **URL History** — Call `wayback_urls(target)` to discover historical URLs, hidden endpoints, old versions
3. **Pattern Analysis** — If wayback returned URLs, call `gf_patterns(urls)` to find sensitive endpoints (admin, api, debug, config)
4. **Endpoint Discovery** — Run `dir_bruteforce(target)` + `api_fuzz(target)` for hidden paths
5. **Certificate Transparency** — Call `crt_search(target)` for historical certs and subdomains
6. **Google Dorking** — Call `dork_search("site:target.com")` + `dork_search("site:target.com filetype:pdf")`
7. **Compile Findings** — URL patterns, exposed services, interesting endpoints, potential attack surface

### Tools Available
`shodan_lookup`, `wayback_urls`, `gf_patterns`, `crt_search`, `dir_bruteforce`, `api_fuzz`, `dork_search`

### Output
OSINT report: exposed services, historical URLs, sensitive endpoints, leaked info, attack surface expansion.

### Next Skill
If scanning not yet done, load `cybersec-scanning`. If scanning done, load `cybersec-bugbounty`.
