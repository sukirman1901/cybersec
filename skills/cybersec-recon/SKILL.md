---
name: cybersec-recon
description: Use when user asks to perform reconnaissance, enumerate subdomains, check DNS, or discover target infrastructure
---

## Reconnaissance Methodology

1. **DNS Enumeration** — Call `dns_lookup(target)` to get A, AAAA, MX, NS, TXT records
2. **Subdomain Discovery** — Try common subdomains via `dns_lookup(sub.target)`: www, mail, admin, api, dev, staging, blog, cdn, test, vpn
3. **HTTP Probing** — Call `http_probe_target(target)` to detect web technologies
4. **WAF Detection** — Call `waf_detection(target)` to check for Web Application Firewall
5. **Google Dorking** — If target is vague, use `dork_search("site:target.com")` to find exposed info

**Output:** Compile findings with target infrastructure, tech stack, and potential attack surface.
