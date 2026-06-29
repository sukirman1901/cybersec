---
name: cybersec-recon
description: Use when user asks to perform reconnaissance, enumerate subdomains, check DNS, or discover target infrastructure
---

## Reconnaissance Methodology

### Checklist

Create a todo list from the checklist below, then execute all steps immediately. Don't ask for confirmation — just run the tools and mark items complete as you go.

1. **Target Validation** — Validate target resolves via `dns_lookup(target)` (A, AAAA, MX, NS, TXT, CNAME records)
2. **WHOIS Lookup** — Call `whois_lookup(target)` for domain registration, registrar, dates
3. **Subdomain Enumeration** — Call `subdomain_enum(target)` for passive subdomain discovery via crt.sh, DNS brute, APIs
4. **Subdomain Takeover Check** — Call `sub_takeover(target)` to check if any subdomains are vulnerable to takeover
5. **Advanced Enumeration** — If available, call `amass_enum(target)` for deeper attack surface mapping
6. **Certificate Transparency** — Call `crt_search(target)` for historical certificates and subdomains
5. **HTTP Probing** — Call `http_probe_target(target)` to detect live web services, tech stack, headers
6. **WAF Detection** — Call `waf_detection(target)` to identify Web Application Firewall
7. **Reverse IP** — Call `reverse_ip(target)` to find other domains on same IP
8. **ASN Lookup** — Call `asn_lookup(target)` for network ownership and IP range
9. **Origin IP Discovery** — If CDN detected, call `origin_ip_discovery(target)` to find real origin
10. **Service Fingerprint** — For each open port, call `service_fingerprint(target, port)` for banner grabs
11. **Dork Target Discovery** — Call `dork_gen(category="config_leak", target="target.com")` to generate targeted dorks, then `dork_scan(dorks)` to execute them
12. **Dork Hunting** — For one-call target discovery, call `dork_hunt(category="vuln_sites", probe=True, validate=True)` — generates dorks, scans engines, probes URLs, validates vulns

### Tools Available
`dns_lookup`, `whois_lookup`, `subdomain_enum`, `sub_takeover`, `amass_enum`, `crt_search`, `http_probe_target`, `waf_detection`, `reverse_ip`, `asn_lookup`, `origin_ip_discovery`, `service_fingerprint`, `dork_search`, `dork_gen`, `dork_scan`, `dork_hunt`

### Output
Compile findings as: target infrastructure map, subdomains, tech stack, CDN/WAF status, network ownership, and potential entry points.

### Next Skill
When all checklist items complete, load `cybersec-scanning` skill for port/service scanning.
