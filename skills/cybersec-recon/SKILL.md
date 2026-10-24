---
name: cybersec-recon
description: Use when user asks to perform reconnaissance, enumerate subdomains, check DNS, or discover target infrastructure
---

## Reconnaissance Methodology

### Checklist

Select relevant branches for the requested DNS, passive inventory or active recon
outcome. Before active target probes require `engagement_gate` `init` + `authorize`;
confirmed `extend` only for additional user-approved resources, never automatically
for subdomains, co-hosted domains, origins or ASN ranges. Record coverage, budget
and skips; redact secrets. CT/WHOIS/archival intelligence does not establish live
ownership or permission. Stop at the requested inventory instead of auto-scanning.

1. **Target Validation** — Validate target resolves via `dns_lookup(target)` (A, AAAA, MX, NS, TXT, CNAME records)
2. **WHOIS Lookup** — Call `whois_lookup(target)` for domain registration, registrar, dates
3. **Subdomain Enumeration** — Call `subdomain_enum(target)` for passive subdomain discovery via crt.sh, DNS brute, APIs
4. **Subdomain Takeover Check** — Call `sub_takeover(target)` to check if any subdomains are vulnerable to takeover
5. **Advanced Enumeration** — If available, call `amass_enum(target)` for deeper attack surface mapping
6. **Certificate Transparency** — Call `crt_search(domain=domain)` for historical certificates and subdomains
5. **HTTP Probing** — Call `http_probe_target(target)` to detect live web services, tech stack, headers
6. **WAF Detection** — Call `waf_detection(target)` to identify Web Application Firewall
7. **Reverse IP** — Call `reverse_ip(target)` to find other domains on same IP
8. **ASN Lookup** — Call `asn_lookup(target)` for network ownership and IP range
9. **Origin IP Discovery** — If CDN detected, call `origin_ip_discovery(target)` to find real origin
10. **Service Fingerprint** — For each open port, call `service_fingerprint(target, port)` for banner grabs
11. **Dork Target Discovery** — `dork_gen(category="config_leak", target=domain)` then `dork_scan(dorks=dorks)` for a target-bound intelligence query
12. **Dork Hunting** — `dork_hunt(category="vuln_sites", target=domain, probe=False, validate=False)` for results only; probes require separate authorization of each returned resource

### Tools Available
`dns_lookup`, `whois_lookup`, `subdomain_enum`, `sub_takeover`, `amass_enum`, `crt_search`, `http_probe_target`, `waf_detection`, `reverse_ip`, `asn_lookup`, `origin_ip_discovery`, `service_fingerprint`, `dork_search`, `dork_gen`, `dork_scan`, `dork_hunt`

### Output
Compile findings as: target infrastructure map, subdomains, tech stack, CDN/WAF status, network ownership, and potential entry points.

### Next Skill
Load `cybersec-scanning` only if port/service scanning is requested and authorized.
