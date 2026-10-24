---
name: cybersec-bugbounty
description: Use when user asks for bug bounty specific testing, nuclei scanning, 403 bypass, or request smuggling
---

## Bug Bounty Hunting Methodology

### Checklist

Select relevant branches from the program scope and observed surface. Before
active target probes require `engagement_gate` `init` + `authorize`; confirmed
`extend` is only for additional user-approved resources, never discovered URLs.
Record coverage, request/time limits and skipped prerequisites; redact secrets.
403 is inconclusive, not permission to bypass. Bypass, smuggling, depth/load and
OOB tests need explicit technique approval and safe endpoints; stop on denial or
throttling. JWT analysis takes a supplied token, not a URL. Intelligence-only
requests do not start scans or exploit execution.

1. **Nuclei Scan** — Run `nuclei_scan(target, severity="critical")` for critical templates first, then expand
2. **403 Bypass** — Only if bypass testing is requested and approved, call `bypass_403(target=url)` on the scoped endpoint
3. **Request Smuggling** — Call `smuggling_check(target)` to test CL.TE and TE.CL smuggling
4. **OOB Testing** — Call `oob_test(target)` for blind SSRF, blind RCE, template injection
5. **CRLF Injection** — Call `crlf_inject(target)` for header injection and response splitting
6. **CORS Misconfig** — Call `cors_check(target)` for CORS bypass opportunities
7. **Open Redirect** — Call `open_redirect(target)` for redirect chains (OAuth phishing)
8. **GraphQL Audit** — Call `graphql_introspect(target)` for introspection + `graphql_depth_bypass(target)` for batching/depth attacks
9. **JWT Analysis** — If JWT tokens found, call `jwt_analyze(token)` for alg confusion, none alg, weak key
10. **Mass Assignment** — If API endpoints found, call `mass_assignment(target)` for privilege escalation via parameter overwriting
11. **HTTP Request Splitting** — Call `http_request_splitting(target)` for request splitting and cache poisoning
12. **Duplicate Check** — Cross-reference findings with known bug bounty reports

### Tools Available
`nuclei_scan`, `bypass_403`, `smuggling_check`, `oob_test`, `cors_check`, `open_redirect`, `graphql_introspect`, `graphql_depth_bypass`, `jwt_analyze`, `dir_bruteforce`, `ffuf_fuzz`, `sqlmap_check`, `xsstrike_check`, `crlf_inject`, `mass_assignment`, `http_request_splitting`

### Output
Bug bounty report with: nuclei findings, bypass results, smuggling status, OOB callback info, and priority rankings based on bounty potential.

### Next Skill
When all checklist items complete, load `cybersec-report` skill for final report.
