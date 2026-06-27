---
name: cybersec-bugbounty
description: Use when user asks for bug bounty specific testing, nuclei scanning, 403 bypass, or request smuggling
---

<HARD-GATE>
Do NOT run active scanning (nuclei) without completing passive recon and web testing first.
Always start with non-intrusive checks before running nuclei with critical templates.
</HARD-GATE>

## Bug Bounty Hunting Methodology

### Checklist

Create a TodoWrite for each item and complete in order:

1. **Nuclei Scan** — Run `nuclei_scan(target, severity="critical")` for critical templates first, then expand
2. **403 Bypass** — If any endpoints return 403, call `bypass_403(url)` to test bypass techniques
3. **Request Smuggling** — Call `smuggling_check(target)` to test CL.TE and TE.CL smuggling
4. **OOB Testing** — Call `oob_test(target)` for blind SSRF, blind RCE, template injection
5. **CORS Misconfig** — Call `cors_check(target)` for CORS bypass opportunities
6. **Open Redirect** — Call `open_redirect(target)` for redirect chains (OAuth phishing)
7. **GraphQL Audit** — Call `graphql_introspect(target)` for introspection + batching attacks
8. **JWT Analysis** — If JWT tokens found, call `jwt_analyze(token)` for alg confusion, none alg, weak key
9. **Duplicate Check** — Cross-reference findings with known bug bounty reports

### Tools Available
`nuclei_scan`, `bypass_403`, `smuggling_check`, `oob_test`, `cors_check`, `open_redirect`, `graphql_introspect`, `jwt_analyze`, `dir_bruteforce`, `ffuf_fuzz`, `sqlmap_check`, `xsstrike_check`

### Output
Bug bounty report with: nuclei findings, bypass results, smuggling status, OOB callback info, and priority rankings based on bounty potential.

### Next Skill
When all checklist items complete, load `cybersec-report` skill for final report.
