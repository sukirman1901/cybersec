---
name: cybersec-web
description: Use when user asks to test web applications, check for SQLi, XSS, or audit CMS
---

## Web Application Testing Methodology

### Checklist

Select relevant branches by requested outcome, input endpoint and observed surface;
this is a menu, not a command to run all tools. Before active target probes require
`engagement_gate` `init` + `authorize`; confirmed `extend` only for additional
user-approved resources, never discovered URLs. Bound requests/time, record coverage
and skipped prerequisites, and redact secrets. Source/token-only analysis stays
offline. Denial/throttling stops the branch; no automatic bypass or escalation.
Use the actual endpoint/parameter and test accounts; IDOR validation requires two
approved roles. Intrusive upload chains, deserialization, races, smuggling, cache
poisoning and load/depth tests require explicit technique approval and cleanup.
SQLi primary is `sqli_detect`, XSS primary is `xss_detect`; deeper CLI tools are
optional. Reflection is not JavaScript execution, and a missing scanner is a gap.

1. **Technology Stack** — Call `tech_detect(target)` + `http_probe_target(target)` for framework, version, headers
2. **Directory Busting** — Call `dir_bruteforce(target)` and `gobuster_dir(target)` to find hidden paths, admin panels, backups
3. **Web Fuzzing** — Call `ffuf_fuzz(target)` for parameter and path fuzzing
4. **API Discovery** — Call `api_fuzz(target)` to find API endpoints, Swagger docs, OpenAPI
5. **CORS Testing** — Call `cors_check(target)` for CORS misconfigurations
6. **Open Redirect** — Call `open_redirect(target)` for redirect vulnerabilities
7. **JWT Analysis** — If JWT tokens found in headers/cookies, call `jwt_analyze(token)` and `jwt_forgery(token)`
8. **GraphQL Testing** — Call `graphql_introspect(target)` for introspection leakage, then `graphql_injection(target)` for injection
9. **CMS Specific** — Call `wordpress_scan(target)` or `wpscan_check(target)` for WordPress. Call `cmseek_check(target)` for Joomla/Drupal/Magento. Call `joomla_scan(target)`, `drupal_scan(target)`, `magento_scan(target)`, `sharepoint_scan(target)` as needed.
10. **Framework Specific** — If Spring detected: `spring_scan(target)`. If Next.js: `nextjs_scan(target)`. If Django: `django_scan(target)`. If Express: `express_scan(target)`. If Rails: `rails_scan(target)`. If Laravel: `laravel_scan(target)`.
11. **Parameter Discovery** — Call `param_discovery(target)` to find hidden parameters
12. **LFI Test** — If PHP detected, call `lfi_detect(target)` for file inclusion
13. **SSTI Test** — If template engine detected, call `ssti_detect(target)`
14. **XXE Test** — If XML processing likely, call `xxe_detect(target)`
15. **SSRF Test** — For an approved URL-fetch input, use `ssrf_detect(target)` and `oast_callback_server(action="generate")`; correlate a unique token with real callback evidence using poll per the live schema (action is not a target URL)
16. **Command Injection** — If shell interaction likely, call `cmd_injection(target)` and `cmd_oast_helper(target)` for blind OS command injection
17. **NoSQL Injection** — If MongoDB/NoSQL detected, call `nosql_inject(target)`
18. **CSRF Detection** — Call `csrf_detect(target)` to check forms for CSRF tokens. Call `csrf_extract(target)` to analyze token patterns.
19. **CRLF Injection** — Call `crlf_inject(target)` for HTTP header injection, response splitting, and log forgery
20. **LDAP Injection** — If LDAP endpoints found, call `ldap_inject(target)` for LDAP query manipulation
21. **IDOR Testing** — Call `idor_detect(target)` for Insecure Direct Object References, then `idor_access_validation(target)` for validation
22. **WebSocket Testing** — If WebSocket endpoints found, call `websocket_test(target)`
23. **Prototype Pollution** — If JavaScript SPA detected, call `prototype_pollution(target)`
24. **Cache Poisoning** — Call `cache_poison_check(target)` for web cache poisoning
25. **Host Header Injection** — Call `host_header_injection(target)` for host header attacks
26. **File Upload Bypass** — If file upload forms found, call `upload_bypass(target)` and `upload_exploit_chain(target)`
27. **OAuth Testing** — If OAuth flows detected, call `oauth_scan(target)`
28. **API Auth Testing** — If API endpoints found, call `api_auth(target)` for auth bypass
29. **Cookie Security** — Call `cookie_audit(target)` to audit cookie security flags, call `cookie_editor(target)` to test cookie manipulation
30. **Security Headers** — Call `csp_analyze(target)` for CSP and security header analysis
31. **Race Condition** — If concurrent requests likely, call `race_condition(target)`
32. **VHost Discovery** — Call `vhost_discovery(target)` to find virtual hosts
33. **Deserialization** — If PHP detected: `php_deserialize(target)`. If Java: `java_deserialize(target)`. If Python: `pickle_deserialize(target)`
34. **Log4J Scan** — Call `log4j_scan(target)` for Log4j JNDI injection
35. **Supply Chain** — Call `supply_chain(target)` for exposed manifests and dependency CVEs
36. **CAPTCHA Detection** — Call `captcha_test(target, action="detect")` to identify captcha type on forms
37. **CAPTCHA Bypass** — Only for explicitly approved anti-automation testing, select a bounded specific action; detection alone grants no bypass permission
38. **SQLi / XSS** — If user input found: call `sqli_detect(target)` and `sqlmap_check(target)` for SQLi. Call `xss_detect(target)` and `xsstrike_check(target)` for XSS.
39. **Injection Validator** — Call `injection_validator(target)` for unified injection validation across 7 types
40. **Web Shell Detection** — Call `webshell_detect(target, deep_scan=True)` to scan for existing web shells (c99, r57, weevely, china chopper, etc.)
41. **Dork Target Discovery** — `dork_gen(category="vuln_sites", target=domain)` then `dork_scan(dorks=dorks)` for requested target-bound intelligence
42. **Dork Hunting** — `dork_hunt(category="shell_upload", target=domain, probe=False, validate=False)` for discovery only; separately authorize returned resources before probing
43. **Mass Assignment** — If API endpoints found, call `mass_assignment(target)` for parameter overwriting / privilege escalation
44. **HTTP Request Splitting** — Call `http_request_splitting(target)` for CRLF injection in HTTP request headers
45. **GraphQL Depth Bypass** — If GraphQL found, call `graphql_depth_bypass(target)` for depth limit bypass, batching, alias attacks

### Bounded CAPTCHA branch

For requested CAPTCHA assessment, detect on the specified form with
`captcha_test(target=endpoint, action="detect")`. Before any reuse/empty-token,
math/OCR, header or cookie bypass test, confirm technique scope, test account and
attempt limit. Stop on throttling, denial or unexpected account effects. Report
the exact observed behavior and impact; unsuccessful attempts do not establish
general effectiveness and successful solving alone does not imply HIGH/CRITICAL.

### Tools Available

`tech_detect` `http_probe_target` `dir_bruteforce` `gobuster_dir` `ffuf_fuzz` `api_fuzz` `param_discovery` `vuln_scan` `nikto_scan`
`sqli_detect` `sqlmap_check` `xss_detect` `xsstrike_check` `csrf_detect` `csrf_extract` `idor_detect` `idor_access_validation`
`lfi_detect` `ssti_detect` `xxe_detect` `ssrf_detect` `cmd_injection` `nosql_inject` `upload_bypass` `upload_exploit_chain`
`cors_check` `open_redirect` `host_header_injection` `cache_poison_check` `race_condition`
`graphql_introspect` `graphql_injection` `websocket_test` `vhost_discovery` `cookie_editor` `cookie_audit` `csp_analyze`
`oauth_scan` `api_auth` `jwt_analyze` `jwt_forgery` `prototype_pollution` `injection_validator`
`oast_callback_server` `cmd_oast_helper` `captcha_test` `auth_macro_runner` `session_verification`
`spring_scan` `nextjs_scan` `django_scan` `express_scan` `rails_scan` `laravel_scan`
`wordpress_scan` `wpscan_check` `joomla_scan` `drupal_scan` `magento_scan` `cmseek_check` `sharepoint_scan`
`php_deserialize` `java_deserialize` `pickle_deserialize` `log4j_scan` `supply_chain`
`webshell_detect`
`dork_gen` `dork_scan` `dork_hunt`
`crlf_inject` `ldap_inject` `mass_assignment` `http_request_splitting` `graphql_depth_bypass`

### Output
Web application assessment with: discovered paths, API endpoints, misconfigurations, input validation issues, CMS vulnerabilities, CAPTCHA bypass results, and exploit potential.

### Next Skill
Load `cybersec-exploit` only for explicitly requested, approved exploitation;
otherwise stop with findings, uncertainty and coverage for the requested tests.
