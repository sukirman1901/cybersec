---
name: cybersec-web
description: Use when user asks to test web applications, check for SQLi, XSS, or audit CMS
---

## Web Application Testing Methodology

### Checklist

Execute tools immediately. Don't ask for confirmation. Just run the tools and show output.

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
15. **SSRF Test** — If app makes external requests, call `ssrf_detect(target)` and `oast_callback_server(target)` for blind SSRF
16. **Command Injection** — If shell interaction likely, call `cmd_injection(target)` and `cmd_oast_helper(target)` for blind OS command injection
17. **NoSQL Injection** — If MongoDB/NoSQL detected, call `nosql_inject(target)`
18. **CSRF Detection** — Call `csrf_detect(target)` to check forms for CSRF tokens. Call `csrf_extract(target)` to analyze token patterns.
19. **IDOR Testing** — Call `idor_detect(target)` for Insecure Direct Object References, then `idor_access_validation(target)` for validation
20. **WebSocket Testing** — If WebSocket endpoints found, call `websocket_test(target)`
21. **Prototype Pollution** — If JavaScript SPA detected, call `prototype_pollution(target)`
22. **Cache Poisoning** — Call `cache_poison_check(target)` for web cache poisoning
23. **Host Header Injection** — Call `host_header_injection(target)` for host header attacks
24. **File Upload Bypass** — If file upload forms found, call `upload_bypass(target)` and `upload_exploit_chain(target)`
25. **OAuth Testing** — If OAuth flows detected, call `oauth_scan(target)`
26. **API Auth Testing** — If API endpoints found, call `api_auth(target)` for auth bypass
27. **Cookie Security** — Call `cookie_audit(target)` to audit cookie security flags, call `cookie_editor(target)` to test cookie manipulation
28. **Security Headers** — Call `csp_analyze(target)` for CSP and security header analysis
29. **Race Condition** — If concurrent requests likely, call `race_condition(target)`
30. **VHost Discovery** — Call `vhost_discovery(target)` to find virtual hosts
31. **Deserialization** — If PHP detected: `php_deserialize(target)`. If Java: `java_deserialize(target)`.
32. **Log4J Scan** — Call `log4j_scan(target)` for Log4j JNDI injection
33. **Supply Chain** — Call `supply_chain(target)` for exposed manifests and dependency CVEs
34. **CAPTCHA Detection** — Call `captcha_test(target, action="detect")` to identify captcha type on forms
35. **CAPTCHA Bypass** — If captcha detected: call `captcha_test(target, action="all")` to test all bypass vectors (token reuse, empty values, OCR, math solving, header/cookie manipulation)
36. **SQLi / XSS** — If user input found: call `sqli_detect(target)` and `sqlmap_check(target)` for SQLi. Call `xss_detect(target)` and `xsstrike_check(target)` for XSS.
37. **Injection Validator** — Call `injection_validator(target)` for unified injection validation across 7 types
38. **Web Shell Detection** — Call `webshell_detect(target, deep_scan=True)` to scan for existing web shells (c99, r57, weevely, china chopper, etc.)
39. **Dork Target Discovery** — Call `dork_gen(category="vuln_sites", target="target.com")` to generate dorks, then `dork_scan(dorks)` to find exposed pages
40. **Dork Hunting** — Call `dork_hunt(category="shell_upload", target="target.com", validate=True)` for one-call vuln discovery

### Auto-CAPTCHA Protocol

**When testing forms/endpoints, ALWAYS auto-detect and test captcha bypass:**

1. On ANY form submission endpoint, run `captcha_test(endpoint, action="detect")`
2. If captcha detected (reCAPTCHA, hCaptcha, Turnstile, image, math):
   - Auto-run `captcha_test(endpoint, action="math")` for math captchas
   - Auto-run `captcha_test(endpoint, action="ocr")` for image captchas
   - Auto-run `captcha_test(endpoint, action="header")` for header bypass
   - Auto-run `captcha_test(endpoint, action="cookie")` for cookie bypass
   - Auto-run `captcha_test(endpoint, action="reuse")` for token reuse
3. Report all bypass attempts with evidence
4. If bypass successful: note in report as HIGH/CRITICAL finding
5. If all bypasses fail: note captcha is effective

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
`php_deserialize` `java_deserialize` `log4j_scan` `supply_chain`
`webshell_detect`
`dork_gen` `dork_scan` `dork_hunt`

### Output
Web application assessment with: discovered paths, API endpoints, misconfigurations, input validation issues, CMS vulnerabilities, CAPTCHA bypass results, and exploit potential.

### Next Skill
When all checklist items complete, load `cybersec-exploit` skill for exploitation.
