---
name: cybersec-web
description: Use when user asks to test web applications, check for SQLi, XSS, or audit CMS
---

<HARD-GATE>
Do NOT test web apps without target URL and tech stack info from previous phases.
Always start with passive/recon techniques before active exploitation.
Never run sqlmap or other destructive tools without explicit user confirmation.
</HARD-GATE>

## Web Application Testing Methodology

### Checklist

Create a TodoWrite for each item and complete in order:

1. **Technology Stack** — Review tech_detect + http_probe_target results for framework/version
2. **Directory Busting** — Call `dir_bruteforce(target)` to find hidden paths, admin panels, backups
3. **API Discovery** — Call `api_fuzz(target)` to find API endpoints and Swagger docs
4. **CORS Testing** — Call `cors_check(target)` for CORS misconfigurations
5. **Open Redirect** — Call `open_redirect(target)` for redirect vulnerabilities
6. **JWT Analysis** — If JWT tokens found in headers/cookies, call `jwt_analyze(token)`
7. **GraphQL Check** — Call `graphql_introspect(target)` for introspection leakage
8. **CMS Specific** — If WordPress detected: call `wpscan_check(target)`. If Joomla/Drupal: call `cmseek_check(target)`
9. **Parameter Discovery** — Call `param_discovery(target)` to find hidden parameters
10. **LFI Test** — If PHP detected, call `lfi_detect(target)` for file inclusion
11. **SSTI Test** — If template engine detected, call `ssti_detect(target)`
12. **XXE Test** — If XML processing likely, call `xxe_detect(target)`
13. **SSRF Test** — If app makes external requests, call `ssrf_detect(target)`
14. **CAPTCHA Detection** — Call `captcha_test(target, action="detect")` to identify captcha type on forms
15. **CAPTCHA Bypass** — If captcha detected: call `captcha_test(target, action="all")` to test all bypass vectors (token reuse, empty values, OCR, math solving, header/cookie manipulation)
16. **SQLi / XSS** — If user input found: call `sqlmap_check(target)` and `xsstrike_check(target)` (with user consent)

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
`dir_bruteforce`, `api_fuzz`, `cors_check`, `open_redirect`, `jwt_analyze`, `graphql_introspect`, `wpscan_check`, `cmseek_check`, `param_discovery`, `lfi_detect`, `ssti_detect`, `xxe_detect`, `ssrf_detect`, `sqlmap_check`, `xsstrike_check`, `nikto_scan`, `gobuster_dir`, `ffuf_fuzz`, `captcha_test`

### Output
Web application assessment with: discovered paths, API endpoints, misconfigurations, input validation issues, CMS vulnerabilities, CAPTCHA bypass results, and exploit potential.

### Next Skill
When all checklist items complete, load `cybersec-exploit` skill for exploitation.
