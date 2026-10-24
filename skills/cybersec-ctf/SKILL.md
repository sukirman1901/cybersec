---
name: cybersec-ctf
description: Capture The Flag methodology — OWASP Juice Shop style challenges covering OWASP Top 10, API Security, and real-world vulns
---

## CTF Testing Methodology

Select the relevant challenge only; a CTF label does not authorize every attack.
Before active target probes require `engagement_gate` `init` + `authorize` for the
lab origin; confirmed `extend` only for additional user-approved resources, never
discovered internal hosts. Respect request/time limits and challenge rules. Record
coverage, redact secrets/flags from public evidence and stop on denied scope.

### 1. Reconnaissance
- Probe target with `http_probe_target`, `tech_detect`, `waf_detection`
- Discover hidden endpoints with `dir_bruteforce`, `param_discovery`
- Check for exposed files: `misplaced_files`, `exposed_git`, `exposed_backup`
- Map API surface: `graphql_introspect`, `api_fuzz`
- Score Board / admin panel discovery

### 2. Injection Attacks
- SQLi primary: `sqli_detect`; optional `sqlmap_check` only for approved deeper validation with the actual input endpoint
- NoSQL: `nosql_inject` only for NoSQL input; `cmd_injection` is for command execution sinks, not SQLi
- Test template injection: `ssti_detect`
- Test XXE: `xxe_detect`
- Test SSRF: `ssrf_detect`
- Test LDAP/LFI: `ldap_enum`, `lfi_detect`, `ldap_inject`
- Test CRLF injection: `crlf_inject`
- Test prompt injection (AI challenges): `prompt_injection`, `llm_agent_hijack`

### 3. Authentication & Session
- Test JWT security: `jwt_analyze`, `jwt_forgery` (none alg, weak secret, kid injection)
- Test OAuth: `oauth_scan`
- Test API auth: `api_auth`
- Brute force: `hydra_brute`, password strength testing
- Session manipulation, 2FA bypass

### 4. Access Control
- Test privilege escalation: `bypass_403`, `idor_detect`, `mass_assignment`
- CSRF: `csrf_detect`
- Basket manipulation, admin registration, deluxe fraud
- SSRF for internal access: `ssrf_detect`

### 5. Input Validation
- File upload bypass: `upload_bypass`
- Parameter pollution, coupon forgery, quantity manipulation
- Race conditions: `race_condition`
- CAPTCHA bypass: `captcha_test`
- Mass assignment / privilege escalation: `mass_assignment`
- Python deserialization: `pickle_deserialize`

### 6. XSS & Client-Side
- XSS primary: `xss_detect`; optional `xsstrike_check` for approved deeper validation. Reflection alone is a candidate, not JavaScript execution; require browser-context execution evidence
- `csp_analyze` and `cookie_audit` provide supporting configuration evidence, not XSS proof
- CSP bypass, DOM manipulation
- HTTP header injection XSS
- HTTP request splitting: `http_request_splitting`

### 7. Cryptography & Obscurity
- JWT attacks: `jwt_forgery`
- Steganography: `stego_detect` (images, metadata, hidden strings)
- Hidden endpoints, easter eggs, obfuscated code analysis
- SSL analysis: `ssl_check`

### 8. Security Misconfiguration
- Check exposed metrics: `metrics_check`
- Check exposed logs: `log_exposure`
- Check exposed configs: `misplaced_files`, `desktop_config`
- CORS: `cors_check`
- Security headers: `csp_analyze`
- GraphQL depth/batching bypass: `graphql_depth_bypass`

### 9. Sensitive Data Exposure
- Log analysis: `log_exposure`
- Secret scanning: `secret_scanner`
- Exposed git/backups: `exposed_git`, `exposed_backup`
- Supply chain: `supply_chain`

### 10. Reporting
- Use `generate_report` to document findings with evidence
- Map each finding to OWASP Top 10 / ASVS category
- Include exploit steps, payloads, and remediation
- Transition to `cybersec-report`

## Tools
- Recon: `http_probe_target`, `tech_detect`, `waf_detection`, `dir_bruteforce`, `param_discovery`, `misplaced_files`
- Injection: `sqli_detect`, `sqlmap_check`, `nosql_inject`, `cmd_injection`, `ssti_detect`, `xxe_detect`, `ssrf_detect`, `lfi_detect`, `ldap_inject`, `crlf_inject`, `prompt_injection`
- Auth: `jwt_analyze`, `jwt_forgery`, `oauth_scan`, `api_auth`, `hydra_brute`
- Access: `bypass_403`, `idor_detect`, `csrf_detect`, `race_condition`, `mass_assignment`
- Input: `upload_bypass`, `captcha_test`, `graphql_introspect`, `api_fuzz`, `pickle_deserialize`
- Crypto: `jwt_forgery`, `ssl_check`, `stego_detect`
- Exposure: `metrics_check`, `log_exposure`, `secret_scanner`, `exposed_git`, `exposed_backup`
- Web: `xss_detect`, `xsstrike_check`, `csp_analyze`, `cookie_audit`, `cors_check`, `open_redirect`, `http_request_splitting`, `graphql_depth_bypass`
