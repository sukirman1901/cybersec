---
name: cybersec-ctf
description: Capture The Flag methodology — OWASP Juice Shop style challenges covering OWASP Top 10, API Security, and real-world vulns
---

## CTF Testing Methodology

### 1. Reconnaissance
- Probe target with `http_probe`, `tech_detect`, `waf_detect`
- Discover hidden endpoints with `dir_bust`, `param_discovery`
- Check for exposed files: `misplaced_files`, `exposed_git`, `exposed_backup`
- Map API surface: `graphql_introspect`, `api_fuzz`
- Score Board / admin panel discovery

### 2. Injection Attacks
- Test SQL/NoSQL injection: `nosql_inject`, `cmd_injection`
- Test template injection: `ssti_detect`
- Test XXE: `xxe_detect`
- Test SSRF: `ssrf_detect`
- Test LDAP/LFI: `ldap_enum`, `lfi_detect`
- Test prompt injection (AI challenges): `prompt_injection`, `llm_agent_hijack`

### 3. Authentication & Session
- Test JWT security: `jwt_analyze`, `jwt_forgery` (none alg, weak secret, kid injection)
- Test OAuth: `oauth_scan`
- Test API auth: `api_auth`
- Brute force: `hydra_brute`, password strength testing
- Session manipulation, 2FA bypass

### 4. Access Control
- Test privilege escalation: `bypass_403`, `idor_detect`
- CSRF: `csrf_detect`
- Basket manipulation, admin registration, deluxe fraud
- SSRF for internal access: `ssrf_detect`

### 5. Input Validation
- File upload bypass: `upload_bypass`
- Parameter pollution, coupon forgery, quantity manipulation
- Race conditions: `race_condition`
- CAPTCHA bypass: `captcha_test`

### 6. XSS & Client-Side
- Test reflected/stored/DOM XSS: `csp_analyze`, `cookie_audit`
- CSP bypass, DOM manipulation
- HTTP header injection XSS

### 7. Cryptography & Obscurity
- JWT attacks: `jwt_forgery`
- Steganography: `stego_detect` (images, metadata, hidden strings)
- Hidden endpoints, easter eggs, obfuscated code analysis
- SSL analysis: `ssl_analyzer`

### 8. Security Misconfiguration
- Check exposed metrics: `metrics_check`
- Check exposed logs: `log_exposure`
- Check exposed configs: `misplaced_files`, `desktop_config`
- CORS: `cors_check`
- Security headers: `csp_analyze`

### 9. Sensitive Data Exposure
- Log analysis: `log_exposure`
- Secret scanning: `secret_scanner`
- Exposed git/backups: `exposed_git`, `exposed_backup`
- Supply chain: `supply_chain`

### 10. Reporting
- Use `report` to document findings with evidence
- Map each finding to OWASP Top 10 / ASVS category
- Include exploit steps, payloads, and remediation
- Transition to `cybersec-report`

## Tools
- Recon: `http_probe`, `tech_detect`, `waf_detect`, `dir_bust`, `param_discovery`, `misplaced_files`
- Injection: `nosql_inject`, `cmd_injection`, `ssti_detect`, `xxe_detect`, `ssrf_detect`, `lfi_detect`, `prompt_injection`
- Auth: `jwt_analyze`, `jwt_forgery`, `oauth_scan`, `api_auth`, `hydra_brute`
- Access: `bypass_403`, `idor_detect`, `csrf_detect`, `race_condition`
- Input: `upload_bypass`, `captcha_test`, `graphql_introspect`, `api_fuzz`
- Crypto: `jwt_forgery`, `ssl_analyzer`, `stego_detect`
- Exposure: `metrics_check`, `log_exposure`, `secret_scanner`, `exposed_git`, `exposed_backup`
- Web: `csp_analyze`, `cookie_audit`, `cors_check`, `open_redirect`
