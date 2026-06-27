---
name: cybersec-web
description: Use when user asks to test web applications, check for SQLi, XSS, or audit CMS
---

## Web Application Testing Methodology

1. **Recon** — Call `http_probe_target(target)` to identify tech stack
2. **Directory Busting** — Call `dir_bruteforce(target)` to find hidden paths
3. **WAF Check** — Call `waf_detection(target)` to know what bypasses needed
4. **CMS Detection** — If WordPress detected:
   - Check /wp-admin, /wp-json, /xmlrpc.php
   - Look for outdated plugins and themes
5. **Manual Testing Guidance** — Based on tech stack, recommend specific tests:
   - PHP sites: LFI/RFI, file upload, PHP wrappers
   - Node.js: SSRF, prototype pollution, path traversal
   - SQL databases: SQL injection via parameter fuzzing

**Output:** Web application assessment with findings and exploit potential.
