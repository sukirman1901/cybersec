---
name: cybersec-vulns
description: Use when user asks to find vulnerabilities, check CVEs, assess PHP2SHELL (CVE-2026-109618 or CVE-2026-109619), or assess security weaknesses
---

## Vulnerability Assessment Methodology

### Checklist

Create a todo list from the checklist below, then execute all steps immediately. Don't ask for confirmation — just run the tools and mark items complete as you go.

1. **CVE Lookup** — For each detected service + version, call `cve_search(service, version)` for known vulnerabilities
2. **Vulnerability Scan** — Call `vuln_scan(target)` for common vulnerability patterns
3. **CVE Cross-Reference** — For software with multiple CVEs, check severity and public exploit availability
4. **CRLF Injection Scan** — Call `crlf_inject(target)` for HTTP header injection vulnerabilities
5. **LDAP Injection Scan** — If LDAP endpoints found, call `ldap_inject(target)` for LDAP query manipulation
6. **Deserialization Check** — If Python app: call `pickle_deserialize(target)`. If API: call `mass_assignment(target)` for privilege escalation
7. **Tech Detection** — Call `tech_detect(target)` to identify CMS/framework versions for known vulns
8. **SSL Issues** — If ssl_check found weaknesses, document: weak ciphers, expired cert, missing HSTS
9. **Prioritize Findings** — Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
10. **Exploit Research** — For critical/high findings, check if public PoC exists via `cve_search`

### Tools Available
`cve_search`, `vuln_scan`, `php2shell_scan`, `tech_detect`, `ssl_check`, `crt_search`, `dork_search`, `crlf_inject`, `ldap_inject`, `pickle_deserialize`, `mass_assignment`

### Output
Prioritized vulnerability list with: CVE ID, CVSS score, affected service, description, and known exploit status.

### PHP2SHELL identification

For CVE-2026-109618 (OOM corruption) and CVE-2026-109619 (stale global
state), use `php2shell_scan(target)` on an authorized target. This dedicated
tool avoids the unrelated credential/path checks of broad `vuln_scan`. Inspect
`php2shell` assessment, `evidence`, `observed_versions`, `reason` and `limitations`.
`cve_search("php", "8.4.26")` also includes offline branch-aware correlation.
Its results are not proof that a remote target runs that version.
For an identification-only request, stop after assessment and remediation advice;
do not follow the generic checklist or Next Skill into unrelated tests/exploitation.

| Supported branch | First fixed release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

- `potentially_affected`: supported version below its fix. Report the two
  critical CVEs with `confidence=probable`, never verified RCE. For example,
  `PHP/8.4.26` is a probable version match, not an exploited vulnerability.
- `not_affected_by_version`: banner meets its branch fix (e.g. `PHP/8.4.27`).
  This is not proof of origin safety, full patch rollout, or absence of other CVEs.
- `unknown`: absent/partial/conflicting versions, prereleases, EOL or future
  branches. PHPSESSID, PHP application signatures and `.php` links do not prove
  a runtime version. No findings does not mean safe. Request runtime/package
  evidence from the owner; EOL requires a supported upgrade or vendor patch review.
- Distro/vendor backports may fix older versions without changing their upstream
  number. Verify package security changelogs. Composer `require.php` constraints
  are compatibility ranges, not the deployed runtime. Do not feed them as versions.
- `php2shell_scan` uses GET/HEAD/OPTIONS and five common phpinfo paths (disable
  discovery with `phpinfo_paths=false`). Default 8 requests, max 12; TLS verified,
  same-origin redirects only, bounded bodies and a 30-second whole-scan deadline.
  Inspect per-request `requests` and `coverage`: `access_blocked` is not the same
  as `php_detected_version_hidden`, `network_error`, `redirect_out_of_scope`,
  `budget_exhausted`, `rate_limited`, `timeout` or `no_php_evidence`. Report what
  was actually checked; do not stop at one missing banner and call it a full audit.
  `version_unclassified` means an observed version is outside the supported
  table or incomplete/prerelease, not that it is hidden. Inspect `body_skipped`
  and truncation records: unexpectedly compressed bodies are not decompressed.
- `configuration` contains only allowlisted phpinfo fields with source URLs:
  SAPI, memory/upload/input limits, upload progress, session serialize handler and
  fatal backtrace settings. phpinfo may be static/stale and is not verified RCE.
  Upload progress `Off` is not proof either CVE is fixed; configuration signals
  never override version evidence or resolve conflicting versions. Do not export
  entire phpinfo pages, session-cookie values, environment variables or secrets.
- CVE-2026-115560 (PHP informational advisory, 2026-10-23): an unlikely RCE vector
  needs a runtime `ini_set()` switch of `session.serialize_handler` to `php` after
  a `php_binary`/`php_serialize` config, plus enabled upload progress. Remote
  evidence cannot prove or refute that runtime switch — `serialize_handler=php`
  in phpinfo is collection coverage only, never "vulnerable" on its own. Defense
  guidance stays unupgraded: update to the next bugfix release or set
  `session.upload_progress.enabled=0` before request parsing (php.ini or FPM pool,
  not `ini_set()`/`.user.ini`) and restart every worker; if that was already
  applied for CVE-2026-109619, no further action is needed.
- `vuln_scan` still offers header-only PHP2SHELL correlation inside its broader
  checks. Do not run reference race harnesses, OOM/multipart load probes,
  malformed requests, webshell uploads or origin/WAF bypass for identification.
- Recommend the branch security release or later supported release. Verify
  `php -v` and package provenance in every serving PHP container and restart/recreate
  persistent workers. A CLI binary alone does not prove the FPM runtime was updated.

References: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[PHP session upload progress advisory](https://www.php.net/archive/2026.php#2026-10-23-1),
[VulnCheck analysis](https://www.vulncheck.com/blog/php2shell-vulnerabilities).

### Next Skill
If web services found, load `cybersec-web` skill for web-specific testing.
Otherwise load `cybersec-exploit` skill directly.
