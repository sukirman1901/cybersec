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
`cve_search`, `vuln_scan`, `tech_detect`, `ssl_check`, `crt_search`, `dork_search`, `crlf_inject`, `ldap_inject`, `pickle_deserialize`, `mass_assignment`

### Output
Prioritized vulnerability list with: CVE ID, CVSS score, affected service, description, and known exploit status.

### PHP2SHELL identification

For CVE-2026-109618 (OOM corruption) and CVE-2026-109619 (stale global
state), use `vuln_scan(target)` on an authorized target. Inspect its `php2shell`
assessment, `evidence`, `observed_versions`, `reason` and `limitations`.
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
- This PHP2SHELL check reads already-fetched headers only. It does not crawl
  phpinfo pages or infer upload-progress settings. Do not run the reference race
  harnesses, OOM/multipart load probes, webshell uploads or origin/WAF bypass to
  identify these CVEs. Existing unrelated `vuln_scan` checks still run.
- Recommend the branch security release or later supported release. Verify
  `php -v` and package provenance in every serving PHP container and restart/recreate
  persistent workers. A CLI binary alone does not prove the FPM runtime was updated.

References: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[VulnCheck analysis](https://www.vulncheck.com/blog/php2shell-vulnerabilities).

### Next Skill
If web services found, load `cybersec-web` skill for web-specific testing.
Otherwise load `cybersec-exploit` skill directly.
