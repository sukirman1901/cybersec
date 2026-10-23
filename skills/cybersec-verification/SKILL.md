---
name: cybersec-verification
description: Use when about to claim scan results, found vulnerabilities, or completed security testing - run tools and show output before making claims
---

# Cybersec Verification

## Principle

Run the tool. Show the output. Then state the finding.

## How To Verify

```
BEFORE claiming any security finding:

1. RUN: Execute the tool (fresh output)
2. READ: Check status codes, count findings
3. REPORT: State findings WITH the output as evidence
```

## Verification Table

| Claim | How to verify |
|-------|---------------|
| Port is open | `port_scan` output showing "open" |
| Vulnerability found | `vuln_scan` or `nuclei_scan` output |
| Hash identified | `hash_analyze` output |
| S3 bucket public | `s3_scanner` output: 200 + listing |
| Subdomain found | DNS resolution or `crt_search` confirms |
| CVE exists | `cve_search` output |
| Exploit works | Actual exploit output |
| Fix applied | Re-run scan shows issue resolved |

### PHP2SHELL evidence gate

For CVE-2026-109618 and CVE-2026-109619, use dedicated `php2shell_scan` for
identification-only requests. Both it and broad `vuln_scan` expose
`php2shell.status` as a version assessment, not an exploit verdict:
The following PHP2SHELL rules override the generic verification table above.

- `potentially_affected` / `confidence=probable` (e.g. PHP/8.4.26): retain the
  version evidence, its source and backport caveat; never promote it to verified RCE.
- `unknown` (including PHPSESSID without a version): insufficient evidence,
  not safe. EOL and future branches require separate vendor assessment.
- `not_affected_by_version` (e.g. PHP/8.4.27): advertised version meets the fix,
  not proof the origin and all workers are patched. Headers may be stale or proxied.

Fixed baselines are 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Before claiming remediation,
verify the actual serving runtime/package provenance and vendor security changelog
on every PHP service, including restarted/recreated long-running workers. Distro
backports may fix older banners. Composer constraints are not runtime evidence.
Do not use OOM/race/load probes or webshell execution for PHP2SHELL identification
or patch verification. A failed probe or absence of a finding cannot prove safety.
Inspect `coverage` and the per-request `requests` records: `access_blocked`,
`php_detected_version_hidden`, `network_error` and `budget_exhausted` are distinct
limitations. The dedicated tool uses bounded phpinfo discovery; configuration is
allowlisted and source-attributed, not a raw-page dump. phpinfo may be static or
stale, so it does not prove the origin's current runtime or verified RCE.
`session.upload_progress.enabled=Off` does not prove either CVE is fixed.
Never publish raw phpinfo, environment secrets or session-cookie values.

## Quick Examples

**Port scan:**
```
[port_scan] → port 443 open → "Port 443 is open"
```

**Vulnerability:**
```
[nuclei_scan] → critical CVE-2024-XXXX → "Critical CVE detected"
```

**Hash:**
```
[hash_analyze] → bcrypt, mode 3200 → "Hash is bcrypt"
```

## Quality fields (required before report)

Every finding handed to `report_schema_v2` / `branded_report` must include:

| Field | Meaning |
|-------|---------|
| `confidence` | HIGH / MEDIUM / LOW (or numeric from `vuln_validate`) |
| `coverage` | What was tested vs skipped (preset, dual-role gap, 429, blocked, budget) |

IDOR/BOLA: dual-role cookies/headers required for HIGH confidence. Single-role enum alone is LOW.

## When To Apply

Before reporting findings, moving to next phase, or writing final report. Load this skill before `report-writer` / `branded_report`.
