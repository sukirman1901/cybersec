---
name: cybersec-verification
description: Use when about to claim scan results, found vulnerabilities, or completed security testing - run tools and show output before making claims
---

# Cybersec Verification

## Principle

Use relevant effect-specific evidence, not an automatic broad rescan. Before
active target probes require `engagement_gate` `init` + `authorize`; confirmed
`extend` only for additional user-approved resources. Offline artifact review needs
no engagement. Record coverage and redact secrets before displaying/exporting
evidence. 403/timeouts/blocked scans are inconclusive, not clean or false positive.

Verdicts: observed (direct fact), candidate (hypothesis), confirmed-by-execution
(controlled observed effect), inconclusive (coverage missing), not_reproduced
(attempt did not reproduce), verified-fixed (patch/runtime evidence plus equivalent
original PoC/session/control retest). Negative scans alone cannot prove clean/fixed.
`vuln_validate` scores supplied claims, not execution or cryptographic attestation.
XSS reflection is not JavaScript execution; require browser-context execution
evidence. Generated/simulated callbacks are not real OAST confirmation.

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
| Vulnerability candidate | `vuln_scan` or `nuclei_scan` alert; confirm exact effect separately |
| Hash identified | `hash_analyze` output |
| S3 bucket public | `s3_scanner` output: 200 + listing |
| Subdomain found | DNS resolution or `crt_search` confirms |
| CVE exists | `cve_search` output |
| Exploit works | Actual exploit output |
| Fix verified | Actual source/runtime patch evidence plus equivalent original PoC/session/control retest; blocked or negative scan alone is insufficient |

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
[nuclei_scan] → CVE alert → "Candidate CVE match; impact unconfirmed"
```

**Hash:**
```
[hash_analyze] → bcrypt, mode 3200 → "Hash is bcrypt"
```

## Quality fields (required before report)

Every finding handed to `report_schema_v2` / `branded_report` / `findings_manager` must include:

| Field | Meaning |
|-------|---------|
| `confidence` | HIGH / MEDIUM / LOW (or numeric from `vuln_validate`) |
| `coverage` | What was tested vs skipped (preset, dual-role gap, 429, blocked, budget) |

### Novelty triage

Before reporting, classify with `findings_manager(action="novelty")` or `vuln_diff`:

| Label | Meaning |
|-------|---------|
| `novel` | New fingerprint vs findings DB / prior scan |
| `duplicate` | Same fingerprint still open |
| `regression` | Fingerprint returned after fixed/retested/wont_fix/false_positive |
| `changed` | Same fingerprint, severity/confidence/status shifted |

`findings_manager(action="add")` rejects missing confidence/coverage by default (`require_quality=true`).

IDOR/BOLA: dual-role cookies/headers required for HIGH confidence. Single-role enum alone is LOW.

### Detector accuracy rules

- CMS/path scanners (wordpress/joomla/drupal/magento): HIGH disclosure only with **body markers**, never status 403 alone.
- `sqli_detect` / `xss_detect`: default `preset=observe-first` (bounded). Use `staging-deep` only with approval.
- CLI wrappers (`nikto`, `sqlmap`, …): `coverage=cli_missing` means the tool did **not** run — do not report clean.
- `auto_exploit`: requires approved `approval_id`. Score thresholds, controlled-evidence records and `exploited=true` flags are claims, not independent exploit proof. Inspect actual baseline/control/probe execution evidence and state only its demonstrated effect.

## When To Apply

Before reporting findings, moving to next phase, or writing final report. Load this skill before `report-writer` / `branded_report`.
