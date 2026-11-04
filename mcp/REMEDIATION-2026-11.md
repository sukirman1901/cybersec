# Scanner remediation — 2026-11-04

Changes address the reproducible scanner reliability audit in the local working tree.
209 public tool names remain registered. Optional request/execution parameters extend
existing APIs; planning remains the default.

## Audit disposition

| ID | Change and evidence | Remaining boundary |
|---|---|---|
| A01 | CLI exit/error propagation; subprocess kill/reap with partial stdout; Nuclei and vuln_scan coverage; XSS request failures visible | Not an end-to-end validation of every external CLI |
| A02 | Cookie hostname fixed; identity marker plus anonymous control; offline session checks no longer assert authentication or refresh | Caller supplies application-specific identity marker and session |
| A03 | Real bounded loopback HTTP collector with correlated callbacks, TTL and shutdown; round-trip integration passes | DNS unsupported; remote callbacks require operator-managed forwarding |
| A04 | WPScan core/plugin/theme findings retained, aborted scans flagged | Real WPScan target/database/API validation not performed |
| A05 | Removed unsupported Amass JSON flag; scoped text output parser | External Amass enumeration not performed |
| A06 | Shared query mutation; authenticated flat JSON/form SQLi and XSS preserving companion fields | Nested JSON and cookie injection unsupported |
| A07 | vulnerabilities/name/matched_at and structured evidence retained in reports; legacy arrays supported | Coverage remains detector-specific |
| A08 | Catch-all Laravel HTML rejected; config markers required; accessible authenticated endpoints no longer labelled IDOR | Ownership policy still needed for BOLA proof |
| A09 | Bulk delegates to canonical scanner and counts nested incomplete/error results | No blanket success inferred from returned envelopes |
| A10 | Static script is not XSS proof; controlled redirect comparison; unsupported proof paths inconclusive | General original authenticated request replay/browser verification not implemented |
| A11 | Opt-in bounded executor, per-step scope checks, normalized findings; SQLi deep preset forwarded; SQLi/XSS request context | Partial capability closure: automatic crawl/HAR/OpenAPI-to-detector inventory and conditional execution remain absent; unsupported steps explicitly skipped |
| A12 | Expanded capability inventory; bounded CLI startup smoke; binary presence no longer means ready | Templates, API credentials and target auth require separate validation |
| A13 | Isolated Bandit/Semgrep/SSLyze/Certipy installer and resolver; core pip check passes | Intel macOS Semgrep pinned below 1.183.0 because newer releases omit its engine |
| A14 | Local plugin package exports and global configuration aligned with local MCP tree; host reload completed and live MCP fingerprint matches disk | Loaded skills cannot be attested by disk configuration alone |
| A15 | Added 26 offline remediation tests and real HTTP callback test; actual SAST positive/negative smoke | Selected fixtures do not establish real-world recall across 209 tools |

Additional repairs: Gitleaks stdout report/redaction, FFUF JSONL, testssl JSON,
wordlist existence checks, Bandit severity/metrics, Semgrep error propagation and
custom-pattern language selection, CI manifest dependency installation.

## Verification

Run from repository root with `mcp/.venv/bin/python`:

- `-m pytest -q mcp/tests`: **377 passed, 1276 subtests passed**, 50 deprecation warnings.
- `-B scripts/run_offline_tests.py`: **344 tests OK**, outbound socket connections disabled.
- `scripts/benchmark_detectors.py --runs 1`: 42 cases; 36 scored, zero FP/FN on those selected cases; five intentional error cases and one incomplete excluded from scoring. SQLi uses actual HTTP/SQLite; other detector families use simulated HTTP responses.
- Actual Bandit 1.9.4 and Semgrep 1.182.1 adapters: one finding each on a synthetic `eval` file, zero on a `json.loads` control. Fixture source was scanned, not executed.
- SSLyze 6.0.0 and Certipy 5.1.0 startup/help checks exit 0; no TLS/AD target testing claimed.
- Core `pip check`: no broken requirements. `git diff --check`: clean.

## Usage changes

`sqli_detect` and `xss_detect` accept optional `request_json`: a JSON object with
`method`, `headers`, `cookies`, and either flat `json` or `data`. Destination is
always the scoped `target`. Supply session secrets through the host's appropriate
credential mechanism. Replay summaries redact recognized secret fields.

`authenticated_scan` requires an identity-specific `verification_marker` found on
the target in the authenticated response but absent from the anonymous control.
Missing verification gives unverified/incomplete, not authenticated success.

`pentest_workflow(execute=True)` executes supported explicit HTTP steps within a
180-second workflow budget. It requires an already authorized engagement and checks
every supported destination. It does not resolve conditions, authorize itself,
create tickets or run unsupported exploit steps. Inspect every skipped/partial step.

OAST: `start` → `generate` → receive HTTP callback → `poll` → `stop`.
`start` returns the ephemeral loopback listener port. For remote targets, configure
`CYBERSEC_OAST_PUBLIC_URL` and forwarding to that listener; reachability is labelled
unverified until a callback actually arrives. DNS and third-party polling are not supported.

## Local activation

Global OpenCode configuration now references `file:///Users/aaa/Documents/Developer/cybersec`.
A backup was retained as `opencode.json.bak-cybersec-remediation-20261104`.
The host was reloaded after implementation. The connected MCP subsequently reported
209 tools and `files_on_disk.mcp_vs_startup: match`, confirming the new process's
startup source fingerprint matches the working tree.

Existing user-owned `mcp/wrapper.py` and `mcp/wrapper.sh` are preserved outside this
change set. Subsequent user-authorized production smoke testing is documented in
`NUSAIBA-SMOKE-2026-11-04.md`; it is not a full production vulnerability assessment.
