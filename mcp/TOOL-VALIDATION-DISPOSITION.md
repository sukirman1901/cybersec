# 209-tool validation disposition — 2026-11-04

**Catalog accounting is complete; operational validation is not.** This read-only assessment runs no scanner, network probe, external CLI, cloud/AD action or test suite. The only generated files are this report and its optional generator. Existing evidence below is attributed to repository records, not freshly reproduced.

## Counts and evidence boundary

- **209/209** inventory registrations have a disposition and mapped implementation(s). **170** have static test-reference candidates; **39** have none in the supplied inventory.
- **148** tools have individually attributable documented execution evidence of some kind in the reviewed records; **61** have no individually attributed execution established by this review. The latter is an evidence gap, not proof they never ran.
- The historical ledger attributes 26 selected fixture/smoke tools, 2 dependency startup-only checks and one runtime diagnostic. The newer `offline-tool-execution.json` separately records actual mapped entry calls with test IDs; overlapping sets must not be added together.
- Historical production smoke, local integrations and current mocked entry traces are different evidence classes. A called function is not proof that every action, external service or platform works.
- Latest verification counts and cycle-specific limits are in `TUNING-PROGRESS.md`. This report generator reads those records; it does not execute tests. The separate runtime trace includes its own test count and success status.
- The ledger's older **98 referenced / 111 unreferenced** baseline is stale relative to the supplied inventory. Inventory references can include mocks, strings and generic contract cases. Current tree changes after the inventory snapshot are not silently added to these counts.
- Input inventory SHA-256: `8e7f7f562c3559c65525e01af97fba7296a33294b1d42c020e00df185b98e823`. All module paths below come from that inventory; source dependency hints are a separate static read of the current tree.

## How to read each row

`None attributed` means no per-tool execution in the reviewed logs/ledger, even if broad suites passed. Test-reference paths are static candidate evidence only. Group routes specify exact **proposed** test module names; they are not claims that those modules already exist. Existing exact test modules are listed per row. Source import/resolver hints can cover a shared module rather than a specific function, are not exhaustive dynamic dependencies, and do not attest installation. Operational prerequisites are requirements, not available-lab claims.

Concrete test-source examples: `test_tool_policy.py::TestToolKinds` checks dispatch authorization for named tools without executing those scanners; `test_core_tools.py::TestWhois` checks only domain normalization; `test_remediation_20261104.py::AuditRegression::test_cli_json_output_channels` patches CLI execution. These references must not become operational pass marks. Conversely, the local fixture integration defined in `test_core_tools.py` is an executable candidate, but its definition alone is not a dated per-tool execution log.

## Validation groups and exact next test modules

All next steps start with offline fixtures/mocks. Existing reference modules can be extended or the named proposed group module added. No new approval is needed to continue these offline engineering steps; a future operational run still needs its scoped environment and authorization. Do not turn missing credentials/labs into a false pass.

| Group | Tools | Proposed module under mcp/tests/ | Operational dependencies | Locally executable next validation / blocked operational work |
|---|---:|---|---|---|
| AD | 9 | `test_validation_ad_adapters.py` | Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable | Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab |
| CLOUD | 7 | `test_validation_cloud_adapters.py` | Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes | Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available |
| DEVICE | 2 | `test_validation_device_adapters.py` | Frida/Objection CLI and attached authorized iOS device/app with compatible instrumentation | Mock CLI output, missing device, timeout and redaction; runtime coverage blocked on device lab |
| ARTIFACT | 14 | `test_validation_artifacts.py` | Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks | Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain |
| LOCAL | 31 | `test_validation_local_utilities.py` | Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed | Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation |
| CLI | 19 | `test_validation_cli_adapters.py` | Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners | Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service |
| INTEL | 22 | `test_validation_intel_adapters.py` | DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here | Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths |
| INTEGRATION | 3 | `test_validation_integrations.py` | Dedicated GitHub/Jira/webhook sandbox and least-privilege test credentials for delivery | Mock payload/auth/status/retry/redaction contracts; delivery blocked on configured sandbox, never send real tickets/notifications in this review |
| PROTOCOL | 14 | `test_validation_protocols.py` | Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof | Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified |
| AUTH | 11 | `test_validation_auth_flows.py` | Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks | Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success |
| AI | 8 | `test_validation_ai_adapters.py` | Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle | Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab |
| ORCHESTRATION | 7 | `test_validation_orchestration.py` | Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments | Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof |
| OAST | 5 | `test_validation_oast.py` | Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector | Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established |
| HTTP | 57 | `test_validation_http_detectors.py` | Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition | Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof |

## High-priority feasible omissions

1. **Response-recognition gaps:** host_header_injection, sharepoint_scan and broader wordpress/redirect/parameter coverage. CRLF, CORS, misplaced files, webshell and WAF now have selected offline suites; their declared unsupported surfaces still remain gaps. Existing exact test modules below are the first regression entry points.
2. **Offline utilities:** phone_osint parsing and broader reporting/action coverage. Cycles 2–3 add hash/GF/report utilities and temporary-store regression suites for HTTP logs and vulnerability DBs. Concurrency/crash durability remains unverified. Selected cases do not cover every format or action.
3. **Adapter contracts:** missing executable, nonzero exit, malformed output, timeout cleanup, API errors and secret redaction for every CLI/provider adapter. Groups: `test_validation_cli_adapters.py`, `test_validation_cloud_adapters.py`, `test_validation_ad_adapters.py`, `test_validation_intel_adapters.py`. These are locally feasible without operational accounts; do not label mocked adapters production-validated.
4. **Auth/orchestration effect boundaries:** anonymous vs owner vs other-owner, expired identity, scope rejection, cancellation and partial child failure. Groups: `test_validation_auth_flows.py`, `test_validation_orchestration.py`. Actual BOLA/CSRF/state-change proof needs the controlled app oracle.
5. **Artifact fixture breadth:** four desktop scanners now have malformed archive/plist/manifest, symlink-swap, bounded-read and redaction fixtures in `test_artifact_accuracy.py`. Other native/mobile formats and platform execution remain separate gaps. No need to inspect personal installed apps or execute generated payloads.

## Concrete remaining completion blockers

- No evidence-backed operational fixture/environment is supplied for every one of the 209 tools. Offline fixture implementation and per-case execution records are still work, not blocked by a need to ask per batch.
- AD: isolated DC, Kerberos/LDAP/SMB services, role-specific accounts, AD CS/relay topology and disposable state. Cloud: disposable tenant/buckets/IAM, credentials and expected policies; Docker/Kubernetes require controlled clusters. iOS runtime: device, app and compatible Frida/Objection setup.
- CLI: executable/version availability is not scanner readiness; rules/templates/feed/API keys, wordlists, OS/privileges and known-positive/negative target fixtures remain necessary. SSLyze/Certipy help success is not a target test.
- External intelligence and notifications: live service availability, quotas, authenticated sandbox credentials and versioned response contracts; offline replay can validate parsing but not current API interoperability or delivery.
- Stateful/browser/model exploits: disposable multi-user applications, browser effect oracle, controlled models/agents with bounded cost, callback reachability, protocol front/back-end topology, reset/cleanup and state-change observations. XSS reflection, generated code, plan steps, vulnerability scoring and simulated OAST are not exploit execution.
- SQLi coverage is SQLite-specific; other DB engines, timing/UNION and broader contexts remain unmeasured. CSRF benchmark has no exploitable-positive fixture; SSRF mocks do not perform server-side fetches. Real network p95, RSS, request budgets and field precision/recall remain unmeasured across the catalog.
- Fresh post-fix smoke/retest evidence and source/runtime provenance are missing for the production-observed fixes. Historical aggregate suite counts cannot be upgraded to current per-tool execution without a case-to-tool ledger and run artifacts.

## Exhaustive tool disposition

Dependencies and next validations inherit the named group above; each row adds source-derived dependency hints and the tool-specific function description. `Static refs` always means references, never observed execution.

### 001. `ad_asrep_roast` — AD
- **Mapped module:** `mcp/cyber_tools/ad_asrep_roast.py`.
- **Declared scope:** ASREP Roasting — request AS-REP tickets for accounts with DONT_REQUIRE_PREAUTH and return crackable hashes.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket, pyasn1.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 002. `ad_certipy` — AD
- **Mapped module:** `mcp/cyber_tools/ad_certipy.py`.
- **Declared scope:** AD CS abuse via Certipy — enumerate certificate services (ESC1-15), request certificates, PKINIT auth, shadow credentials. Actions: find, req, auth, shadow.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** REMEDIATION-2026-11.md §Verification: dependency CLI startup/help only (SSLyze 6.0.0 / Certipy 5.1.0); public tool operational execution NOT established
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 003. `ad_dcsync` — AD
- **Mapped module:** `mcp/cyber_tools/ad_dcsync.py`.
- **Declared scope:** DCSync — extract password hashes from domain controller via DRSUAPI replication. Requires Domain Admin privileges.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 004. `ad_enum` — AD
- **Mapped module:** `mcp/cyber_tools/ad_enum.py`.
- **Declared scope:** Comprehensive Active Directory enumeration via LDAP — users, groups, computers, trusts, password policy.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 005. `ad_kerberoast` — AD
- **Mapped module:** `mcp/cyber_tools/ad_kerberoast.py`.
- **Declared scope:** Kerberoasting — request TGS tickets for SPN accounts and return crackable hashes (hashcat format).
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket, pyasn1.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 006. `ad_ntlm_relay` — AD
- **Mapped module:** `mcp/cyber_tools/ad_ntlm_relay.py`.
- **Declared scope:** NTLM Relay — set up relay server to capture and relay NTLM authentications to target systems via ntlmrelayx.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket; literal resolver names: ntlmrelayx.py.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 007. `ad_passthehash` — AD
- **Mapped module:** `mcp/cyber_tools/ad_passthehash.py`.
- **Declared scope:** Pass-the-Hash — execute commands on remote targets using NTLM hash authentication. Protocols: smbexec, wmiexec, atexec, psexec.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 008. `ad_spray` — AD
- **Mapped module:** `mcp/cyber_tools/ad_spray.py`.
- **Declared scope:** Password spraying — test a single password against multiple AD accounts while respecting lockout policy.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): import roots: impacket.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 009. `amass_enum` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Attack surface mapping. Requires amass CLI.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 010. `api_auth` — AUTH
- **Mapped module:** `mcp/cyber_tools/api_auth.py`.
- **Declared scope:** Test API auth bypass — no auth, basic, bearer fake, internal headers.
- **Static refs:** `mcp/tests/test_auth_surface_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 15 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 011. `api_fuzz` — HTTP
- **Mapped module:** `mcp/cyber_tools/api_fuzz.py`.
- **Declared scope:** Fuzz a web target for common API endpoints and swagger docs.
- **Static refs:** `mcp/tests/test_discovery_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 3 + discovery-benchmark.json: selected synthetic HTTP cases, explicitly partial discovery; offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 012. `apk_analyze` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/apk_analyze.py`.
- **Declared scope:** Analyze APK file — permissions, exported activities, package name, suspicious files.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_mobile_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 013. `approval_artifact` — LOCAL
- **Mapped module:** `mcp/cyber_tools/approval_artifact.py`.
- **Declared scope:** Approval artifact — digital approval/signature before destructive actions.
- **Static refs:** `mcp/tests/test_detector_accuracy.py`; `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 2 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 014. `asn_lookup` — INTEL
- **Mapped module:** `mcp/cyber_tools/asn_lookup.py`.
- **Declared scope:** Look up ASN information for an IP address via Team Cymru.
- **Static refs:** `mcp/tests/test_intel_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 015. `attack_surface_map` — LOCAL
- **Mapped module:** `mcp/cyber_tools/attack_surface.py`.
- **Declared scope:** Build an attack surface map from aggregated scan results. Accepts JSON string with results from port_scan, dns_lookup, subdomain_enum, http_probe, vuln_scan, etc.
- **Static refs:** `mcp/tests/test_store_report_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 016. `auth_macro_runner` — AUTH
- **Mapped module:** `mcp/cyber_tools/auth_macro_runner.py`.
- **Declared scope:** Multi-step auth macro runner — form login, basic auth, bearer token, custom step chains with cookie persistence.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 017. `authenticated_scan` — AUTH
- **Mapped module:** `mcp/cyber_tools/authenticated_scan.py`.
- **Declared scope:** Inspect authenticated content after identity-specific verification_marker and anonymous control. Endpoint accessibility alone is not IDOR. Cookies/headers are JSON objects.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 018. `auto_exploit` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/auto_exploit.py`.
- **Declared scope:** Auto-exploit chain: detect → verify → vuln_validate → exploit. Requires approved approval_id. vuln_type: auto, sqli, xss, lfi, ssrf, open_redirect.
- **Static refs:** `mcp/tests/test_detector_accuracy.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 3 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 019. `bandit_scan` — CLI
- **Mapped module:** `mcp/cyber_tools/bandit_scan.py`.
- **Declared scope:** Run bandit SAST scanner on Python codebase.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** REMEDIATION-2026-11.md §Verification: actual adapters, one synthetic eval positive and json.loads negative; selected rules only; offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): literal resolver names: bandit.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 020. `binary_checksec` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/binary_checksec.py`.
- **Declared scope:** Analyze binary security — ELF/Mach-O/PE, PIE, NX, linked libs, interesting strings.
- **Static refs:** `mcp/tests/test_source_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 12 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 021. `bloodhound_collect` — AD
- **Mapped module:** `mcp/cyber_tools/bloodhound_collect.py`.
- **Declared scope:** Collect AD data for BloodHound analysis. Requires bloodhound-python CLI.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab. Proposed exact group module: `mcp/tests/test_validation_ad_adapters.py`; existing exact regression modules are the static refs above.

### 022. `branded_report` — LOCAL
- **Mapped module:** `mcp/cyber_tools/branded_report.py`.
- **Declared scope:** White-label pentest reports — custom logo, colors, company name, footer, disclaimer.
- **Static refs:** `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_store_report_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 023. `browser_agent_hijack` — AI
- **Mapped module:** `mcp/cyber_tools/browser_agent_hijack.py`.
- **Declared scope:** Test browser-based AI agents for hijack — prompt injection via web content, hidden forms, autofill, clickjacking.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 024. `bulk_scan` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/bulk_scan.py`.
- **Declared scope:** Scan multiple targets at once. Targets: comma or newline separated. Tool: port_scan, http_probe, ssl_check, vuln_scan. Max 50 targets.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 2 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 025. `bypass_403` — HTTP
- **Mapped module:** `mcp/cyber_tools/bypass_403.py`.
- **Declared scope:** Test 403 bypass techniques (headers, path, method).
- **Static refs:** `mcp/tests/test_auth_surface_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 15 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 026. `cache_poison_check` — HTTP
- **Mapped module:** `mcp/cyber_tools/cache_poison_check.py`.
- **Declared scope:** Web cache poisoning detection — header manipulation, cache key injection, cache deception, scheme bypass.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 027. `captcha_test` — AI
- **Mapped module:** `mcp/cyber_tools/captcha_test.py`.
- **Declared scope:** Test CAPTCHA bypass — 10 vectors: token reuse, OCR, math solving, header/cookie bypass, hCaptcha/Turnstile detection. action: all|reuse|ocr|math|header|cookie|recaptcha|detect
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: PIL, httpx, pytesseract.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 028. `ci_cd_scan` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/ci_cd_scan.py`.
- **Declared scope:** Scan CI/CD configs — GitHub Actions, GitLab CI, Jenkins, CircleCI, secrets exposure.
- **Static refs:** `mcp/tests/test_integration_adapter_accuracy.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 029. `cleanup_tracking` — LOCAL
- **Mapped module:** `mcp/cyber_tools/cleanup_tracking.py`.
- **Declared scope:** Cleanup tracking — log modifications, generate cleanup scripts, track artifact state.
- **Static refs:** `mcp/tests/test_local_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 030. `cloud_audit` — CLOUD
- **Mapped module:** `mcp/cyber_tools/cloud_audit.py`.
- **Declared scope:** Comprehensive cloud security audit — S3 public, K8s API, Docker socket, IAM, infra recommendations.
- **Static refs:** `mcp/tests/test_cloud_adapter_accuracy.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 031. `cloud_enum` — CLOUD
- **Mapped module:** `mcp/cyber_tools/cloud_enum.py`.
- **Declared scope:** Enumerate cloud storage resources (AWS S3, Azure, GCP) for a company name.
- **Static refs:** `mcp/tests/test_cloud_adapter_accuracy.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 032. `cloud_iam_audit` — CLOUD
- **Mapped module:** `mcp/cyber_tools/cloud_iam_audit.py`.
- **Declared scope:** Audit cloud IAM policies — overly permissive roles, public access, cross-account trust.
- **Static refs:** `mcp/tests/test_cloud_adapter_accuracy.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): literal resolver names: aws, gcloud, prowler.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 033. `cloud_infra` — CLOUD
- **Mapped module:** `mcp/cyber_tools/cloud_infra.py`.
- **Declared scope:** Enumerate cloud infra config — open security groups, unencrypted storage, public endpoints.
- **Static refs:** `mcp/tests/test_cloud_adapter_accuracy.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): literal resolver names: aws, az, scoutsuite.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 034. `cmd_injection` — HTTP
- **Mapped module:** `mcp/cyber_tools/cmd_injection.py`.
- **Declared scope:** Test for command injection (semicolon, pipe, subshell, etc).
- **Static refs:** `mcp/tests/test_core_tools.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 035. `cmd_oast_helper` — OAST
- **Mapped module:** `mcp/cyber_tools/cmd_oast_helper.py`.
- **Declared scope:** Command injection OAST helper — blind CMD testing with OOB callback correlation and time-based detection.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established. Proposed exact group module: `mcp/tests/test_validation_oast.py`; existing exact regression modules are the static refs above.

### 036. `cmseek_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** CMS detection and version identification. Requires cmseek CLI.
- **Static refs:** `mcp/tests/test_cli_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 037. `compliance_map` — LOCAL
- **Mapped module:** `mcp/cyber_tools/compliance_map.py`.
- **Declared scope:** Map findings to compliance frameworks: SOC2, ISO27001, GDPR, PCI-DSS, NIST 800-53.
- **Static refs:** `mcp/tests/test_local_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 038. `continuous_monitor` — LOCAL
- **Mapped module:** `mcp/cyber_tools/continuous_monitor.py`.
- **Declared scope:** Monitor a target for changes over time. Actions: record, history, diff, stats, clear. Stores snapshots and detects changes.
- **Static refs:** `mcp/tests/test_integration_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 039. `cookie_audit` — HTTP
- **Mapped module:** `mcp/cyber_tools/cookie_audit.py`.
- **Declared scope:** Audit cookie security — HttpOnly, Secure, SameSite, sensitive cookies.
- **Static refs:** `mcp/tests/test_accuracy_tuning.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 1: targeted offline regressions documented; NUSAIBA-SMOKE-2026-11-04.md §§Execution evidence/Scanner defects: pre-fix smoke calls, defects recorded; no post-fix live retest; offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 040. `cookie_editor` — AUTH
- **Mapped module:** `mcp/cyber_tools/cookie_editor.py`.
- **Declared scope:** Decode, forge, and test cookie manipulation — base64/JSON decode, privilege escalation.
- **Static refs:** `mcp/tests/test_local_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 041. `cors_check` — HTTP
- **Mapped module:** `mcp/cyber_tools/cors_check.py`.
- **Declared scope:** Test for CORS misconfiguration. preset: observe-first (default, bounded) or staging-deep.
- **Static refs:** `mcp/tests/test_cors_accuracy.py`; `mcp/tests/test_pipeline_quality.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 042. `crlf_inject` — HTTP
- **Mapped module:** `mcp/cyber_tools/crlf_inject.py`.
- **Declared scope:** CRLF injection — inject HTTP headers via \r\n in parameters, response splitting, log forgery, redirect injection.
- **Static refs:** `mcp/tests/test_crlf_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 11 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 043. `crt_search` — INTEL
- **Mapped module:** `mcp/cyber_tools/crt_search.py`.
- **Declared scope:** Search Certificate Transparency logs for certificates.
- **Static refs:** `mcp/tests/test_intel_adapter_accuracy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 044. `csp_analyze` — HTTP
- **Mapped module:** `mcp/cyber_tools/csp_analyze.py`.
- **Declared scope:** Analyze Content-Security-Policy header + other security headers.
- **Static refs:** `mcp/tests/test_accuracy_tuning.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 1: targeted offline regressions documented; NUSAIBA-SMOKE-2026-11-04.md §§Execution evidence/Scanner defects: pre-fix smoke calls, defects recorded; no post-fix live retest; offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 045. `csrf_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/csrf_detect.py`.
- **Declared scope:** Check forms for CSRF tokens, SameSite cookies, and Origin/Referer validation.
- **Static refs:** `mcp/tests/test_csrf_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 5 + csrf-benchmark.json: read-only synthetic observations; exploitable-CSRF recall unmeasured; offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 046. `csrf_extract` — AUTH
- **Mapped module:** `mcp/cyber_tools/csrf_extract.py`.
- **Declared scope:** Extract and analyze anti-CSRF tokens from meta tags, hidden inputs, JS variables, cookies, headers.
- **Static refs:** `mcp/tests/test_tool_policy.py`; `mcp/tests/test_web_observation_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 047. `custom_wordlist` — LOCAL
- **Mapped module:** `mcp/cyber_tools/custom_wordlist.py`.
- **Declared scope:** Custom wordlist manager. Actions: create, list, show, delete, merge, generate, import, builtin, append.
- **Static refs:** `mcp/tests/test_local_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 048. `cve_search` — INTEL
- **Mapped module:** `mcp/cyber_tools/vuln_db.py`.
- **Declared scope:** Look up known CVEs by service/version, including offline PHP2SHELL version correlation (not verified RCE).
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_core_tools.py`; `mcp/tests/test_php2shell.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 049. `desktop_config` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/desktop_config.py`.
- **Declared scope:** Scan for exposed config files and saved credentials in desktop apps.
- **Static refs:** `mcp/tests/test_desktop_config_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 050. `desktop_electron` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/desktop_electron.py`.
- **Declared scope:** Analyze Electron app — ASAR unpack, preload inspection, IPC safety.
- **Static refs:** `mcp/tests/test_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 17 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 051. `desktop_entitlements` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/desktop_entitlements.py`.
- **Declared scope:** Check macOS entitlements, Windows manifest, Linux capabilities in desktop apps.
- **Static refs:** `mcp/tests/test_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 11 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 052. `desktop_packages` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/desktop_packages.py`.
- **Declared scope:** Check bundled package versions in desktop apps for known CVEs.
- **Static refs:** `mcp/tests/test_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 14 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 053. `desktop_strings` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/desktop_strings.py`.
- **Declared scope:** Extract strings from desktop binaries — find secrets, API keys, URLs, IPs.
- **Static refs:** `mcp/tests/test_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 054. `dir_bruteforce` — HTTP
- **Mapped module:** `mcp/cyber_tools/web_fuzz.py`.
- **Declared scope:** Brute-force directories and files on a web target.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 055. `django_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/django_scan.py`.
- **Declared scope:** Django security scan — debug mode, SECRET_KEY, admin, session flags.
- **Static refs:** `mcp/tests/test_framework_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 4b + framework-benchmark.json: selected synthetic recognition cases; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 056. `dns_lookup` — INTEL
- **Mapped module:** `mcp/cyber_tools/dns_enum.py`.
- **Declared scope:** Enumerate DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME).
- **Static refs:** `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 057. `docker_scan` — CLOUD
- **Mapped module:** `mcp/cyber_tools/docker_scan.py`.
- **Declared scope:** Scan for Docker socket exposure, container escape paths, env leaks.
- **Static refs:** `mcp/tests/test_cloud_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 058. `dork_and_scan` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/dork_pipeline.py`.
- **Declared scope:** Bulk dork pipeline: generate dorks → search → list ALL websites → parallel vuln_scan/tech_detect/sqli_detect. scan_mode=hosts (unique domains) or urls (every URL). max_scan up to 50.
- **Static refs:** `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 059. `dork_gen` — LOCAL
- **Mapped module:** `mcp/cyber_tools/dork_gen.py`.
- **Declared scope:** Generate Google dorks for target discovery. Categories: vuln_sites, config_leak, admin_panels, db_dumps, backup_files, git_exposed, api_keys, iot_devices, login_portals, phpinfo, error_messages, upload_forms, exposed_cms, shell_upload, deface_target, s3_buckets, exposed_docs. Tech: wordpress, laravel, django, spring, nodejs, jenkins, gitlab, kibana, grafana. Vuln: sqli, lfi, xss, rce.
- **Static refs:** `mcp/tests/test_dork_generation_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 060. `dork_hunt` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/dork_hunt.py`.
- **Declared scope:** Full dorking pipeline: generate dorks → scan engines → HTTP probe → validate vulnerabilities. One-call target discovery — give a category, get back validated vulnerable URLs.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 061. `dork_scan` — INTEL
- **Mapped module:** `mcp/cyber_tools/dork_scan.py`.
- **Declared scope:** Execute dork queries via multiple search engines (DuckDuckGo, Bing, Google). Returns URLs found. Avoids CAPTCHA by using DDG HTML version + Bing.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx; environment variable names: SERPAPI_API_KEY.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 062. `dork_search` — INTEL
- **Mapped module:** `mcp/cyber_tools/google_dork.py`.
- **Declared scope:** Return search metadata; matches do not establish vulnerability or authorization.
- **Static refs:** `mcp/tests/test_dork_wrapper_accuracy.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_search_metadata_accuracy.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 063. `drupal_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/drupal_scan.py`.
- **Declared scope:** Drupal security scan — drupalgeddon, install.php, settings.php, jsonapi.
- **Static refs:** `mcp/tests/test_detector_accuracy.py`
- **Documented executed coverage:** DETECTOR-BENCHMARK.md §§Recorded before/after/Limits + REMEDIATION-2026-11.md §Verification: selected mocked HTTP cases; no browser/SSRF-fetch/CMS runtime effect; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 064. `email_osint` — INTEL
- **Mapped module:** `mcp/cyber_tools/email_osint.py`.
- **Declared scope:** Email intelligence — validate format, check MX records, domain reputation, Gravatar profile, and generate breach lookup URLs (HIBP, GhostProject, IntelligenceX). No paid APIs.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: dns, httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 065. `engagement_gate` — LOCAL
- **Mapped module:** `mcp/cyber_tools/engagement_gate.py`.
- **Declared scope:** Engagement gate — scope validation, authorization check, pre-flight approval rules.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_php2shell.py`; `mcp/tests/test_php2shell_remote.py`; `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_routing_eval.py`; `mcp/tests/test_sqli_mcp.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 37 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 066. `epss_lookup` — INTEL
- **Mapped module:** `mcp/cyber_tools/epss_lookup.py`.
- **Declared scope:** FIRST EPSS probability + percentile per CVE, plus CISA KEV membership and
- **Static refs:** `mcp/tests/test_epss_freshness.py`; `mcp/tests/test_epss_lookup.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_vuln_scan_epss_intel.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 11 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 067. `evidence_manifest` — LOCAL
- **Mapped module:** `mcp/cyber_tools/evidence_manifest.py`.
- **Declared scope:** Evidence manifest — SHA256 hash chain for court-admissible evidence integrity.
- **Static refs:** `mcp/tests/test_report_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 068. `executive_summary` — LOCAL
- **Mapped module:** `mcp/cyber_tools/executive_summary.py`.
- **Declared scope:** Auto-generate executive summary from findings JSON. Risk posture, severity breakdown, top findings, recommendations.
- **Static refs:** `mcp/tests/test_report_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 069. `exploit_db_detail` — INTEL
- **Mapped module:** `mcp/cyber_tools/exploit_db.py`.
- **Declared scope:** Get Exploit-DB exploit details — title, author, CVE, code, download link.
- **Static refs:** `mcp/tests/test_search_metadata_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 070. `exploit_db_download` — INTEL
- **Mapped module:** `mcp/cyber_tools/exploit_db.py`.
- **Declared scope:** Download exploit code from Exploit-DB by exploit ID.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 071. `exploit_db_search` — INTEL
- **Mapped module:** `mcp/cyber_tools/exploit_db.py`.
- **Declared scope:** Search Exploit-DB for public exploits by keyword, CVE, type (dos/local/remote/webapps), platform.
- **Static refs:** `mcp/tests/test_search_metadata_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 11 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 072. `exposed_backup` — HTTP
- **Mapped module:** `mcp/cyber_tools/exposed_backup.py`.
- **Declared scope:** Scan for exposed backup files (.bak, .old, .sql, .dump, ~, etc).
- **Static refs:** `mcp/tests/test_discovery_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 3 + discovery-benchmark.json: selected synthetic HTTP cases, explicitly partial discovery; offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 073. `exposed_git` — HTTP
- **Mapped module:** `mcp/cyber_tools/exposed_git.py`.
- **Declared scope:** Check for exposed .git folder — config, HEAD, logs, objects.
- **Static refs:** `mcp/tests/test_web_surface_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 2 + web-surface-benchmark.json: selected synthetic HTTP cases; no real target/runtime proof; offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 074. `express_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/express_scan.py`.
- **Declared scope:** Scan Express.js app — header disclosure, error handling, directory listing, exposed paths.
- **Static refs:** `mcp/tests/test_framework_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 4b + framework-benchmark.json: selected synthetic recognition cases; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 075. `ffuf_fuzz` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Fast web fuzzing. Requires ffuf CLI.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 076. `findings_manager` — LOCAL
- **Mapped module:** `mcp/cyber_tools/findings_manager.py`.
- **Declared scope:** Findings DB with novelty triage. Actions: add, novelty, triage, list, update, stats, export, clear.
- **Static refs:** `mcp/tests/test_novelty_engine.py`; `mcp/tests/test_pipeline_quality.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 3 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 077. `generate_report` — LOCAL
- **Mapped module:** `mcp/cyber_tools/report.py`.
- **Declared scope:** Generate a penetration testing report from findings JSON.
- **Static refs:** `mcp/tests/test_accuracy_tuning.py`; `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 1: targeted offline regressions documented; NUSAIBA-SMOKE-2026-11-04.md §§Execution evidence/Scanner defects: pre-fix smoke calls, defects recorded; no post-fix live retest; offline-tool-execution.json: mapped Python implementation entry observed in 2 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 078. `gf_patterns` — LOCAL
- **Mapped module:** `mcp/cyber_tools/gf_patterns.py`.
- **Declared scope:** Find sensitive patterns in URLs (debug, api, files, params).
- **Static refs:** `mcp/tests/test_gf_patterns_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 079. `ghdb_search` — INTEL
- **Mapped module:** `mcp/cyber_tools/ghdb_search.py`.
- **Declared scope:** Search Google Hacking Database (GHDB) for sensitive information dorks — files containing passwords, admin panels, directory listings.
- **Static refs:** `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_search_metadata_accuracy.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 16 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 080. `github_issue` — INTEGRATION
- **Mapped module:** `mcp/cyber_tools/github_issue.py`.
- **Declared scope:** Create GitHub issue from security finding. Requires repo (owner/repo) and token with repo scope.
- **Static refs:** `mcp/tests/test_integration_adapter_accuracy.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Dedicated GitHub/Jira/webhook sandbox and least-privilege test credentials for delivery. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock payload/auth/status/retry/redaction contracts; delivery blocked on configured sandbox, never send real tickets/notifications in this review. Proposed exact group module: `mcp/tests/test_validation_integrations.py`; existing exact regression modules are the static refs above.

### 081. `gitleaks_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Git secret scanning in a repository. Requires gitleaks CLI.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 082. `gobuster_dir` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Directory/file brute-forcing. Requires gobuster CLI.
- **Static refs:** `mcp/tests/test_cli_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 083. `graphql_depth_bypass` — HTTP
- **Mapped module:** `mcp/cyber_tools/graphql_depth_bypass.py`.
- **Declared scope:** GraphQL depth limit bypass — batching, alias attacks, circular fragments, resource exhaustion.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 084. `graphql_injection` — HTTP
- **Mapped module:** `mcp/cyber_tools/graphql_injection.py`.
- **Declared scope:** Test GraphQL endpoints — SQL injection, deep nesting, alias batching, introspection, auth bypass.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 085. `graphql_introspect` — HTTP
- **Mapped module:** `mcp/cyber_tools/graphql_introspect.py`.
- **Declared scope:** Test for GraphQL introspection endpoint.
- **Static refs:** `mcp/tests/test_web_surface_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 2 + web-surface-benchmark.json: selected synthetic HTTP cases; no real target/runtime proof; offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 086. `hash_analyze` — LOCAL
- **Mapped module:** `mcp/cyber_tools/hash_analyze.py`.
- **Declared scope:** Identify hash type from its format (MD5, SHA1, bcrypt, NTLM, etc).
- **Static refs:** `mcp/tests/test_offline_crypto_accuracy.py`; `mcp/tests/test_routing_eval.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 087. `hash_detect` — LOCAL
- **Mapped module:** `mcp/cyber_tools/hash_detect.py`.
- **Declared scope:** Identify hash type from format — MD5, SHA1/256/512, bcrypt, NTLM, argon2, and 20+ more.
- **Static refs:** `mcp/tests/test_hash_detect_accuracy.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 088. `host_header_injection` — HTTP
- **Mapped module:** `mcp/cyber_tools/host_header.py`.
- **Declared scope:** Test host header injection — password reset poisoning, cache poison.
- **Static refs:** `mcp/tests/test_web_observation_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 089. `http_ingest` — LOCAL
- **Mapped module:** `mcp/cyber_tools/http_ingest.py`.
- **Declared scope:** HTTP ingest — parse URL, OpenAPI, HAR, Burp XML, raw HTTP, curl → standardized findings.
- **Static refs:** `mcp/tests/test_report_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 090. `http_logger` — LOCAL
- **Mapped module:** `mcp/cyber_tools/http_logger.py`.
- **Declared scope:** Persistent HTTP request/response logger. Actions: log, list, search, stats, export, clear.
- **Static refs:** `mcp/tests/test_store_report_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 11 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 091. `http_probe_target` — HTTP
- **Mapped module:** `mcp/cyber_tools/http_probe.py`.
- **Declared scope:** Probe HTTP/HTTPS service, detect technology stack and headers.
- **Static refs:** `mcp/tests/test_accuracy_tuning.py`; `mcp/tests/test_core_tools.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 1: targeted offline regressions documented; NUSAIBA-SMOKE-2026-11-04.md §§Execution evidence/Scanner defects: pre-fix smoke calls, defects recorded; no post-fix live retest; offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 092. `http_request_splitting` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/http_request_splitting.py`.
- **Declared scope:** HTTP request splitting — CRLF injection in headers, request line splitting, chunked encoding abuse.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 093. `hydra_brute` — CLI
- **Mapped module:** `mcp/cyber_tools/hydra_brute.py`.
- **Declared scope:** Online password brute forcing. Requires hydra CLI.
- **Static refs:** `mcp/tests/test_credential_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 094. `idor_access_validation` — AUTH
- **Mapped module:** `mcp/cyber_tools/idor_access_validation.py`.
- **Declared scope:** IDOR/BOLA validation with dual-role differential. Single-role enum is LOW confidence; both cookies/headers required for HIGH BOLA.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 3 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 095. `idor_detect` — AUTH
- **Mapped module:** `mcp/cyber_tools/idor_detect.py`.
- **Declared scope:** Test for Insecure Direct Object References by accessing sequential IDs.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 096. `injection_validator` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/injection_validator.py`.
- **Declared scope:** Unified injection validator — SQLi, XSS, NoSQL, CMD, LDAP, SSTI, XXE with multi-technique payloads.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 097. `ios_data_storage` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/ios_data_storage.py`.
- **Declared scope:** Check iOS app for insecure local data storage patterns.
- **Static refs:** `mcp/tests/test_mobile_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 098. `ios_frida` — DEVICE
- **Mapped module:** `mcp/cyber_tools/ios_frida.py`.
- **Declared scope:** Run frida on iOS device — SSL pinning bypass, method tracing, process list.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Frida/Objection CLI and attached authorized iOS device/app with compatible instrumentation. Source hints (not installation checks): literal resolver names: frida.
- **Next validation / blocker:** Mock CLI output, missing device, timeout and redaction; runtime coverage blocked on device lab. Proposed exact group module: `mcp/tests/test_validation_device_adapters.py`; existing exact regression modules are the static refs above.

### 099. `ios_objection` — DEVICE
- **Mapped module:** `mcp/cyber_tools/ios_objection.py`.
- **Declared scope:** Run objection iOS runtime exploration — keychain dump, sqlite, nsuserdefaults.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Frida/Objection CLI and attached authorized iOS device/app with compatible instrumentation. Source hints (not installation checks): literal resolver names: objection.
- **Next validation / blocker:** Mock CLI output, missing device, timeout and redaction; runtime coverage blocked on device lab. Proposed exact group module: `mcp/tests/test_validation_device_adapters.py`; existing exact regression modules are the static refs above.

### 100. `ios_signing` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/ios_signing.py`.
- **Declared scope:** Check iOS app signing — provisioning profile, team ID, ad-hoc vs distribution.
- **Static refs:** `mcp/tests/test_mobile_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 11 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 101. `ipa_analyze` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/ipa_analyze.py`.
- **Declared scope:** Analyze iOS IPA file — metadata, entitlements, plist, permissions.
- **Static refs:** `mcp/tests/test_mobile_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 102. `java_deserialize` — HTTP
- **Mapped module:** `mcp/cyber_tools/java_deserialize.py`.
- **Declared scope:** Check for Java deserialization endpoints, RMI, JNDI, and serialized data.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 103. `jira_create` — INTEGRATION
- **Mapped module:** `mcp/cyber_tools/jira_create.py`.
- **Declared scope:** Create a Jira issue from a security finding. Requires Jira URL, email, and API token.
- **Static refs:** `mcp/tests/test_integration_adapter_accuracy.py`; `mcp/tests/test_redirect_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Dedicated GitHub/Jira/webhook sandbox and least-privilege test credentials for delivery. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock payload/auth/status/retry/redaction contracts; delivery blocked on configured sandbox, never send real tickets/notifications in this review. Proposed exact group module: `mcp/tests/test_validation_integrations.py`; existing exact regression modules are the static refs above.

### 104. `joomla_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/joomla_scan.py`.
- **Declared scope:** Scan Joomla CMS — version, admin, components, plugins, exposed configs.
- **Static refs:** `mcp/tests/test_detector_accuracy.py`
- **Documented executed coverage:** DETECTOR-BENCHMARK.md §§Recorded before/after/Limits + REMEDIATION-2026-11.md §Verification: selected mocked HTTP cases; no browser/SSRF-fetch/CMS runtime effect; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 105. `jwt_analyze` — LOCAL
- **Mapped module:** `mcp/cyber_tools/jwt_analyze.py`.
- **Declared scope:** Decode and analyze a JWT token for security issues.
- **Static refs:** `mcp/tests/test_offline_crypto_accuracy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 16 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 106. `jwt_forgery` — AUTH
- **Mapped module:** `mcp/cyber_tools/jwt_forgery.py`.
- **Declared scope:** Test JWT for known attacks — none algorithm, weak secret, kid injection, algorithm confusion.
- **Static refs:** `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 107. `k8s_scan` — CLOUD
- **Mapped module:** `mcp/cyber_tools/k8s_scan.py`.
- **Declared scope:** Scan K8s API for unauthorized access, secrets exposure, RBAC issues.
- **Static refs:** `mcp/tests/test_cloud_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 108. `laravel_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/laravel_scan.py`.
- **Declared scope:** Scan Laravel app for .env leak, debug mode, artisan exposure. preset: observe-first|staging-deep.
- **Static refs:** `mcp/tests/test_pipeline_quality.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 109. `ldap_enum` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/ldap_enum.py`.
- **Declared scope:** LDAP anonymous bind and server enumeration.
- **Static refs:** `mcp/tests/test_remaining_protocol_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 110. `ldap_inject` — HTTP
- **Mapped module:** `mcp/cyber_tools/ldap_inject.py`.
- **Declared scope:** LDAP injection — test for LDAP query manipulation, auth bypass, error-based, boolean-blind, time-blind.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 111. `lfi_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/lfi_detect.py`.
- **Declared scope:** Test for Local/Remote File Inclusion vulnerabilities.
- **Static refs:** `mcp/tests/test_core_tools.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 112. `llm_agent_hijack` — AI
- **Mapped module:** `mcp/cyber_tools/llm_agent_hijack.py`.
- **Declared scope:** Test agent function call/tool injection in LLM.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 113. `llm_data_exposure` — AI
- **Mapped module:** `mcp/cyber_tools/llm_data_exposure.py`.
- **Declared scope:** Test for training data leakage (PII exposure) from LLM.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 114. `llm_guardrails` — AI
- **Mapped module:** `mcp/cyber_tools/llm_guardrails.py`.
- **Declared scope:** Check if LLM output is sanitized against XSS and event handlers.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 115. `llm_model_dos` — AI
- **Mapped module:** `mcp/cyber_tools/llm_model_dos.py`.
- **Declared scope:** Test LLM for DoS via excessive token generation.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 116. `log4j_scan` — OAST
- **Mapped module:** `mcp/cyber_tools/log4j_scan.py`.
- **Declared scope:** Test for Log4j JNDI injection via headers and params.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established. Proposed exact group module: `mcp/tests/test_validation_oast.py`; existing exact regression modules are the static refs above.

### 117. `log_exposure` — HTTP
- **Mapped module:** `mcp/cyber_tools/log_exposure.py`.
- **Declared scope:** Scan for exposed log files — access logs, error logs, debug logs with sensitive data.
- **Static refs:** `mcp/tests/test_discovery_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 3 + discovery-benchmark.json: selected synthetic HTTP cases, explicitly partial discovery; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 118. `magento_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/magento_scan.py`.
- **Declared scope:** Magento security scan — admin, downloader, local.xml, system.log.
- **Static refs:** `mcp/tests/test_detector_accuracy.py`
- **Documented executed coverage:** DETECTOR-BENCHMARK.md §§Recorded before/after/Limits + REMEDIATION-2026-11.md §Verification: selected mocked HTTP cases; no browser/SSRF-fetch/CMS runtime effect; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 119. `mass_assignment` — AUTH
- **Mapped module:** `mcp/cyber_tools/mass_assignment.py`.
- **Declared scope:** Mass assignment / overposting — test for parameter overwriting in APIs, privilege escalation.
- **Static refs:** `mcp/tests/test_rails_accuracy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 120. `masscan_scan` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Ultra-fast TCP port scanner. Requires masscan CLI.
- **Static refs:** `mcp/tests/test_cli_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 121. `mcp_abuse_test` — AI
- **Mapped module:** `mcp/cyber_tools/mcp_abuse_test.py`.
- **Declared scope:** Test MCP server for abuse vectors — dangerous tools, JSON-RPC injection, prompt injection in tool descriptions.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 122. `metrics_check` — HTTP
- **Mapped module:** `mcp/cyber_tools/metrics_check.py`.
- **Declared scope:** Check for exposed metrics endpoints — Prometheus, Actuator, debug, health.
- **Static refs:** `mcp/tests/test_metrics_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 4a: documented offline recognition regressions; no app execution; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 123. `misplaced_files` — HTTP
- **Mapped module:** `mcp/cyber_tools/misplaced_files.py`.
- **Declared scope:** Scan for misplaced sensitive files — signatures, certs, configs, backups.
- **Static refs:** `mcp/tests/test_remaining_http_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 124. `nextjs_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/nextjs_scan.py`.
- **Declared scope:** Next.js security scan — source maps, data endpoints, SSR misconfig.
- **Static refs:** `mcp/tests/test_web_surface_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 2 + web-surface-benchmark.json: selected synthetic HTTP cases; no real target/runtime proof; offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 125. `nikto_scan` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Web server vulnerability scanner. Requires nikto CLI.
- **Static refs:** `mcp/tests/test_detector_accuracy.py`; `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 2 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 126. `nmap_scan` — CLI
- **Mapped module:** `mcp/cyber_tools/nmap_scan.py`.
- **Declared scope:** Full nmap network scan with service detection. Requires nmap CLI.
- **Static refs:** `mcp/tests/test_cli_remaining_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 127. `nosql_inject` — HTTP
- **Mapped module:** `mcp/cyber_tools/nosql_inject.py`.
- **Declared scope:** Test for NoSQL injection (MongoDB $ne, $gt, $where payloads).
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 128. `notify_webhook` — INTEGRATION
- **Mapped module:** `mcp/cyber_tools/notify_webhook.py`.
- **Declared scope:** Send finding notifications to Slack/Discord/Teams webhook. Auto-detects platform from URL.
- **Static refs:** `mcp/tests/test_integration_adapter_accuracy.py`; `mcp/tests/test_redirect_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Dedicated GitHub/Jira/webhook sandbox and least-privilege test credentials for delivery. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock payload/auth/status/retry/redaction contracts; delivery blocked on configured sandbox, never send real tickets/notifications in this review. Proposed exact group module: `mcp/tests/test_validation_integrations.py`; existing exact regression modules are the static refs above.

### 129. `nuclei_scan` — CLI
- **Mapped module:** `mcp/cyber_tools/nuclei_scan.py`.
- **Declared scope:** Template-based vulnerability scanner. Requires nuclei CLI.
- **Static refs:** `mcp/tests/test_novelty_engine.py`; `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 130. `oast_callback_server` — OAST
- **Mapped module:** `mcp/cyber_tools/oast_callback_server.py`.
- **Declared scope:** HTTP callback collector: start, generate, poll, status, clear, stop. Binds loopback; CYBERSEC_OAST_PUBLIC_URL may advertise an operator-managed forwarding endpoint. No DNS or third-party polling.
- **Static refs:** `mcp/tests/test_oast_http_integration.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** REMEDIATION-2026-11.md A03/§Verification: real loopback HTTP callback round-trip; no DNS or remote callback proof; offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector. Source hints (not installation checks): environment variable names: CYBERSEC_OAST_PUBLIC_URL.
- **Next validation / blocker:** Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established. Proposed exact group module: `mcp/tests/test_validation_oast.py`; existing exact regression modules are the static refs above.

### 131. `oauth_scan` — AUTH
- **Mapped module:** `mcp/cyber_tools/oauth_scan.py`.
- **Declared scope:** Scan OAuth/OIDC endpoints — authorize, token, .well-known, redirect_uri.
- **Static refs:** `mcp/tests/test_web_observation_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 132. `oob_test` — OAST
- **Mapped module:** `mcp/cyber_tools/oob_test.py`.
- **Declared scope:** Test for blind OOB interaction (SSRF, RCE, template injection).
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established. Proposed exact group module: `mcp/tests/test_validation_oast.py`; existing exact regression modules are the static refs above.

### 133. `open_redirect` — HTTP
- **Mapped module:** `mcp/cyber_tools/open_redirect.py`.
- **Declared scope:** Test for open redirect vulnerabilities in common parameters.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 134. `origin_ip_discovery` — INTEL
- **Mapped module:** `mcp/cyber_tools/origin_ip_discovery.py`.
- **Declared scope:** Discover origin IP behind CDN via historical DNS and records.
- **Static refs:** `mcp/tests/test_discovery_intel_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 135. `param_discovery` — HTTP
- **Mapped module:** `mcp/cyber_tools/param_discovery.py`.
- **Declared scope:** Discover HTTP parameters by testing common parameter names.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 136. `password_audit` — AUTH
- **Mapped module:** `mcp/cyber_tools/password_audit.py`.
- **Declared scope:** Multi-protocol password audit — SSH, FTP, SMTP, HTTP form, RDP. Default wordlist included.
- **Static refs:** `mcp/tests/test_credential_adapter_accuracy.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks. Source hints (not installation checks): import roots: paramiko.
- **Next validation / blocker:** Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success. Proposed exact group module: `mcp/tests/test_validation_auth_flows.py`; existing exact regression modules are the static refs above.

### 137. `pentest_workflow` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/pentest_workflow.py`, `mcp/cyber_tools/workflow_runner.py`.
- **Declared scope:** Plan by default. execute=true runs supported HTTP detector steps with per-step scope checks, 180s budget, explicit skipped steps and normalized findings. No implicit approval, conditions, tickets or exploit actions. request_json preserves SQLi/XSS sessions/bodies.
- **Static refs:** `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 20 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 138. `people_osint` — INTEL
- **Mapped module:** `mcp/cyber_tools/people_osint.py`.
- **Declared scope:** Individual OSINT — GitHub profile, LinkedIn/Twitter/search, email analysis with Gravatar.
- **Static refs:** `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 139. `phone_osint` — LOCAL
- **Mapped module:** `mcp/cyber_tools/phone_osint.py`.
- **Declared scope:** Phone number intelligence — parse carrier, region, line type, timezones (offline via phonenumbers lib). Generates lookup URLs for Truecaller, GetContact, sync.me, and Google search.
- **Static refs:** `mcp/tests/test_phone_metadata_accuracy.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): import roots: phonenumbers.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 140. `php2shell_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/php2shell_remote.py`.
- **Declared scope:** Identify PHP2SHELL CVE-2026-109618/109619 on an authorized single origin.
- **Static refs:** `mcp/tests/test_php2shell_remote.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 31 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 141. `php_deserialize` — HTTP
- **Mapped module:** `mcp/cyber_tools/php_deserialize.py`.
- **Declared scope:** Check for PHP deserialization vulnerabilities via gadget chains.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 142. `pickle_deserialize` — HTTP
- **Mapped module:** `mcp/cyber_tools/pickle_deserialize.py`.
- **Declared scope:** Python pickle deserialization — detect and test for insecure deserialization, RCE confirmation.
- **Static refs:** `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 143. `port_scan` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/port_scanner.py`.
- **Declared scope:** Scan TCP ports on a target host.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_protocol_adapter_accuracy.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 144. `prompt_injection` — AI
- **Mapped module:** `mcp/cyber_tools/prompt_injection.py`.
- **Declared scope:** Test LLM endpoint for prompt injection vulnerability.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab. Proposed exact group module: `mcp/tests/test_validation_ai_adapters.py`; existing exact regression modules are the static refs above.

### 145. `prototype_pollution` — HTTP
- **Mapped module:** `mcp/cyber_tools/prototype_pollution.py`.
- **Declared scope:** Test for client-side/server-side prototype pollution via query params and JSON body.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 146. `race_condition` — HTTP
- **Mapped module:** `mcp/cyber_tools/race_condition.py`.
- **Declared scope:** Test for race conditions by sending parallel requests to sensitive endpoints.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 147. `rails_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/rails_scan.py`.
- **Declared scope:** Scan Ruby on Rails app — exposed configs, mass assignment, debug console, routes.
- **Static refs:** `mcp/tests/test_rails_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 4a: documented offline recognition regressions; no app execution; offline-tool-execution.json: mapped Python implementation entry observed in 6 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 148. `raw_replay` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/raw_replay.py`.
- **Declared scope:** Faithful raw HTTP request replay — send exact bytes, capture full response.
- **Static refs:** `mcp/tests/test_audit_regressions.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 149. `redis_enum` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/redis_enum.py`.
- **Declared scope:** Enumerate Redis server — check auth, keyspace, version.
- **Static refs:** `mcp/tests/test_remaining_protocol_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 150. `report_export` — LOCAL
- **Mapped module:** `mcp/cyber_tools/report_export.py`.
- **Declared scope:** Export pentest report to multiple formats: html, csv, markdown, json. HTML includes styled executive summary with severity color coding.
- **Static refs:** `mcp/tests/test_report_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 151. `report_schema_v2` — LOCAL
- **Mapped module:** `mcp/cyber_tools/report_schema_v2.py`.
- **Declared scope:** Report schema v2 — validate, convert v1→v2, merge, create standardized reports with evidence chain.
- **Static refs:** `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_sqli_evidence.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 2 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 152. `retest_vuln` — ORCHESTRATION
- **Mapped module:** `mcp/cyber_tools/retest_vuln.py`.
- **Declared scope:** Retest a previously found vulnerability to confirm if it's fixed. Supports: sqli, xss, lfi, ssrf, open_redirect, ssti, log4j.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof. Proposed exact group module: `mcp/tests/test_validation_orchestration.py`; existing exact regression modules are the static refs above.

### 153. `reverse_ip` — INTEL
- **Mapped module:** `mcp/cyber_tools/reverse_ip.py`.
- **Declared scope:** Find domains hosted on the same IP address.
- **Static refs:** `mcp/tests/test_intel_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 154. `risk_score` — LOCAL
- **Mapped module:** `mcp/cyber_tools/risk_score.py`.
- **Declared scope:** Calculate risk score for a vulnerability finding. Combines CVSS severity, business impact, and exploitability likelihood. asset_value: low, medium, high, critical.
- **Static refs:** `mcp/tests/test_report_utility_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 155. `s3_scanner` — CLOUD
- **Mapped module:** `mcp/cyber_tools/s3_scanner.py`.
- **Declared scope:** Check if an S3 bucket is publicly accessible and list its contents.
- **Static refs:** `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available. Proposed exact group module: `mcp/tests/test_validation_cloud_adapters.py`; existing exact regression modules are the static refs above.

### 156. `sast_review` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/sast_review.py`.
- **Declared scope:** Pattern-based code review — detect eval, deserialization, SQLi, XSS patterns.
- **Static refs:** `mcp/tests/test_source_artifact_accuracy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 157. `scan_template` — LOCAL
- **Mapped module:** `mcp/cyber_tools/scan_template.py`.
- **Declared scope:** Scan template combos. Defaults observe-first; also staging-deep, quick-recon, web-full, network-audit, api-security, cloud-audit, ad-pentest, code-audit, ctf.
- **Static refs:** `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 158. `searchsploit` — CLI
- **Mapped module:** `mcp/cyber_tools/searchsploit.py`.
- **Declared scope:** Search exploit-db for exploits. Requires searchsploit CLI.
- **Static refs:** `mcp/tests/test_cli_remaining_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 159. `secret_scanner` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/secret_scanner.py`.
- **Declared scope:** Regex + entropy-based secret scanning — API keys, tokens, passwords in code.
- **Static refs:** `mcp/tests/test_source_artifact_accuracy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 160. `semgrep_scan` — CLI
- **Mapped module:** `mcp/cyber_tools/semgrep_scan.py`.
- **Declared scope:** Run semgrep multi-language SAST — auto or custom pattern.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_routing_eval.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** REMEDIATION-2026-11.md §Verification: actual adapters, one synthetic eval positive and json.loads negative; selected rules only; offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): literal resolver names: semgrep.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 161. `service_fingerprint` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/service_fingerprint.py`.
- **Declared scope:** Deep service fingerprinting via banner grabbing.
- **Static refs:** `mcp/tests/test_protocol_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 162. `session_verification` — LOCAL
- **Mapped module:** `mcp/cyber_tools/session_verification.py`.
- **Declared scope:** Session verification — validate session cookies, tokens, expiry before testing.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 163. `sharepoint_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/sharepoint_scan.py`.
- **Declared scope:** Scan Microsoft SharePoint — version, exposed paths, web services, API endpoints.
- **Static refs:** `mcp/tests/test_web_observation_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 164. `shodan_lookup` — INTEL
- **Mapped module:** `mcp/cyber_tools/shodan_lookup.py`.
- **Declared scope:** Search Shodan for exposed devices and services.
- **Static refs:** `mcp/tests/test_intel_adapter_accuracy.py`; `mcp/tests/test_tool_policy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 165. `smb_enum` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/smb_enum.py`.
- **Declared scope:** Enumerate SMB services — check if port 445 is open.
- **Static refs:** `mcp/tests/test_remaining_protocol_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 166. `smtp_enum` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/smtp_enum.py`.
- **Declared scope:** Enumerate SMTP users via VRFY, EXPN, and RCPT commands.
- **Static refs:** `mcp/tests/test_remaining_protocol_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 167. `smuggling_check` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/smuggling_check.py`.
- **Declared scope:** Test for HTTP request smuggling (CL.TE, TE.CL).
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 168. `snmp_enum` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/snmp_enum.py`.
- **Declared scope:** Check SNMP service availability on port 161.
- **Static refs:** `mcp/tests/test_remaining_protocol_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 169. `social_osint` — INTEL
- **Mapped module:** `mcp/cyber_tools/social_osint.py`.
- **Declared scope:** Search for a username across 100+ social media platforms (Instagram, Twitter, TikTok, GitHub, Telegram, etc.). Sherlock-style — no API keys required. Returns found accounts with URLs and status codes.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 170. `spring_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/spring_scan.py`.
- **Declared scope:** Spring Boot actuator scan — env, heapdump, beans, mappings, configprops.
- **Static refs:** `mcp/tests/test_framework_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 4b + framework-benchmark.json: selected synthetic recognition cases; offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 171. `sqli_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/sqli_detect.py`.
- **Declared scope:** Controlled SQLi query or flat JSON/form probes. request_json: method, json/data, headers, cookies. preset observe-first or staging-deep. No extraction/timing.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_detector_accuracy.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_routing_eval.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_sqli_evidence.py`; `mcp/tests/test_sqli_mcp.py`; `mcp/tests/test_sqli_or_evidence.py`; `mcp/tests/test_sqli_sqlite_benchmark.py`
- **Documented executed coverage:** SQLI-EVIDENCE.md §Reproduce the benchmark + DETECTOR-BENCHMARK.md: 13 local HTTP/SQLite cases, repeated; no other DB/timing/UNION coverage; offline-tool-execution.json: mapped Python implementation entry observed in 38 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 172. `sqli_exploit` — LOCAL
- **Mapped module:** `mcp/cyber_tools/sqli_exploit.py`.
- **Declared scope:** Generate PoC SQL injection exploit payloads. Techniques: error-based, union-based, boolean, time-based, stacked.
- **Static refs:** `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 173. `sqlmap_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** SQL injection detection. Requires sqlmap CLI (safe mode default).
- **Static refs:** `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 174. `ssh_audit` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/ssh_audit.py`.
- **Declared scope:** Audit SSH server — grab banner and check algorithm support.
- **Static refs:** `mcp/tests/test_protocol_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 175. `ssl_check` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/ssl_analyzer.py`.
- **Declared scope:** Analyze SSL/TLS certificate and protocol security.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_protocol_adapter_accuracy.py`; `mcp/tests/test_routing_eval.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 176. `ssl_pinning_check` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/ssl_pinning_check.py`.
- **Declared scope:** Check SSL certificate details, HSTS, and cert verification behavior.
- **Static refs:** `mcp/tests/test_mobile_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 177. `sslyze_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** Fast SSL/TLS scanning. Requires sslyze CLI.
- **Static refs:** `mcp/tests/test_cli_adapter_accuracy.py`
- **Documented executed coverage:** REMEDIATION-2026-11.md §Verification: dependency CLI startup/help only (SSLyze 6.0.0 / Certipy 5.1.0); public tool operational execution NOT established; offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 178. `ssrf_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/ssrf_detect.py`.
- **Declared scope:** Test for Server-Side Request Forgery vulnerabilities.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_detector_benchmark.py`
- **Documented executed coverage:** DETECTOR-BENCHMARK.md §§Recorded before/after/Limits + REMEDIATION-2026-11.md §Verification: selected mocked HTTP cases; no browser/SSRF-fetch/CMS runtime effect; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 179. `ssti_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/ssti_detect.py`.
- **Declared scope:** Test for Server-Side Template Injection vulnerabilities.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 180. `stego_detect` — ARTIFACT
- **Mapped module:** `mcp/cyber_tools/stego_detect.py`.
- **Declared scope:** Detect hidden data in files — steganography, LSB, metadata anomalies, embedded strings.
- **Static refs:** `mcp/tests/test_mobile_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain. Proposed exact group module: `mcp/tests/test_validation_artifacts.py`; existing exact regression modules are the static refs above.

### 181. `sub_takeover` — INTEL
- **Mapped module:** `mcp/cyber_tools/sub_takeover.py`.
- **Declared scope:** Check for subdomain takeover (dangling DNS CNAME).
- **Static refs:** `mcp/tests/test_discovery_intel_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 4 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 182. `subdomain_enum` — INTEL
- **Mapped module:** `mcp/cyber_tools/subdomain_enum.py`.
- **Declared scope:** Passive subdomain enumeration via crt.sh, DNS brute-force, and APIs.
- **Static refs:** `mcp/tests/test_discovery_intel_accuracy.py`; `mcp/tests/test_redirect_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 183. `supply_chain` — HTTP
- **Mapped module:** `mcp/cyber_tools/supply_chain.py`.
- **Declared scope:** Check exposed manifest files for known vulnerable package versions.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_source_artifact_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 184. `tech_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/tech_detect.py`.
- **Declared scope:** Detect web technologies (CMS, JS frameworks, CDN, analytics) from HTTP response.
- **Static refs:** `mcp/tests/test_framework_accuracy.py`
- **Documented executed coverage:** TUNING-PROGRESS.md §Batch 4b + framework-benchmark.json: selected synthetic recognition cases; offline-tool-execution.json: mapped Python implementation entry observed in 5 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 185. `telegram_osint` — INTEL
- **Mapped module:** `mcp/cyber_tools/telegram_osint.py`.
- **Declared scope:** Gather public info about a Telegram user via t.me scraping — user ID, bio, profile photo, username history links (SangMata, TGStat). No Telegram API required.
- **Static refs:** `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 186. `testssl_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** SSL/TLS server testing. Requires testssl CLI.
- **Static refs:** `mcp/tests/test_cli_adapter_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 187. `tool_health` — CLI
- **Mapped module:** `mcp/cyber_tools/runtime_info.py`, `mcp/cyber_tools/tool_health.py`.
- **Declared scope:** Check CLI dependencies and read-only MCP startup source identity.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_routing_eval.py`; `mcp/tests/test_runtime_info.py`
- **Documented executed coverage:** REMEDIATION-2026-11.md §Local activation: connected MCP source fingerprint matched disk; readiness of all tools NOT established; offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 188. `upload_bypass` — HTTP
- **Mapped module:** `mcp/cyber_tools/upload_bypass.py`.
- **Declared scope:** Test file upload filters — PHP/JSP/ASP shell, double ext, null byte, SVG XSS.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 189. `upload_exploit_chain` — HTTP
- **Mapped module:** `mcp/cyber_tools/upload_exploit_chain.py`.
- **Declared scope:** Upload exploit-chain validation — upload (PHP/JSP/ASP/SVG/PY/SH) → verify accessibility → execute payload.
- **Static refs:** `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 190. `vhost_discovery` — HTTP
- **Mapped module:** `mcp/cyber_tools/vhost_discovery.py`.
- **Declared scope:** Discover virtual hosts by probing common subdomain vhosts via Host header manipulation.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 191. `vuln_database` — LOCAL
- **Mapped module:** `mcp/cyber_tools/vuln_database.py`.
- **Declared scope:** Local vulnerability database. Actions: add, get, search, list, update, delete, stats, export, import, tags, clear.
- **Static refs:** `mcp/tests/test_store_report_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 192. `vuln_diff` — LOCAL
- **Mapped module:** `mcp/cyber_tools/vuln_diff.py`.
- **Declared scope:** Offline diff of two stored scans (vulnerabilities/findings/open_ports).
- **Static refs:** `mcp/tests/test_novelty_engine.py`; `mcp/tests/test_vuln_diff_intel.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 13 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 193. `vuln_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/vuln_scanner.py`.
- **Declared scope:** Scan headers, exposed paths and CVE patterns; includes non-destructive PHP2SHELL header assessment.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_php2shell.py`; `mcp/tests/test_vuln_scan_epss_intel.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 194. `vuln_validate` — LOCAL
- **Mapped module:** `mcp/cyber_tools/vuln_validate.py`.
- **Declared scope:** Validate a vulnerability finding — confirm exploitability or flag as false positive. Accepts JSON with type, host, evidence, response.
- **Static refs:** `mcp/tests/test_audit_regressions.py`; `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 195. `vulnerable_fixture` — OAST
- **Mapped module:** `mcp/cyber_tools/vulnerable_fixture.py`.
- **Declared scope:** Vulnerable fixture — local vulnerable app for E2E tool validation. Actions: start, stop, status, endpoints, e2e, cleanup.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established. Proposed exact group module: `mcp/tests/test_validation_oast.py`; existing exact regression modules are the static refs above.

### 196. `waf_detection` — HTTP
- **Mapped module:** `mcp/cyber_tools/waf_detect.py`.
- **Declared scope:** Detect Web Application Firewall (WAF) protecting a target.
- **Static refs:** `mcp/tests/test_remaining_http_accuracy.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 197. `wayback_urls` — INTEL
- **Mapped module:** `mcp/cyber_tools/wayback_urls.py`.
- **Declared scope:** Fetch URL history from Wayback Machine.
- **Static refs:** `mcp/tests/test_intel_adapter_accuracy.py`; `mcp/tests/test_workflow_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 7 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 198. `webshell_connect` — HTTP
- **Mapped module:** `mcp/cyber_tools/webshell_connect.py`.
- **Declared scope:** Connect to an uploaded web shell and execute commands. Supports GET/POST, password auth, and extra parameters.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 199. `webshell_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/webshell_detect.py`.
- **Declared scope:** Detect web shells on a target via signature scanning. Checks common filenames and content patterns (c99, r57, weevely, china chopper, etc.).
- **Static refs:** `mcp/tests/test_remaining_http_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 200. `webshell_gen` — LOCAL
- **Mapped module:** `mcp/cyber_tools/webshell_gen.py`.
- **Declared scope:** Generate a web shell payload (PHP/JSP/ASP/ASPX). Types: cmd (command exec), eval (eval code), reverse (reverse shell). Optional obfuscation and password protection.
- **Static refs:** `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 201. `webshell_upload` — HTTP
- **Mapped module:** `mcp/cyber_tools/webshell_upload.py`.
- **Declared scope:** Upload a web shell to a target via file upload vulnerability. Auto-discovers upload endpoints and verifies shell accessibility.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 202. `websocket_test` — PROTOCOL
- **Mapped module:** `mcp/cyber_tools/websocket_test.py`.
- **Declared scope:** Test WebSocket endpoints — origin validation, CSWSH, Socket.IO detection.
- **Static refs:** `mcp/tests/test_web_observation_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 10 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified. Proposed exact group module: `mcp/tests/test_validation_protocols.py`; existing exact regression modules are the static refs above.

### 203. `whois_lookup` — INTEL
- **Mapped module:** `mcp/cyber_tools/whois_lookup.py`.
- **Declared scope:** Query WHOIS for domain registration information.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_discovery_intel_accuracy.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 12 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here. Source hints (not installation checks): literal resolver names: whois.
- **Next validation / blocker:** Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths. Proposed exact group module: `mcp/tests/test_validation_intel_adapters.py`; existing exact regression modules are the static refs above.

### 204. `wordpress_scan` — HTTP
- **Mapped module:** `mcp/cyber_tools/wordpress_scan.py`.
- **Declared scope:** Scan WordPress site — version, plugins, themes, XML-RPC, REST API, exposed paths.
- **Static refs:** `mcp/tests/test_novelty_engine.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 205. `wpscan_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** WordPress vulnerability scanner. Requires wpscan CLI.
- **Static refs:** `mcp/tests/test_remediation_20261104.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 1 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 206. `xss_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/xss_detect.py`.
- **Declared scope:** Bounded XSS HTTP reflection tests. request_json preserves flat json/data, headers and cookies. Authenticated body browser replay is not supported; reflection is not execution.
- **Static refs:** `mcp/tests/test_core_tools.py`; `mcp/tests/test_detector_benchmark.py`; `mcp/tests/test_pipeline_quality.py`; `mcp/tests/test_redirect_contract.py`; `mcp/tests/test_remediation_20261104.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** DETECTOR-BENCHMARK.md §§Recorded before/after/Limits + REMEDIATION-2026-11.md §Verification: selected mocked HTTP cases; no browser/SSRF-fetch/CMS runtime effect; offline-tool-execution.json: mapped Python implementation entry observed in 8 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx, playwright.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

### 207. `xss_exploit` — LOCAL
- **Mapped module:** `mcp/cyber_tools/xss_exploit.py`.
- **Declared scope:** Generate PoC XSS exploit payloads and steal links. Types: reflected, stored, dom_based, bypass_waf, cookie_steal.
- **Static refs:** `mcp/tests/test_skill_contract.py`; `mcp/tests/test_tool_policy.py`
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation. Proposed exact group module: `mcp/tests/test_validation_local_utilities.py`; existing exact regression modules are the static refs above.

### 208. `xsstrike_check` — CLI
- **Mapped module:** `mcp/cyber_tools/cli_tools.py`.
- **Declared scope:** XSS vulnerability detection. Requires xsstrike CLI.
- **Static refs:** `mcp/tests/test_cli_adapter_accuracy.py`; `mcp/tests/test_skill_contract.py`
- **Documented executed coverage:** offline-tool-execution.json: mapped Python implementation entry observed in 9 named test cases; dependencies may be mocked; not an operational pass
- **Dependencies:** Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners. Source hints (not installation checks): stdlib-only imports in mapped source.
- **Next validation / blocker:** Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service. Proposed exact group module: `mcp/tests/test_validation_cli_adapters.py`; existing exact regression modules are the static refs above.

### 209. `xxe_detect` — HTTP
- **Mapped module:** `mcp/cyber_tools/xxe_detect.py`.
- **Declared scope:** Test for XML External Entity injection vulnerabilities.
- **Static refs:** None in supplied inventory.
- **Documented executed coverage:** None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.
- **Dependencies:** Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition. Source hints (not installation checks): import roots: httpx.
- **Next validation / blocker:** Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof. Proposed exact group module: `mcp/tests/test_validation_http_detectors.py`; existing exact regression modules are the static refs above.

## Source records and reproducibility

Reviewed: `mcp/tool-coverage-inventory.json`, `scripts/tool_coverage_inventory.py`, mapped implementation ASTs, exact referenced test paths, `mcp/TUNING-PROGRESS.md`, `mcp/REMEDIATION-2026-11.md`, `mcp/DETECTOR-BENCHMARK.md`, `mcp/SQLI-EVIDENCE.md`, `mcp/NUSAIBA-SMOKE-2026-11-04.md`, and `mcp/RUNTIME-DIAGNOSTICS.md`. Benchmark filenames are cited via their ledger records; their timing samples are not re-measured here. No secret stores or environment values are read.

Regenerate with `python3 scripts/tool_validation_disposition.py --write` (Python 3.10+). Without `--write`, prints to stdout. Generation asserts 209 unique rows and known group/evidence names; it imports no MCP server/tool implementation. Evidence attribution is intentionally curated and must be updated from actual new execution records, not inferred from new test references. This report is a snapshot and does not incorporate other agents' future work automatically.
