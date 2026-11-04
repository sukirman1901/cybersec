"""Build a read-only evidence disposition; never import or execute security tools.

Only --write writes, and only mcp/TOOL-VALIDATION-DISPOSITION.md. Execution evidence
is deliberately curated from named records, never inferred from static references.
"""
import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

# Group assignment is a validation route, not a statement of installed capability.
GROUPS = {
    "AD": ("ad_asrep_roast ad_certipy ad_dcsync ad_enum ad_kerberoast ad_ntlm_relay ad_passthehash ad_spray bloodhound_collect", "Impacket/LDAP/Kerberos; isolated domain controller, domain identities and role-specific permissions; Certipy/BloodHound or relay CLI where applicable", "Mock protocol/CLI responses, permission denial, timeout and secret redaction; real behavior blocked on isolated AD lab", "test_validation_ad_adapters.py"),
    "CLOUD": ("cloud_audit cloud_enum cloud_iam_audit cloud_infra s3_scanner docker_scan k8s_scan", "Disposable cloud account/resources or local Docker/Kubernetes cluster; provider credentials/SDK/CLI for authenticated modes", "Synthetic provider JSON/HTTP and permission-denied controls; offline IAM-policy inputs where supported; operational tenant/cluster not evidenced available", "test_validation_cloud_adapters.py"),
    "DEVICE": ("ios_frida ios_objection", "Frida/Objection CLI and attached authorized iOS device/app with compatible instrumentation", "Mock CLI output, missing device, timeout and redaction; runtime coverage blocked on device lab", "test_validation_device_adapters.py"),
    "ARTIFACT": ("apk_analyze ipa_analyze ios_signing ios_data_storage binary_checksec desktop_config desktop_electron desktop_entitlements desktop_packages desktop_strings stego_detect ci_cd_scan sast_review secret_scanner", "Synthetic APK/IPA/archive/source/binary fixtures; platform extraction/signing tools for applicable formats; package advisory feed for online package checks", "Temporary synthetic positive/negative/malformed files, traversal/size limits and redaction; mock optional commands/feed; real platform formats need matching fixtures/toolchain", "test_validation_artifacts.py"),
    "LOCAL": ("approval_artifact attack_surface_map branded_report cleanup_tracking compliance_map continuous_monitor custom_wordlist dork_gen engagement_gate evidence_manifest executive_summary findings_manager generate_report gf_patterns hash_analyze hash_detect http_ingest http_logger jwt_analyze phone_osint report_export report_schema_v2 risk_score scan_template session_verification sqli_exploit vuln_database vuln_diff vuln_validate webshell_gen xss_exploit", "Python dependencies and synthetic inputs; temporary storage for persistence/export actions; phonenumbers for phone parsing; generated payloads are not executed", "Offline valid/invalid/empty inputs, action round-trip in temporary storage, output schema and secret redaction; scoring/plans/payloads never count as exploit validation", "test_validation_local_utilities.py"),
    "CLI": ("amass_enum bandit_scan cmseek_check ffuf_fuzz gitleaks_check gobuster_dir hydra_brute masscan_scan nikto_scan nmap_scan nuclei_scan searchsploit semgrep_scan sqlmap_check sslyze_check testssl_check wpscan_check xsstrike_check tool_health", "Named executable plus compatible version, rules/templates/database and wordlists; scoped local target for active modes; privileges for raw packet scanners", "Mock argv/exit/stdout/stderr/timeout/missing executable; offline SAST with bundled rules and synthetic code where installed; active CLI runtime needs fixture service", "test_validation_cli_adapters.py"),
    "INTEL": ("asn_lookup crt_search cve_search dns_lookup dork_scan dork_search email_osint epss_lookup exploit_db_detail exploit_db_download exploit_db_search ghdb_search origin_ip_discovery people_osint reverse_ip shodan_lookup social_osint sub_takeover subdomain_enum telegram_osint wayback_urls whois_lookup", "DNS/WHOIS or external intelligence/search API and service availability; API keys for gated modes; no live availability established here", "Recorded synthetic API/DNS responses including empty, malformed, pagination, stale feed, rate limits and redaction; mock download writes into temporary paths", "test_validation_intel_adapters.py"),
    "INTEGRATION": ("github_issue jira_create notify_webhook", "Dedicated GitHub/Jira/webhook sandbox and least-privilege test credentials for delivery", "Mock payload/auth/status/retry/redaction contracts; delivery blocked on configured sandbox, never send real tickets/notifications in this review", "test_validation_integrations.py"),
    "PROTOCOL": ("port_scan service_fingerprint ldap_enum redis_enum smb_enum smtp_enum snmp_enum ssh_audit ssl_check ssl_pinning_check raw_replay http_request_splitting smuggling_check websocket_test", "Controlled TCP/UDP/TLS/WebSocket services; test certificates, protocol banners and timeout/error cases; proxy/backend pair for smuggling proof", "Mock sockets/TLS/protocol state first; later loopback protocol fixtures; real service/chain semantics remain unverified", "test_validation_protocols.py"),
    "AUTH": ("api_auth auth_macro_runner authenticated_scan cookie_editor csrf_extract idor_access_validation idor_detect jwt_forgery mass_assignment oauth_scan password_audit", "Synthetic sessions plus controlled app with two identities, ownership policy and state oracle; lockout-safe accounts for credential checks", "Mock authenticated/anonymous/other-owner responses, expired session, denial and redaction; later disposable app state proof, not status-only success", "test_validation_auth_flows.py"),
    "AI": ("browser_agent_hijack llm_agent_hijack llm_data_exposure llm_guardrails llm_model_dos mcp_abuse_test prompt_injection captcha_test", "Controlled model/agent/MCP or browser test application, synthetic data, explicit cost/action limits and observable effect oracle", "Mock responses and budget/denial handling; test plan vs execution distinction; behavioral proof blocked on configured agent/browser/model lab", "test_validation_ai_adapters.py"),
    "ORCHESTRATION": ("auto_exploit bulk_scan dork_and_scan dork_hunt injection_validator pentest_workflow retest_vuln", "Scoped child-tool fixtures, authorization/approval state and deterministic child results; real child capabilities require their own environments", "Mock child dispatch, scope denial, budget cancellation, skipped/error propagation and normalization; orchestration success is not child exploit proof", "test_validation_orchestration.py"),
    "OAST": ("oast_callback_server cmd_oast_helper oob_test log4j_scan vulnerable_fixture", "Loopback fixture/collector for local integration; reachable controlled callback endpoint and vulnerable service for remote effect; DNS unsupported by current HTTP collector", "Mock callback correlation, TTL, blocked/absent callback and cleanup; later local callback round-trip; remote callback reachability not established", "test_validation_oast.py"),
    "HTTP": ("", "Controlled HTTP application with positive/negative/malformed/denied responses; browser/DB/state oracle for effect claims beyond response recognition", "Offline MockTransport positive, negative, catch-all, malformed, 403/429/5xx, timeout, budget and redaction cases; later disposable app effect proof", "test_validation_http_detectors.py"),
}


def execution_evidence():
    evidence = {}
    def add(names, text):
        for name in names.split():
            evidence.setdefault(name, []).append(text)
    add("csp_analyze cookie_audit http_probe_target generate_report", "TUNING-PROGRESS.md §Batch 1: targeted offline regressions documented; NUSAIBA-SMOKE-2026-11-04.md §§Execution evidence/Scanner defects: pre-fix smoke calls, defects recorded; no post-fix live retest")
    add("exposed_git nextjs_scan graphql_introspect", "TUNING-PROGRESS.md §Batch 2 + web-surface-benchmark.json: selected synthetic HTTP cases; no real target/runtime proof")
    add("api_fuzz exposed_backup log_exposure", "TUNING-PROGRESS.md §Batch 3 + discovery-benchmark.json: selected synthetic HTTP cases, explicitly partial discovery")
    add("rails_scan metrics_check", "TUNING-PROGRESS.md §Batch 4a: documented offline recognition regressions; no app execution")
    add("django_scan express_scan spring_scan tech_detect", "TUNING-PROGRESS.md §Batch 4b + framework-benchmark.json: selected synthetic recognition cases")
    add("csrf_detect", "TUNING-PROGRESS.md §Batch 5 + csrf-benchmark.json: read-only synthetic observations; exploitable-CSRF recall unmeasured")
    add("xss_detect ssrf_detect joomla_scan drupal_scan magento_scan", "DETECTOR-BENCHMARK.md §§Recorded before/after/Limits + REMEDIATION-2026-11.md §Verification: selected mocked HTTP cases; no browser/SSRF-fetch/CMS runtime effect")
    add("sqli_detect", "SQLI-EVIDENCE.md §Reproduce the benchmark + DETECTOR-BENCHMARK.md: 13 local HTTP/SQLite cases, repeated; no other DB/timing/UNION coverage")
    add("bandit_scan semgrep_scan", "REMEDIATION-2026-11.md §Verification: actual adapters, one synthetic eval positive and json.loads negative; selected rules only")
    add("oast_callback_server", "REMEDIATION-2026-11.md A03/§Verification: real loopback HTTP callback round-trip; no DNS or remote callback proof")
    add("sslyze_check ad_certipy", "REMEDIATION-2026-11.md §Verification: dependency CLI startup/help only (SSLyze 6.0.0 / Certipy 5.1.0); public tool operational execution NOT established")
    add("tool_health", "REMEDIATION-2026-11.md §Local activation: connected MCP source fingerprint matched disk; readiness of all tools NOT established")
    trace_path = ROOT / 'mcp/offline-tool-execution.json'
    if trace_path.exists():
        trace = json.loads(trace_path.read_text())
        if trace.get('tests_successful'):
            for row in trace['tools']:
                if row['entry_execution_observed']:
                    add(row['tool'], 'offline-tool-execution.json: mapped Python implementation entry observed in ' + str(len(row['test_ids'])) + ' named test cases; dependencies may be mocked; not an operational pass')
    return evidence


def source_hints(tool):
    """Dependency names only, never read environment values or local secret stores."""
    executables, env_names = set(), set()
    for filename in tool["implementation_files"]:
        tree = ast.parse((ROOT / filename).read_text())
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call) or not n.args:
                continue
            name = ast.unparse(n.func)
            arg = n.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if name.endswith((".getenv", "environ.get")):
                    env_names.add(arg.value)
                if name.endswith((".which", "resolve_tool")):
                    executables.add(arg.value)
    packages = sorted(set(tool["import_roots"]) - sys.stdlib_module_names - {"cyber_tools", "__future__"})
    parts = []
    if packages:
        parts.append("import roots: " + ", ".join(packages))
    if executables:
        parts.append("literal resolver names: " + ", ".join(sorted(executables)))
    if env_names:
        parts.append("environment variable names: " + ", ".join(sorted(env_names)))
    return "; ".join(parts) or "stdlib-only imports in mapped source"


def build():
    inventory_path = ROOT / "mcp/tool-coverage-inventory.json"
    raw = inventory_path.read_bytes()
    inventory = json.loads(raw)
    tools = inventory["tools"]
    assert len(tools) == len({t["name"] for t in tools}) == 209
    names = {t["name"] for t in tools}
    groups = {}
    for group, (members, _, _, _) in GROUPS.items():
        for name in members.split():
            assert name in names and name not in groups, name
            groups[name] = group
    evidence = execution_evidence()
    assert set(evidence) <= names
    counts = Counter(groups.get(t["name"], "HTTP") for t in tools)
    refs = sum(bool(t["static_test_references"]) for t in tools)
    lines = [
        "# 209-tool validation disposition — 2026-11-04",
        "",
        "**Catalog accounting is complete; operational validation is not.** This read-only assessment runs no scanner, network probe, external CLI, cloud/AD action or test suite. The only generated files are this report and its optional generator. Existing evidence below is attributed to repository records, not freshly reproduced.",
        "",
        "## Counts and evidence boundary",
        "",
        f"- **209/209** inventory registrations have a disposition and mapped implementation(s). **{refs}** have static test-reference candidates; **{209-refs}** have none in the supplied inventory.",
        f"- **{len(evidence)}** tools have individually attributable documented execution evidence of some kind in the reviewed records; **{209-len(evidence)}** have no individually attributed execution established by this review. The latter is an evidence gap, not proof they never ran.",
        "- The historical ledger attributes 26 selected fixture/smoke tools, 2 dependency startup-only checks and one runtime diagnostic. The newer `offline-tool-execution.json` separately records actual mapped entry calls with test IDs; overlapping sets must not be added together.",
        "- Historical production smoke, local integrations and current mocked entry traces are different evidence classes. A called function is not proof that every action, external service or platform works.",
        "- Latest verification counts and cycle-specific limits are in `TUNING-PROGRESS.md`. This report generator reads those records; it does not execute tests. The separate runtime trace includes its own test count and success status.",
        "- The ledger's older **98 referenced / 111 unreferenced** baseline is stale relative to the supplied inventory. Inventory references can include mocks, strings and generic contract cases. Current tree changes after the inventory snapshot are not silently added to these counts.",
        f"- Input inventory SHA-256: `{hashlib.sha256(raw).hexdigest()}`. All module paths below come from that inventory; source dependency hints are a separate static read of the current tree.",
        "",
        "## How to read each row",
        "",
        "`None attributed` means no per-tool execution in the reviewed logs/ledger, even if broad suites passed. Test-reference paths are static candidate evidence only. Group routes specify exact **proposed** test module names; they are not claims that those modules already exist. Existing exact test modules are listed per row. Source import/resolver hints can cover a shared module rather than a specific function, are not exhaustive dynamic dependencies, and do not attest installation. Operational prerequisites are requirements, not available-lab claims.",
        "",
        "Concrete test-source examples: `test_tool_policy.py::TestToolKinds` checks dispatch authorization for named tools without executing those scanners; `test_core_tools.py::TestWhois` checks only domain normalization; `test_remediation_20261104.py::AuditRegression::test_cli_json_output_channels` patches CLI execution. These references must not become operational pass marks. Conversely, the local fixture integration defined in `test_core_tools.py` is an executable candidate, but its definition alone is not a dated per-tool execution log.",
        "",
        "## Validation groups and exact next test modules",
        "",
        "All next steps start with offline fixtures/mocks. Existing reference modules can be extended or the named proposed group module added. No new approval is needed to continue these offline engineering steps; a future operational run still needs its scoped environment and authorization. Do not turn missing credentials/labs into a false pass.",
        "",
        "| Group | Tools | Proposed module under mcp/tests/ | Operational dependencies | Locally executable next validation / blocked operational work |",
        "|---|---:|---|---|---|",
    ]
    for group, (_, deps, nxt, test) in GROUPS.items():
        lines.append(f"| {group} | {counts[group]} | `{test}` | {deps} | {nxt} |")
    lines += [
        "",
        "## High-priority feasible omissions",
        "",
        "1. **Response-recognition gaps:** host_header_injection, sharepoint_scan and broader wordpress/redirect/parameter coverage. CRLF, CORS, misplaced files, webshell and WAF now have selected offline suites; their declared unsupported surfaces still remain gaps. Existing exact test modules below are the first regression entry points.",
        "2. **Offline utilities:** phone_osint parsing, persistent-store isolation and broader reporting/action coverage. Cycle 2 adds hash_detect, gf_patterns and five report/evidence utility suites. Use temporary storage; never production findings/log stores. Selected cases do not cover every format or action.",
        "3. **Adapter contracts:** missing executable, nonzero exit, malformed output, timeout cleanup, API errors and secret redaction for every CLI/provider adapter. Groups: `test_validation_cli_adapters.py`, `test_validation_cloud_adapters.py`, `test_validation_ad_adapters.py`, `test_validation_intel_adapters.py`. These are locally feasible without operational accounts; do not label mocked adapters production-validated.",
        "4. **Auth/orchestration effect boundaries:** anonymous vs owner vs other-owner, expired identity, scope rejection, cancellation and partial child failure. Groups: `test_validation_auth_flows.py`, `test_validation_orchestration.py`. Actual BOLA/CSRF/state-change proof needs the controlled app oracle.",
        "5. **Artifact fixture breadth:** four desktop scanners now have malformed archive/plist/manifest, symlink-swap, bounded-read and redaction fixtures in `test_artifact_accuracy.py`. Other native/mobile formats and platform execution remain separate gaps. No need to inspect personal installed apps or execute generated payloads.",
        "",
        "## Concrete remaining completion blockers",
        "",
        "- No evidence-backed operational fixture/environment is supplied for every one of the 209 tools. Offline fixture implementation and per-case execution records are still work, not blocked by a need to ask per batch.",
        "- AD: isolated DC, Kerberos/LDAP/SMB services, role-specific accounts, AD CS/relay topology and disposable state. Cloud: disposable tenant/buckets/IAM, credentials and expected policies; Docker/Kubernetes require controlled clusters. iOS runtime: device, app and compatible Frida/Objection setup.",
        "- CLI: executable/version availability is not scanner readiness; rules/templates/feed/API keys, wordlists, OS/privileges and known-positive/negative target fixtures remain necessary. SSLyze/Certipy help success is not a target test.",
        "- External intelligence and notifications: live service availability, quotas, authenticated sandbox credentials and versioned response contracts; offline replay can validate parsing but not current API interoperability or delivery.",
        "- Stateful/browser/model exploits: disposable multi-user applications, browser effect oracle, controlled models/agents with bounded cost, callback reachability, protocol front/back-end topology, reset/cleanup and state-change observations. XSS reflection, generated code, plan steps, vulnerability scoring and simulated OAST are not exploit execution.",
        "- SQLi coverage is SQLite-specific; other DB engines, timing/UNION and broader contexts remain unmeasured. CSRF benchmark has no exploitable-positive fixture; SSRF mocks do not perform server-side fetches. Real network p95, RSS, request budgets and field precision/recall remain unmeasured across the catalog.",
        "- Fresh post-fix smoke/retest evidence and source/runtime provenance are missing for the production-observed fixes. Historical aggregate suite counts cannot be upgraded to current per-tool execution without a case-to-tool ledger and run artifacts.",
        "",
        "## Exhaustive tool disposition",
        "",
        "Dependencies and next validations inherit the named group above; each row adds source-derived dependency hints and the tool-specific function description. `Static refs` always means references, never observed execution.",
        "",
    ]
    for i, tool in enumerate(tools, 1):
        name = tool["name"]
        group = groups.get(name, "HTTP")
        static = "; ".join(f"`{p}`" for p in tool["static_test_references"]) or "None in supplied inventory."
        lines += [
            f"### {i:03d}. `{name}` — {group}",
            f"- **Mapped module:** {', '.join('`'+p+'`' for p in tool['implementation_files'])}.",
            f"- **Declared scope:** {tool['description'].splitlines()[0]}",
            f"- **Static refs:** {static}",
            f"- **Documented executed coverage:** {'; '.join(evidence.get(name, ['None attributed in reviewed execution records; aggregate suite/contract results are not a per-tool runtime trace.']))}",
            f"- **Dependencies:** {GROUPS[group][1]}. Source hints (not installation checks): {source_hints(tool)}.",
            f"- **Next validation / blocker:** {GROUPS[group][2]}. Proposed exact group module: `mcp/tests/{GROUPS[group][3]}`; existing exact regression modules are the static refs above.",
            "",
        ]
    lines += [
        "## Source records and reproducibility",
        "",
        "Reviewed: `mcp/tool-coverage-inventory.json`, `scripts/tool_coverage_inventory.py`, mapped implementation ASTs, exact referenced test paths, `mcp/TUNING-PROGRESS.md`, `mcp/REMEDIATION-2026-11.md`, `mcp/DETECTOR-BENCHMARK.md`, `mcp/SQLI-EVIDENCE.md`, `mcp/NUSAIBA-SMOKE-2026-11-04.md`, and `mcp/RUNTIME-DIAGNOSTICS.md`. Benchmark filenames are cited via their ledger records; their timing samples are not re-measured here. No secret stores or environment values are read.",
        "",
        "Regenerate with `python3 scripts/tool_validation_disposition.py --write` (Python 3.10+). Without `--write`, prints to stdout. Generation asserts 209 unique rows and known group/evidence names; it imports no MCP server/tool implementation. Evidence attribution is intentionally curated and must be updated from actual new execution records, not inferred from new test references. This report is a snapshot and does not incorporate other agents' future work automatically.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = build()
    if args.write:
        destination = ROOT / "mcp/TOOL-VALIDATION-DISPOSITION.md"
        destination.write_text(result)
        print(f"Wrote {destination}: 209 dispositions; no tools/tests executed")
    else:
        print(result, end="")
