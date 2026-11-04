# Accuracy and performance tuning ledger

## Batch 1 — response interpretation (2026-11-04)

Scope: four modules implicated by the Nusaiba smoke review. All verification in
this batch was offline or local fixture testing; no production requests issued.

Changes:
- CSP: parse source tokens per directive; explicit HTTPS hosts are not scheme
  wildcards; first duplicate directive wins; nonce/hash policies suppress generic
  unsafe-inline warnings. Multiple policies return inconclusive rather than an
  unsupported effective-policy verdict. Warnings are header hardening observations,
  not exploit confirmations. Non-success responses stay incomplete.
- Cookie audit: parse each Set-Cookie independently, preserve Expires commas,
  inspect attribute names rather than value substrings, distinguish deletion and
  Max-Age precedence, remove cookie value previews. Missing HttpOnly is contextual;
  SameSite=None alone is not a vulnerability.
- HTTP fingerprint: use relevant product headers and word boundaries. A policy
  containing `tracking` no longer implies Ruby/Rack. Next.js response headers
  produce a technology hint, not runtime/version attestation.
- Report: absent port inventory is not zero open ports; observations are not
  automatically called vulnerabilities; preserve caller summary and avoid a
  generic patch prescription without verified impact.

Evidence:
- Initial regression run: 12 failed, one positive control passed.
- Final targeted suite: 14 passed (including inventory contract).
- Full suite: 391 passed, 1276 subtests passed; 50 existing deprecation warnings.
- Network-disabled runner: 358 tests OK.
- Existing detector benchmark: 42 executions; 36 scored with zero FP/FN on those
  selected cases, five deliberate errors and one incomplete excluded. These are
  not production accuracy estimates. No speedup or p95 improvement claimed.

## Catalog baseline

`tool-coverage-inventory.json` is reproducible using:

```sh
mcp/.venv/bin/python scripts/tool_coverage_inventory.py > mcp/tool-coverage-inventory.json
```

209 registrations mapped to implementation files and Python import roots. 98 have
static references in test files; 111 do not. References may be mocks, strings or
contract tests and do not establish executed coverage. Every row explicitly marks
accuracy unmeasured by the inventory and latency/request metrics null.

## Batch 2 — shallow web surfaces (2026-11-04)

Selected previously unreferenced tools: `exposed_git`, `nextjs_scan`, and
`graphql_introspect`. Root causes reproduced: status/length-only Git exposure,
generic `next` substring and successful-path Next.js findings, repeated homepage
downloads, source-map matching that missed normal links, and unvalidated GraphQL
JSON indexing. Initial suite exposed 15 failures across tests/subtests.

Changes:
- Git: require recognized HEAD/config/index/ref signatures; do not export raw
  config contents or label .gitignore as exposed repository metadata.
- Next.js: use framework-specific hints; reuse root response; inspect up to three
  explicitly linked same-origin maps with valid source-map JSON. Build IDs and
  public bundles are not vulnerabilities. Embedded source is an observation,
  not automatic high/critical secret leakage.
- GraphQL: validate nested JSON shape, avoid crashing on unrelated schema text
  or null schema, respect an explicitly supplied endpoint, request type names
  rather than full field inventories. Open introspection is a capability,
  not exploit confirmation.
- Shared probe: 15-second overall deadline, explicit request cap, 256 KiB decoded
  body cap, no redirect following, stop on denial/rate-limit/server failure.
  Preserve incomplete results rather than empty clean scans.

Verification: **402 tests and 1294 subtests passed**, 50 existing deprecation
warnings; **369 offline tests OK**. Regression suite includes deadline cancellation,
request/response limits and blocking behavior. No production traffic in this batch.

`web-surface-benchmark.json` preserves before/after results. Seven unique synthetic
cases per tool, five repetitions (105 executions per snapshot). Repetitions are
not independent targets. After: 75 scored executions, zero FP/FN; 30 deliberate
blocked/transport executions excluded and marked incomplete, zero exceptions.
Before: Git 15 FP; Next.js 10 FP/5 FN plus transport exceptions; GraphQL 10 malformed
response exceptions (excluded, not counted clean).

| Tool | Local mock-processing p95 before → after (ms) | Request change |
|---|---|---|
| exposed_git | 3.375 → 2.216 | 12 → 5 normal; 12 → 1 blocked |
| nextjs_scan | 3.582 → 1.216 | 12 → 1 non-Next; 12 → 2 linked-map positive |
| graphql_introspect | 1.974 → 1.779 | positive remains 1; blocked 4 → 1 |

These timings measure Python/mock transport, not real network p95. Resource/RSS
usage has not been benchmarked. Reduced request counts partly reflect narrower,
explicit coverage: Git now checks five signature-bearing metadata paths; Next.js
no longer probes generic directories/API/404/sitemap or retrieves unlinked maps.
No claim that omitted paths or unlinked artifacts are secure.

## Batch 3 — API, backup and log discovery (2026-11-04)

Tools: `api_fuzz`, `exposed_backup`, `log_exposure`. Initial labelled fixtures
exposed 17 failing tests/subtests, including catch-all false positives, unbounded
backup enumeration, continued requests after 429, and raw synthetic secrets in
log snippets. Additional tests cover prioritized PHP/SQL/JSON backup formats and
JSON log credential markers.

Changes:
- API discovery requires successful, distinctive content with schema/document or
  endpoint markers; unrelated successful HTML and catch-all JSON are not endpoints.
  Returned routes are observations, not vulnerability claims.
- Backup detection uses deterministic selection of six priority filenames across
  four suffixes, content signatures and a missing-path control. Budget: 24 candidate
  paths plus one control; 592 of 616 candidates are deferred on a normal run.
  Deferred coverage is explicitly partial. No linked-path expansion or archive
  extraction. Sensitive-looking file names alone do not imply critical severity.
- Log detection requires at least two recognized records, not keyword matches in
  arbitrary prose. No raw snippets or secret values are returned. Credential
  assignment patterns are candidates, not verified active credentials.
- All three use the bounded probe and stop on denial/rate-limit, redirects,
  server errors or transport failures. No-result logs say NO_EVIDENCE rather than PASS.

Verification: **409 tests + 1318 subtests passed**, 50 existing deprecation warnings;
**376 offline tests OK**. No production requests in this batch.

`discovery-benchmark.json`: 21 unique fixtures, five repetitions, 105 executions
per snapshot. Before: each tool had 15 FP across repeated scored fixtures; backup
had five transport exceptions. After: 75 scored recognition executions with zero
FP/FN; 30 blocked/transport cases excluded, zero exceptions. Backup recognition
scores do not imply completeness: unselected paths remain unknown.

| Tool | Mock-processing p95 before → after (ms) | Normal request count |
|---|---|---|
| api_fuzz | 5.005 → 6.328 | 20 → 21 |
| exposed_backup | 148.484 → 7.679 | 617 → 25 |
| log_exposure | 5.427 → 6.253 | 18 → 19 |

API/log have modest extra local overhead and one control request, traded for
better discrimination. Backup savings come primarily from intentionally reduced
coverage, not an equivalent full scan becoming faster. All stop after one request
on the blocked/transport fixtures. These p95 values exclude real network latency;
resource/RSS and real-world accuracy remain unmeasured. Soft-404 equality only
recognizes identical response bodies; dynamic variants and unsupported formats
remain limits of these shallow detectors.

## Batch 4a — read-only Rails and metrics recognition (2026-11-04)

- `rails_scan`: removed implicit user-creation POST and status-only mass-assignment
  claim. Header fingerprints are observations, not vulnerabilities. Source/route
  findings require structural signatures; dynamic HTML catch-alls are rejected.
  Mass assignment, console execution, encrypted credential validation, logs and
  admin access validation are explicitly not performed. Existing path probes are
  retained with bounded GETs (26 maximum including root and missing-path control).
- `metrics_check`: recognizes numeric Prometheus records rather than keywords;
  requires two samples or a declared matching type plus sample. Raw snippets,
  label values and metric values are omitted. Identical missing-path responses
  are rejected. JSON health/info and OpenMetrics exemplars remain unsupported.
- Both stop on blocked/error/redirect responses and report incomplete coverage;
  transport failure is structured and never a PASS. Limits inherited from
  SurfaceProbe: 15 seconds total, 256 KiB per body. Metrics uses 10 requests
  normally instead of nine due to the missing-path control; blocked fixtures
  use one instead of nine. Rails blocked fixtures use one instead of 26.
- Red phase reproduced 8 Rails and 10 metrics failing tests/subtests. Green:
  **420 tests + 1334 subtests passed**, 50 existing deprecation warnings;
  **387 offline tests OK**. No production requests. These fixtures do not measure
  real-world accuracy, network p95 or RSS. Framework detection is currently only
  the explicit header hint, not proof of the runtime behind a discovered file.

The rest of this group is covered in batch 4b below.

## Batch 4b — Django, Express, Spring and technology hints (2026-11-04)

Tools: `django_scan`, `express_scan`, `spring_scan`, `tech_detect`.

- Framework path scans now share bounded root/control/path handling. Successful
  status alone, incidental prose, generic security headers and login/health pages
  no longer become vulnerabilities. Informational evidence is in `observations`.
- Django source checks recognize settings, management scripts, env assignments,
  dependency manifests and admin login markup. Cookie auditing, debug execution
  and API authorization are explicitly not performed by this shallow scan.
- Express recognizes env, Git HEAD, package manifests, stack frames and directory
  indexes. No raw header values/cookies or stack content is exported. A 5xx stack
  remains incomplete under the shared stop policy, not a negative finding.
- Spring requires Actuator JSON structure; denial is incomplete, never exposure.
  Heapdump URLs are not requested. Legacy trace/dump formats and write operations
  are explicitly outside this detector's assessment.
- Technology hints use parsed resource attributes, generator metadata, exact
  cookie names and selected header names. Arbitrary article text, HTML comments,
  ordinary links, resource queries and cookie values do not supply fingerprints.
  Only recognized server product names are returned in `headers`, rather than raw
  response headers. No redirects or script execution; non-200 is incomplete.
- Final parser edge-case fixture catches boolean meta attributes without crashing.

Verification: initial red phase had **24 failures/subtest failures**; a subsequent
malformed-attribute fixture reproduced one parser error and was fixed. Final full
suite: **430 tests + 1366 subtests passed**, 50 existing deprecation warnings.
Network-disabled runner: **397 tests OK**. No production requests in this batch.

`scripts/benchmark_frameworks.py --revision 1ddff85` compares the committed baseline
against the same fixture runner. `mcp/framework-benchmark.json` retains snapshots:
24 unique synthetic cases repeated five times; 80 scored executions and 40
blocked/transport exclusions per snapshot. Baseline: 35 false positives and 15
uncaught transport exceptions. After: zero fixture FP/FN and no exceptions.
These are selected fixture results, not real-world accuracy or full capability
coverage. Technology 404 cases are scored for absence of false detection while
their scan coverage remains explicitly incomplete.

| Tool | Mock-processing p95 before → after (ms) | Normal requests before → after |
|---|---|---|
| django_scan | 5.176 → 7.017 | 15 → 16 |
| express_scan | 6.835 → 8.771 | 21 → 22 |
| spring_scan | 5.785 → 5.511 | 15 → 14 |
| tech_detect | 4.187 → 1.207 | 1 → 1 |

Django/Express trade an extra control request and processing for discrimination.
Spring savings partly reflect removing two heapdump requests and adding a control.
Blocked and transport fixtures now stop after one attempt. p95 is local synthetic
processing only, affected by interpreter warmup and host scheduling; RSS/network
latency remain unmeasured. Benchmark snapshots preceded only the boolean-meta
guard fix, which does not alter any benchmark fixture path.

Full 209-tool operational validation remains incomplete; the inventory is static
test-reference accounting, not proof that every tool or signature was executed.

## Batch 5 — CSRF observation accuracy and repeated cookie headers (2026-11-04)

`csrf_detect` now reports read-only indicators rather than claiming exploitability
from a successful GET. Initial fixtures reproduced **10 failing tests/subtests**:
form attributes were read from inner HTML, reversed token attributes selected the
field name as value, meta tokens were treated as form protection, and length or
encoding was mislabeled as entropy/weakness. The double-submit pattern is now an
observation, not a vulnerability. Missing tokens on POST forms become explicit
`candidate_forms`; a single response cannot prove token validation or CSRF.

- HTMLParser retains form opening-tag metadata and handles attribute order,
  unquoted attributes, comments and entity decoding. At most 100 forms are
  retained; excess forms and oversized bodies report incomplete coverage.
- No Origin/Referer GET comparison: this did not test a state-changing operation.
  Default execution uses one bounded GET, no form submission, and explicitly
  lists unavailable token validation, browser SameSite and state-change proof.
- Cookie attributes are parsed per cookie; cookie absence is NOT_APPLICABLE.
  Token/cookie values are not returned. Target query values are redacted, and form
  action output describes origin relation instead of returning potentially secret
  action URLs. A URL parameter named token does not prove CSRF-token leakage.
- An expiry-comma regression exposed `SurfaceProbe` collapsing repeated headers
  through `dict(response.headers)`. Copying the HTTPX Headers object now preserves
  distinct Set-Cookie fields across all consumers. The new fixture failed before
  this helper fix and passes afterward.

Verification: **439 tests + 1372 subtests passed**, 50 existing warnings;
**406 network-disabled tests OK**. No production requests.

`scripts/benchmark_csrf.py --revision f5f4ed2` supplies the baseline for
`mcp/csrf-benchmark.json`: six unique fixtures repeated five times, 15 scored
non-exploit fixtures plus 15 blocked/transport exclusions. Unsupported vulnerability
claims: **15 → 0**. Missing-token candidates recognized: **0 → 5**. Synthetic query
secret exported: **30 → 0**. Normal/blocked requests: **4 → 1**, transport: **1 → 1**.
Mock-processing p95: **3.401 → 1.191 ms**. Reduced work comes from removing invalid
GET-origin inference, not equivalent exploit validation becoming faster.

There are no true-positive exploitable CSRF fixtures in this benchmark; CSRF
vulnerability recall is unmeasured. `csrf_vulnerable=false` means no confirmed
finding, not safe; `assessment=not_exploit_tested` makes that boundary explicit.
Coverage completion refers only to the described snapshot analysis. JavaScript
forms, external form associations and submit-button overrides are not modeled.
The CRLF scanner was inspected but remains pending its own evidence-focused batch.

## Autonomous cycle 1 — 14 further tools and live smoke (2026-11-04)

User requested continuous execution without per-batch prompts. Independent modules
were delegated in parallel, reviewed, and integrated. No agent ran live probes.
Parent performed the bounded una browser smoke documented in
`NUSAIBA-AUTONOMOUS-SMOKE-2026-11-04.md`: root 200, missing route 404, selected
security-header presence, Next asset hints; no exploit or all-tool validation claim.

| Tools | Verified change / selected evidence | Remaining boundary |
|---|---|---|
| crlf_inject | Two fresh exact response-header nonces, absent in baseline and non-newline controls; raw query preservation, 49 requests/15s, no body reads | Four query names/three encodings; other input surfaces, splitting/log forgery not tested |
| api_auth, bypass_403 | Stable denied controls, repeats and matching structured resource envelopes; independent cookie state, redaction, malformed URL rejection | Medium-confidence resource-access observation; authenticated privilege not confirmed; raw protocol/mutation probes removed |
| cors_check | Browser-valid origin/ACAC semantics; wildcard+credentials and same-origin are not findings; actual GET policy required; GET/OPTIONS only | Policy candidates, not verified sensitive-data leaks or browser credential delivery |
| jwt_analyze, hash_analyze | Malformed/duplicate JSON, dates, ambiguity, uppercase hex and crypt formats; redacted output; 64 KiB/4 KiB ASCII input bounds | No signature, algorithm identity or credential verification |
| desktop_config | JSON/env/key-envelope candidates; no raw values; bounded regular-file reads, symlink/race rejection, accurate scan count | Selected filenames, heuristic assignments, cooperative local deadline, no secret validity test |
| compliance_map | Invalid input rejected; heuristic mappings no longer certify compliance | Control editions need independent review |
| cleanup_tracking | Correct updates/combined filters/ID selection and status aliases; quote generated removal args, sanitize comments | Generated cleanup scripts not executed |
| custom_wordlist | Name/path/symlink controls, bounded imports/merges, missing-source protection and UTF-8 failures | Synthetic temporary round-trips; concurrent filesystem races untested |
| cookie_editor | Supplied analysis stays offline, no implicit escalation, bounded decoding and value-free structural output | Escalation action not operationally validated |
| misplaced_files | Structural file signatures, missing-path control, no raw snippets, 17 supported paths | Public documents and unsupported formats explicitly excluded |
| webshell_detect | Direct source-pattern candidates, not filename/brand/prose matches; 25/33-request limits | No confirmed-shell execution or obfuscated/rendered-interface validation |
| waf_detection | One header-only request, product hints separate from CDN/load-balancer observations | No WAF enforcement/bypass proof; per-I/O timeout rather than hard wall-clock bound |

Red-phase reproductions: CRLF 9 failures/2 errors; auth 5 failures/6 errors;
desktop initial six failures plus private-key and file-swap regressions; CORS 10
failures/6 errors; remaining HTTP 42 failures/subtest failures. Offline crypto and
local utility regressions were also run red/green before their fixes.

An initial integration run overlapped another agent's red-phase work and failed
those unfinished HTTP cases; the source-fingerprint test correctly noticed files
changing. No passing claim or commit used that run. After every agent finished,
the stable full suite passed: **551 tests + 1511 subtests**, 59 deprecation warnings.
Network-disabled traced runner passed **518 tests**.

`crlf-benchmark.json` compares unchanged historical code at eeaa568 against the
same offline fixtures. A real synthetic query/header sink was missed before and
recognized after. Static scripts produced 493 bogus findings before versus zero
after; reflected bodies 58 versus zero. Blocked/transport runs went from 1684
attempts each to one. This is deliberately reduced, evidence-backed query coverage,
not equivalent broad exploitation becoming faster. Local timings are not network p95.

New evidence accounting:
- `TOOL-VALIDATION-DISPOSITION.md`: all **209** registrations mapped to evidence,
  validation groups and operational dependencies, not marked uniformly passing.
- `scripts/trace_offline_tool_execution.py`: profiles mapped implementation entries
  only during named network-disabled tests, with no arguments/locals/return values.
- `offline-tool-execution.json`: **72/209** entries observed in this run. The other
  137 were not observed by this main-thread offline trace; subprocesses and excluded
  local integrations are not measured. A traced call can use mocked dependencies
  and is not an all-actions operational pass. Static-reference counts remain separate.

Continue feasible offline work automatically. AD/cloud/device operational coverage
still needs appropriate labs; `nusaiba.dev` cannot establish those capabilities.

## Autonomous cycle 2 — verified source integration

Cycle 2 covers artifact scanners, report/evidence utilities, intelligence response
adapters and external CLI parsing using synthetic local fixtures and mocked
dependencies. Integration ran after all four agents stopped source edits.
No external binaries, live OSINT providers or personal desktop applications are
used by these new suites.

Parent-owned regressions:
- `hash_detect`: Argon2id/i/d shapes, invalid bcrypt cost, SHA-crypt rounds/salt
  alphabet, ambiguous hexadecimal shapes, secret-free output, input limits and
  character-entropy caveat. Initial run reproduced 8 failures/subtest failures;
  SHA-crypt follow-up reproduced 2 additional failures. Final targeted run:
  **5 tests + 8 subtests passed**. No hash cracking or algorithm verification.
- `gf_patterns`: URL query values no longer classify endpoint paths; credentials,
  query values and fragments omitted from exported URLs; malformed inputs and
  1000-entry/8192-character URL/1 Mi-character aggregate bounds are explicit.
  Red phase reproduced **7 failures/subtest failures**. Combined parent suites:
  **10 tests + 11 subtests passed**. URL paths remain visible; classification is
  an offline hint, not a vulnerability verdict or general secret detector.

Reviewer follow-ups requested before integration: remove raw CLI stderr/XSStrike
output from result errors, fix independently reproduced nmap/searchsploit parser
failures, bound report inputs, and redact report URL query/fragment values.

Reviewed agent groups (selected fixtures only):
- Intelligence: ASN response identity/prefix validation and cleanup, CT schema and
  domain boundary filtering, reverse-IP certificate/PTR association, Wayback column
  ordering and URL redaction, Shodan query encoding/schema/limits. Red phase: 47
  failures/subtest failures. Historical certificate associations do not establish
  current shared hosting; discovered results never extend authorized scope.
- Reports: ingest malformed/empty input handling and rollback, local evidence
  content/chain consistency, candidate-status preservation, HTML escaping and CSV
  quoting/formula neutralization. Five entry points now have explicit input and
  collection limits; report URL credentials/query/fragment values are redacted.
  Local consistency is not provenance. Export APIs return strings, not disk files.
- CLI adapters: resolved executable/argv preservation, structured parsing and
  failure status for masscan, CMSeeK, XSStrike, testssl, SSLyze and gobuster; nmap
  malformed XML and searchsploit column/header/exit handling. All subprocesses were
  mocked. External-tool reports are not independent exploit confirmation; shared
  subprocess output-collection limits remain a separate unresolved concern.
- Parent integration of these completed groups plus hash/GF suites passed
  **82 tests + 113 subtests**, with 10 existing datetime deprecation warnings.

Live repeat at **16:57:21 UTC**: two credential-free same-origin GETs through the
existing una browser returned root 200 and control 404, with all four previously
observed security headers present. Streams were cancelled without body reads.
See `NUSAIBA-AUTONOMOUS-SMOKE-2026-11-04.md`; no external CLI/provider validation
is inferred from this smoke check.

Connected-runtime check during cycle 2: `tool_health(include_optional=False)`
reported `files_on_disk.mcp_vs_startup=different`. The connected server still has
its 15:21:42 UTC startup snapshot; source tests exercise newer disk code. No MCP
reload operation is exposed in the discovered host tools, and no server/browser
process was killed to force reconnection. Loaded-runtime validation remains open
until the host reconnects the server; do not describe source fixes as already
active in this connected MCP process.

Artifact review completed: all four scanners use bounded regular-file reads with
no-follow/nonblocking opens and post-open device/inode checks. ASAR inspection is
in-memory rather than extraction; linked/unpacked/unsafe or oversized archives
are explicitly unsupported. Secret string matches are redacted. Electron lexical
matches remain candidates, not a complete JavaScript parser. Entitlements support
synthetic XML/binary/embedded plist cases. Package comparisons distinguish exact
npm declarations from ranges/other ecosystems; unreliable bundled CVE associations
were removed, and legacy thresholds are review hints, not safe-version guarantees.
Agent's final artifact suite: **36 tests passed**, with synthetic read races and
truncation coverage. No installed apps, platform executable or advisory feeds ran.

Stable integration evidence:
- Full pytest: **669 tests + 1660 subtests passed**, 69 deprecation warnings,
  97.90 seconds on this machine.
- Network-disabled traced run: **636 tests passed**, 42.470 seconds.
- Actual mapped entry calls: **96/209** observed, up from 72 in cycle 1.
  The other 113 entries remain unobserved in this specific trace. No inference of
  complete operational coverage, real-world precision/recall or network p95.
- `offline-tool-execution.json`, inventory and disposition refreshed from these
  results. These timings are test-run measurements, not target performance.

## Autonomous cycle 3 — verified source integration

Independent groups cover temporary persistent stores/reports, source/binary
scanners, discovery intelligence and protocol observers. Parent owns shared CLI
collection. No live scanner/provider/binary execution is part of these groups.

Shared `_run_cli` now retains at most **2 MiB raw output across stdout/stderr**,
marks truncation as incomplete, uses monotonic duration, and omits raw spawn errors
and wrapper stderr from exported errors. On timeout/output limit/cancellation it
kills/reaps the child and, on POSIX, its process group. Post-kill streams are drained
without retention under a two-second cleanup budget to release paused pipe readers.
Noisy synthetic Python children reproduced the prior unbounded output and, during
development, a paused-reader cleanup failure; both have regression coverage.
Actual subprocess tests execute only synthetic Python scripts, not scanners.
Existing process mocks now use real StreamReader buffers instead of assuming one
unbounded `communicate()` call. Latest focused helper/remaining-CLI/remediation
check: **43 tests + 2 subtests passed**; two existing datetime warnings.

Completed store/report agent review: **24 tests passed** using temporary stores.
Raw HTTP records now persist redacted placeholders and length metadata; named
credentials/body/header values and URL userinfo/query/fragments are redacted on
export, including legacy data. General prose-secret detection is not claimed.
Corrupt stores preserve data and return failure rather than empty success; database
updates use atomic replacement. Logger/database/logo leaf-file reads and logger
appends reject tested symlink/identity swaps with no-follow/nonblocking opens.
Full concurrent-writer/crash durability and parent-directory races remain unverified.

Independent subprocess review reproduced cancellation *during* output-limit cleanup
leaving a paused pipe (180224 bytes buffered), and found a test-only cancelled-future
warning. A retained shielded cleanup task now finishes under repeated caller
cancellation before cancellation propagates; incomplete drain gets a last-resort
transport close and bounded 0.5-second reap after the two-second cleanup timeout.
The test timeout stub now awaits cancelled futures and leaves cleanup's real
timeouts intact. Reviewer reran the original reproducer: child exited -9, both
streams EOF, buffers empty, transports closed, zero residual tasks. Collector
suite **8 passed**; remaining-CLI suite **10 passed**, no gathering warnings.
Parent's combined CLI suites passed **60 tests + 20 subtests**. This is POSIX/macOS
synthetic-process evidence; arbitrary detached descendants/platforms are not proven.

WHOIS and binary collectors received the same noisy-output and repeated-cancellation
regressions. Final targeted agent suites: WHOIS **13 tests + 10 subtests**, source/
binary artifacts **43 tests**. Both protected cleanup tasks finish before propagating
caller cancellation. Target binaries and WHOIS commands were never executed; only
harmless Python fixtures exercised actual subprocess cleanup.

Other completed groups:
- Discovery intelligence: bounded WHOIS allowlisted metadata, provider/domain
  validation, wildcard DNS controls, origin-IP candidates and structured takeover
  error candidates. Neither origin identity nor takeover claimability is confirmed.
  Initial regressions reproduced 40 failures/subtest failures.
- Source artifacts: redacted secret locations, bounded/race-checked file reads,
  source syntax/comment/literal filtering, parsed dependency declarations with
  ecosystem boundaries, and private binary snapshots. Advisory hints remain
  historical candidates; JavaScript analysis remains lexical; no runtime exploit
  confirmation. ELF NX and PIE observations are separate from runtime ASLR.
- Protocols: refused versus unknown TCP observations, bounded connection/banner
  attempts, SSH identity-only observations, and default-verifying TLS contexts.
  All sockets/TLS were mocked. OS DNS/address retries for synchronous TLS remain
  outside a hard total deadline; service hints do not establish vulnerabilities.
  Initial regressions: 5 failures and 9 errors. Targeted suite: 22 tests passed.

After all source agents stopped, full integration passed **790 tests + 1753
subtests**, 97 existing datetime deprecation warnings, in **122.43 seconds**.
Network-disabled traced run passed **757 tests** in **65.764 seconds**. Mapped
implementation entries observed: **112/209**, up from 96; **97 unobserved in this
run** remain explicit gaps. A source comparison found no changes to existing public
function signatures across the 17 changed implementation modules. Aggregate test
counts and trace coverage still do not establish all-action operational accuracy.

## Autonomous cycle 4 — verified source integration

Five independent groups cover mobile artifact adapters, remaining network-protocol
adapters, mocked external integrations, web observations, and mocked credential-audit
boundaries. No real integrations
are posted, devices contacted or credentials attempted by these suites.

Parent fixes:
- `phone_osint`: corrected off-by-one line-type mapping using library enum names;
  country is now country metadata rather than a city/area description. Invalid
  numbers produce no lookup links; normalized E164 is used in URL templates.
  Inputs are bounded, parser/metadata exceptions are generic, and output explicitly
  distinguishes numbering-plan metadata from identity/location/reachability proof.
  Original input is redacted; normalized supplied numbers remain in results by
  design. No external lookup services contacted. Fixtures use a fictional NANPA
  number and the installed library's example-number metadata.
- `dork_gen`: validates selector/limit/domain syntax, prevents search operators
  from entering the supplied site scope, uses URL query encoding, and labels
  results as generated templates only. Existing query templates were not expanded;
  no search or target access occurs.

Red phases reproduced **10** phone and **11** query-generator failures/subtest
failures, plus three follow-up unknown-selector error-redaction failures. Combined
targeted green run: **11 tests + 18 subtests passed**. Phone
metadata fixtures require the optional installed phonenumbers package; skips must
not be treated as execution evidence on environments without that dependency.

Completed protocol/integration groups reviewed:
- Redis/LDAP/SMB/SMTP retain selected protocol-positive observations, distinguish
  refused connections from unknown transport failures, redact banners/config or
  credential data and bound reads/commands. SNMP remains explicitly TCP-only;
  UDP/community validity is not assessed. Credentialed LDAP binds are unsupported.
- GitHub/Jira creation and Slack/Discord/Teams delivery acknowledge only validated
  mocked receipts; redirects are disabled and outgoing raw evidence/URL secrets
  redacted. Jira description uses ADF. No issue or message was actually created.
- Monitoring uses temporary persistent-store fixtures, atomic writes and read-race
  checks; disappearance of findings no longer means remediation. CI/CD observations
  are bounded candidates with soft-404 controls, not successful exploitation.

Parent combined check for these groups plus phone/query utilities: **58 tests + 36
subtests passed**. A test module's missing standalone import path was reproduced and
corrected before that run. Credential-adapter review identified a key-auth ambiguity
in Paramiko's defaults and requested password-only auth options, bounded auth/banner
waits, input validation and no-follow wordlist reads before integration.

Credential and mobile review follow-ups verified together: **56 tests + 66
subtests passed**. SSH explicitly disables agent/key lookup and bounds banner/auth
waits; all authentication and Hydra execution remain mocked. Hydra output must
match the supplied host/service, with bounded regular-file wordlist reads.
Mobile archive inspection remains in-memory; binary AXML, signing validity,
runtime device protection and pinning are explicitly unverified. Blocking TLS
observation now runs off-loop with a bounded await; synthetic heartbeat and cleanup
fixtures pass. Resolver workers may outlive cancellation until their blocking call
returns; this is not a hard DNS execution deadline. No devices or real login
attempts were used. Web review follow-up completed before source freeze:
Engine.IO uses `EIO=4&transport=polling`; strict fixtures enforce the five-request
cap, empty GET bodies and absence of authentication probes. Handshake observations
carry confidence and coverage, without inferring authentication or origin-policy
security. Source edits stopped before integration.

Stable cycle-4 integration:
- Full pytest: **926 tests + 1903 subtests passed**, 97 warnings, **107.50 seconds**.
- Network-disabled trace: **893 tests passed**, **53.103 seconds**, no failures/errors.
- Actual mapped entries observed: **137/209**, up from 112. **72 entries remain
  unobserved in this trace**; operational coverage and real-world accuracy across
  all tools are not established.
- Inventory, trace and 209-tool disposition refreshed. External provider/device
  interoperability remains unverified. Connected MCP startup identity has not been
  refreshed by these source tests.

## Autonomous cycle 5 — verified source integration

Cloud/container observation adapters and search metadata adapters are under
offline review. No cloud credentials, live providers, containers or infrastructure
are used. Parent independently verified search metadata fixtures: **38 tests + 15
subtests passed** across GHDB and the actual mapped `google_dork.py` /
`exploit_db.py` modules. Download implementation remains unchanged. Provider
layouts are not operationally validated; redaction remains pattern-based.
Parent review confirmed `dork_search`'s server wrapper still echoed raw queries
and counted diagnostic rows. A narrowly scoped wrapper fix and regression suite
completed. Parent verification of search metadata plus wrapper: **46 tests + 15
subtests passed**. The wrapper's regression tests execute its actual function via
isolated AST extraction, not MCP dispatch. Query echo is fully redacted, diagnostic
rows are counted separately, and incomplete/truncation metadata is preserved.
Cloud follow-up independently passed **26 tests**. Aggregate probes share a
per-call **40-request / 30-second cooperative budget**, clamp remaining I/O time,
disable redirects, and mark skipped probes incomplete. Synchronous blocking I/O
cannot be hard-interrupted. Findings carry confidence/coverage; CLI inventories
explicitly do not establish a complete audit. No local Docker socket is probed
implicitly. No cloud accounts, credentials, providers or containers were used.

Initial full integration found one static redirect-inventory failure: a no-redirect
handler was supplied indirectly in a list. Supplying the same handler explicitly
resolved classification without weakening the test. Related regression run:
**40 tests + 19 subtests passed**.

Stable integration after source freeze:
- Full pytest: **998 tests + 1918 subtests passed**, 97 warnings, **104.61 seconds**.
- Network-disabled trace: **965 tests passed**, **46.320 seconds**, zero failures/errors.
- Mapped entries observed: **147/209**; **62 unobserved** in this trace. AST-only
  wrapper tests do not establish connected MCP dispatch coverage.
- Nusaiba repeat at **2026-11-04T18:01:02.973Z**: one authorized credential-free
  GET `/` returned **200**, with four recorded security headers present. Response
  body cancelled unread; no cloud/scanner validation inferred from this smoke.

## Remaining work

- Expand family-specific labelled fixtures and execution evidence beyond the
  current benchmark, prioritizing the 111 tools without static test references.
- Measure p95 latency, request budgets and resource usage before optimizing.
- Validate CLI/version/template contracts and authenticated multi-step flows in labs.
- AD/cloud/mobile need suitable authorized environments to establish operational
  accuracy; importability or mock tests alone are insufficient.
- Retest the four production-observed behaviors after reload using a new bounded
  run. No current claim that all 209 tools have high accuracy or performance.

CSP limitations include meta policies, browser-version behavior, policy intersection
and effective fallback interactions. Cookie parsing cannot infer application cookie
semantics from a name; malformed/unsupported attributes require manual review.
