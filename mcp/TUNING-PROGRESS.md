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
