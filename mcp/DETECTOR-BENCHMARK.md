# Local detector accuracy benchmark

From the repository root:

```sh
mcp/.venv/bin/python scripts/benchmark_detectors.py --runs 1
mcp/.venv/bin/python scripts/benchmark_detectors.py --runs 3 > detector-results.json
# No listening server needed for this subset:
mcp/.venv/bin/python scripts/benchmark_detectors.py --mock-only
```

`--runs` is bounded to 1–10. There is no remote-target argument. JSON output
retains every case execution, detector verdict, requests, transport failures and
classification. Group metrics by **detector AND environment**, never combine
mock response simulation and actual HTTP/SQLite execution into a single accuracy.
The runner is development tooling, not a new MCP tool or a general scanner.

## Ground truth and environments

- **SQLi (`localhost_http_sqlite`)**: reuse all 13 cases from
  `scripts/benchmark_sqli.py`, unchanged order/presets. An ephemeral loopback
  server executes real parameterized and concatenated SQLite queries against
  synthetic rows. Setup/teardown belongs to the runner; no remote-target option.
- **XSS (`mock_http`, seven cases)**: raw HTML reflection is the positive signal.
  Escaped HTML, nosniff text/plain, JSON, comments, and an unchanged pre-existing
  script are negative controls. One transport-error case is excluded. This is
  **static markup signal classification, not demonstrated browser execution**.
- **SSRF (`mock_http`, seven cases)**: file and metadata response simulations are
  positive signals. Generic HTTP 200, URL echoes and unchanged metadata prose
  are negative controls. Blocked and transport-error cases are excluded. No URL
  is actually fetched by a fixture; no real metadata, credentials or callbacks.
- **CMS (`mock_http`, five cases each for Joomla, Drupal, Magento)**: sensitive
  configuration source at the expected path is positive. Forbidden files,
  generic soft-404 pages and missing files are negative. Transport failure is
  excluded. CMS presence/admin login alone is **not** the positive label.

MockTransport replaces the entire httpx client transport, rejects hosts other
than `fixture.test`, records boundary violations even if a detector catches the
exception, and caps requests per case. Browser mode is disabled. Runs are serial
because transport patching is process-wide. Each mock call has a 10s deadline;
SQLite cases have a 60s deadline. Repeated runs are not independent targets.

## Accounting

For completed cases: TP/TN/FP/FN compare `vulnerable` with the fixture label.
Thrown exceptions, detector-reported errors, and transport failures become
`error`. Entirely blocked/rate-limited responses or incomplete detector coverage
become `incomplete`. These rows are **not true negatives**; raw `detected` remains
visible even on excluded rows. Both excluded counts are reported alongside the
scored denominator. Precision = TP/(TP+FP), recall = TP/(TP+FN); undefined ratios
are null, not 100%. Runner exit success means execution finished, not zero FP/FN.

## Recorded before/after (2026-10-24)

Baseline detector source: `9a3230c` (before this PR). Mock baseline was rechecked
with the identical final fixtures, including explicit HTML Content-Type headers.
SQLite cases were unchanged. Each row below is **one run**, in TP/TN/FP/FN order.

| Detector / environment | Before | After | Excluded per run |
|---|---|---|---|
| XSS / mock HTTP | 1 / 2 / 3 / 0 | 1 / 5 / 0 / 0 | 1 error |
| SSRF / mock HTTP | 2 / 0 / 3 / 0 | 2 / 3 / 0 / 0 | 1 error, 1 incomplete |
| Joomla / mock HTTP | 1 / 2 / 1 / 0 | 1 / 3 / 0 / 0 | 1 error |
| Drupal / mock HTTP | 1 / 2 / 1 / 0 | 1 / 3 / 0 / 0 | 1 error |
| Magento / mock HTTP | 1 / 2 / 1 / 0 | 1 / 3 / 0 / 0 | 1 error |
| SQLi / localhost SQLite | 9 / 4 / 0 / 0 | 9 / 4 / 0 / 0 | 0 |

Three post-change runs: 126 case executions, 108 scored, 15 transport-error
executions, 3 incomplete blocked executions; zero FP/FN **on this selected set**.
The nine reproduced false positives became regression cases before detector edits.

## Targeted detector changes

- XSS reflection/header/DOM inspection requires an HTML response. A payload
  already present in the baseline is not new injection evidence.
- SSRF status/size/slow/error responses alone no longer count as basic evidence.
  Content must differ from baseline after URL echoes are removed. Nonempty
  protocol responses alone no longer confirm gopher/dict/LDAP reachability.
- CMS identical root/catch-all responses are not content confirmation. Joomla
  configuration, Drupal settings and Magento env.php require source structure,
  rather than a CMS name or login/password prose alone.

## Limits / remaining work

This small selected regression set does not establish real-world precision,
recall or exploitability. No MySQL/PostgreSQL/MSSQL, WAF, CSP, browser execution,
DOM dataflow, stored-XSS execution, real SSRF fetch/OOB behavior, blind timing
validation, or exhaustive CMS templates are measured. Broad SSRF timing and
redirect heuristics remain outside these fixes. Baseline subtraction and exact
soft-404 matching can miss dynamic templates or genuine content matching the
baseline; stricter source checks may miss alternate configuration formats.
Missing HTML Content-Type is not treated as confirmed XSS reflection.
Future cases must preserve existing case identities and report coverage growth
separately rather than comparing an expanded denominator with this baseline.
