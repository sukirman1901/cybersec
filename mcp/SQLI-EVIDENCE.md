# SQLi evidence engine (GET/query, first slice)

The existing `sqli_detect(target, param="", preset="observe-first")` MCP interface
is unchanged. It now uses repeated, controlled experiments rather than treating a
single SQL-looking error, status change, slow response or HTML table as proof.

## What executes

- Preserve existing query values, duplicate parameters, empty values and the raw
  encoding of untouched parameters. Mutate one occurrence at a time.
- Three original-value baselines establish content/status stability.
- Two benign value controls must succeed without SQL errors or blocking.
- Error confirmation requires a new SQL error on two repeated quote probes,
  absent from baseline/controls, with a normal recovery response in between.
- Boolean confirmation requires two distinct true/false AND predicates, with
  reversed request order on the second round. True responses must remain close
  to baseline; false responses must consistently separate in content, with the
  same successful status. Exact probe reflection is normalized before comparison.
- Findings include request roles, SHA-256 response hashes, response sizes/statuses,
  timings, matched SQL error signatures and content-distance measurements.
  `evidence` remains a JSON-encoded **string** for existing report converters.
- Each finding and its evidence carry a replay recipe: original query context,
  selected token index, original value, successful probe values and benign controls.
  Recognized credential query keys and URL userinfo are redacted. If the recipe
  needs redacted secrets, `reproducible=false` and `replay.requires_secrets` identifies
  the missing inputs; confirmation confidence is distinct from replay completeness.
- Novelty uses a stable causal `evidence_hash`, not volatile timings or counters.
  Full response hashes remain available in the observation evidence.
- Confirmed observations survive later request-budget/deadline exhaustion.

| Preset | Parameter occurrences | Request ceiling | Wall-clock I/O budget |
| --- | ---: | ---: | ---: |
| observe-first | 2 | 80 | 18 seconds |
| staging-deep | 4 | 160 | 55 seconds |

An individual response read is bounded by the remaining deadline and an 8-second
request limit. Collected response bodies are limited to 256 KiB. Content similarity
uses linear-time 4-character shingle overlap on a prefix/suffix window of at most
16 KiB on larger pages. SQL error regex wildcard spans are bounded, avoiding
unbounded backtracking on repeated warning text. No redirects are
followed. No automatic network retry is performed. Proxy environment variables are
not used. TLS certificate checking remains disabled as in the previous scanner.

## Result interpretation

Existing keys (`results`, `findings`, `vulnerable`, `risk_summary`, etc.) remain.
New fields include `candidates`, `assessment`, `coverage_complete`, `errors`,
`requests_sent`, `request_budget`, and `techniques_skipped`.

- `confirmed`: at least one experiment met its confirmation conditions.
- `inconclusive`: unresolved candidate, unstable/blocked/failed requests, or
  incomplete parameter coverage without a confirmed finding.
- `no_evidence`: implemented experiments completed without a confirmed finding or
  unresolved candidate. **This does not establish that the endpoint is safe.**

`coverage_complete` refers only to implemented experiments on selected query
contexts. It never means all SQLi techniques were tested. Without query parameters,
the scanner tries guessed names and explicitly records that fact. Findings are
not automatically labeled CRITICAL; impact was not established by these probes.

## Explicit omissions and limitations

Legacy timing, CPU-heavy BENCHMARK/randomblob probes, UNION heuristics, DB enumeration,
POST/JSON/cookie testing and WAF bypass transformations are **not executed** by this
slice. They are listed in output coverage rather than counted as completed work.
The old error/UNION payloads that attempted to read users/passwords are not used.
Vendor/version fingerprinting is not established (`db_fingerprint` remains null).

Repeated observations reduce noise but are not a mathematical proof of SQL execution
on arbitrary applications. Highly dynamic content, small differences on large pages,
uncovered SQL quoting contexts, and blind queries with an empty baseline can be missed.
Only SQLite numeric/string execution is benchmarked here; this is not a claim of
MySQL/PostgreSQL/MSSQL/Oracle coverage or production-wide accuracy.

## Reproduce the benchmark

From the repository root, using an environment with the MCP dependencies:

```bash
python scripts/benchmark_sqli.py --runs 3
python -m pytest mcp/tests/test_sqli_evidence.py mcp/tests/test_sqli_sqlite_benchmark.py -q
```

The benchmark binds an ephemeral **127.0.0.1** port and runs SQL against synthetic
in-memory tables. It has no remote-target option and shuts down in `finally`.

Observed on Python 3.12, 2026-10-24, including a rerun after review fixes:

| Three runs of nine labeled scenarios | Count |
| --- | ---: |
| True positive | 18 |
| True negative | 6 |
| False positive | 0 |
| False negative | 3 |

The three misses are the **same known-vulnerable empty-baseline blind case**, once
per run. Count it as a false negative, not a clean endpoint. The repeated deep
preset is also not an independent target. These small benchmark counts must not
be marketed as general detection accuracy.
