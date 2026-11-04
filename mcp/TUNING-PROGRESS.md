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
