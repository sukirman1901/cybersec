# Audit regression fixes

## MCP engagement preflight

FastMCP 3.4.2 or later (below 4) is required. In the same MCP transport session:

1. Call `engagement_gate(action="init", scope_json='{"domains":["lab.example"],"networks":["192.0.2.0/24"]}')`.
2. Obtain the user's authorization for this scope, then record it using
   `engagement_gate(action="authorize", confirmation="yes")`.
3. Call the target-specific tools. Out-of-scope and unapproved calls fail before
   tool dispatch. A new `init` clears previous scope and authorization, even if
   its input is invalid. Other MCP sessions do not inherit this engagement.

Confirmation is a record of client intent, **not independent proof of legal
authorization**. Workflow templates no longer supply their own confirmation.
Offline report/analysis tools and read-only CVE/EPSS intelligence remain usable
without engagement authorization. Reconnaissance against a supplied domain
still needs scope authorization.

All explicit destinations in a bulk call, raw Host header, login/upload URL and
other supported destination arguments are checked. Tools without a verifiable
destination, generated/opaque target lists and discovered-target scan chains
are rejected instead of guessing their scope. Use individual scoped tools.

**Limitations:** This is a dispatch boundary, not a network sandbox. It does not
mediate every redirect, DNS resolution, discovered subdomain, HTTP request or
subprocess. Do not treat it as full egress containment or a global request-rate
limiter. Direct Python module calls bypass MCP middleware. Approval artifacts
remain a separate mechanism and are not independent human identity verification.
Other module-level stores have not been made multi-tenant by this change.

## Result compatibility

- `retest_vuln`: request failures, blocked/error responses and unconfirmed redirects yield
  `inconclusive`, never `fixed`. Completed negative probes yield
  `not_reproduced`, with `verified_fixed=false`. These are heuristic probes,
  not proof of exploitability or a complete before/after remediation check.
  Existing query parameters are preserved and payloads are URL-encoded.
- `idor_access_validation`: matching bodies across two sessions are recorded as
  `cross_role_access_observed`; sequential access as `sequential_access_observed`.
  Neither sets `bola_found`/`idor_found`. This API cannot establish private
  ownership or the expected access policy, so confidence stays LOW and coverage
  explicitly names the missing evidence. Confirm the private owner, distinct
  identities and expected denial separately before reporting an authorization bug.
- `vuln_validate`: insufficient evidence and blocking/error signals remain
  `unverified`, not `false_positive`. Callback evidence is scored only when a
  callback ID matches a provided hit. Caller-supplied hit records are not
  independently authenticated. SQL errors are not automatic false-positive
  signals; error signals for unrelated vulnerability types are not mixed.

## Verification

```sh
mcp/.venv/bin/python -B scripts/run_offline_tests.py
```

The runner disables socket connections and runs explicit mock/contract suites.
It excludes tests requiring a listening loopback HTTP/SQLite fixture. CI runs
the same command. Success on selected fixtures is not a measurement of all
209 tools, real-world detector precision or production deployment safety.
