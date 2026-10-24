# Core requirements and offline policy coverage

## Approved scope

Remove Certipy from core Python requirements while retaining its isolated pipx
installation guidance. Keep the explicit offline module allowlist and include
the policy regression module. Add contract tests preventing both omissions from
returning. Do not change redirects, gates, skill text, or target-facing behavior.

## Design

The existing `unittest` runner remains the CI entrypoint and continues to block
outbound socket connections during tests. Explicit selection avoids accidentally
running network integration modules. A new standard-library-only test module
checks parsed active requirements and the runner's module inventory, including
its own selection. Existing Certipy subprocess discovery remains untouched.

## Verification

First observe the contract tests fail against the baseline. Apply the minimal
requirements and runner edits, then run the complete offline suite. Resolve the
full requirements in a temporary environment using pip dry-run (no installation
into the user's existing environment). A dry-run proves resolution for this
platform/interpreter only, not runtime compatibility of every dependency.

## Baseline

HEAD `699167d`; clean worktree; 189 existing offline tests passed using the
existing repository virtualenv interpreter and the isolated checkout's sources.
