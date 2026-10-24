# Requirements and Policy CI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Isolate Certipy from core dependencies and run policy regressions in CI.

**Architecture:** Preserve the explicit offline unittest module list. Add a
contract test for active dependency names and required runner
modules, then make the smallest requirements and allowlist changes.

**Tech Stack:** Python, unittest, packaging requirement parsing, pip, GitHub Actions.

---

### Task 1: Lock the contracts with failing tests

**Files:** Create `mcp/tests/test_install_ci_contract.py`.

1. Parse active lines from `mcp/requirements.txt` with packaging.requirements.Requirement;
   normalize names with packaging.utils.canonicalize_name and assert certipy-ad is absent.
2. Load `scripts/run_offline_tests.py` via runpy.run_path without invoking main;
   assert MODULES contains test_tool_policy and test_install_ci_contract once each.
3. Run `/Users/aaa/Documents/Developer/cybersec/mcp/.venv/bin/python3 -B -m unittest discover -s mcp/tests -p test_install_ci_contract.py -v`.
   Expect failures for the active Certipy dependency and missing module selections.

### Task 2: Apply the minimal fix

**Files:** Modify `mcp/requirements.txt`, `scripts/run_offline_tests.py`.

1. Delete only the active `certipy-ad>=5.1.0` requirement; retain pipx comments.
2. Append `test_tool_policy`, `test_install_ci_contract` to MODULES.
3. Re-run focused tests; expect pass.
4. Run `/Users/aaa/Documents/Developer/cybersec/mcp/.venv/bin/python3 -B scripts/run_offline_tests.py`;
   expect all selected tests, including policy cases, to pass with outbound sockets blocked.

### Task 3: Verify dependencies and prepare the PR

1. Create an isolated temporary venv outside the repo and use its pip to run
   `install --dry-run --ignore-installed --report <temporary-report.json> -r mcp/requirements.txt`.
   Expect a resolved full requirement set without Certipy. Do not install scanners.
2. Run `git diff --check` and inspect the complete diff.
3. Commit only approved changes and documentation on `fix/requirements-policy-ci`.
4. Prepare a PR with actual local verification results; distinguish remote CI
   results and dependency dry-run from executed runtime installation tests.

## Progress

- [x] Approved design and isolated worktree.
- [x] Baseline: 189 offline tests pass.
- [x] Red contract tests: active Certipy and both missing runner selections fail.
- [x] Minimal fixes and green suite: 219 offline tests pass (Python 3.12/macOS).
- [x] Isolated dependency dry-run: 82 packages resolve on Python 3.14/macOS;
  cryptography 50.0.2, FastMCP 3.4.11, no Certipy selected. No core packages installed.
- [x] Diff self-review and whitespace verification.
- [ ] Publish PR and verify hosted CI separately.
