<!--
BEFORE SUBMITTING: Read every word of this template. PRs that leave
sections blank or contain unrelated changes will be closed without review.
-->

## What problem are you trying to solve?
<!-- Describe the specific problem. What broke? What was missing? -->

## What does this PR change?
<!-- 1-3 sentences. What, not why. -->

## Is this change appropriate for Cybersec core?
- [ ] Would this be useful to security testers working on different targets?
- [ ] Is this project-specific or team-specific? (If yes, it doesn't belong here)

## Does this PR contain multiple unrelated changes?
- [ ] No — all changes are related
- [ ] Yes — I will split into separate PRs

## Existing PRs
- [ ] I have reviewed all open AND closed PRs for duplicates
- Related PRs: <!-- #number, or "none found" -->

## Environment tested

| Platform (Claude Code, Cursor, OpenCode, etc.) | Platform version | Model | Model version |
|------------------------------------------------|------------------|-------|---------------|
| | | | |

## Testing

- [ ] MCP server starts without errors: `echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ./mcp/.venv/bin/python3 -m server`
- [ ] All JSON files valid: `python3 -m json.tool <file>.json`
- [ ] New tool/skill follows existing naming conventions
- [ ] No secrets or API keys committed

## Human review
- [ ] A human has reviewed the COMPLETE proposed diff before submission