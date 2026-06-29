---
name: cybersec-skill-dev
description: Use when creating new cybersecurity methodology skills, editing existing skills, or verifying security skills work before deployment
---

# Writing Cybersec Skills

## Overview

**Writing Cybersec skills IS TDD applied to security methodology.**

You write test cases (security pressure scenarios with subagents), watch them fail (agent skips recon), write the skill (methodology documentation), watch tests pass (agent follows methodology), and refactor (close loopholes).

**Core principle:** If you didn't watch an agent fail without the skill, you don't know if the skill teaches the right security methodology.

**REQUIRED BACKGROUND:** Understand Superpowers `writing-skills` and `test-driven-development`. This skill adapts those patterns for security testing.

## TDD Mapping for Cybersec Skills

| TDD Concept | Security Skill Creation |
|-------------|------------------------|
| **Test case** | Security pressure scenario with subagent |
| **Production code** | Skill document (SKILL.md) |
| **Test fails (RED)** | Agent skips security steps without skill |
| **Test passes (GREEN)** | Agent follows methodology with skill |
| **Refactor** | Close loopholes (agent bypasses security steps) |

## When to Create a Cybersec Skill

**Create when:**
- New security testing methodology isn't covered by existing skills
- Agent keeps skipping important security steps
- Pattern applies across multiple testing scenarios

**Don't create for:**
- Tool documentation (put in MCP tool description)
- Project-specific testing instructions
- Standard practices well-documented elsewhere

## Skill Structure for Cybersec

```markdown
---
name: cybersec-skill-name
description: Use when [specific security scenario triggers]
---

## [Security Methodology Name]

### Checklist

1. **Step One** — Run `tool_name(params)` for specific purpose
2. **Step Two** — Analyze output for [specific indicators]
3. **Step Three** — Document findings with evidence

### Tools Available
`tool1`, `tool2`, `tool3`

### Next Skill
Load `cybersec-next-phase` when this phase is complete.
```

## CSO for Cybersec Skills

**Search terms agents look for:**
- Attack names: "SQL injection", "XSS", "SSRF", "path traversal"
- Tools: "nmap", "nuclei", "hydra", "hashcat"
- Phases: "recon", "enumeration", "scanning", "exploitation"
- Targets: "web app", "AD", "cloud", "API", "network"

**Description (trigger only, no workflow):**
```yaml
# ✅ GOOD: Trigger conditions only
description: Use when user asks about web application testing, SQL injection, XSS, or API security
```

## RED-GREEN-REFACTOR for Cybersec Skills

### RED: Baseline Without Skill

Run pressure scenario WITHOUT the skill. Document:
- Did agent skip recon? Jump straight to exploit?
- What rationalizations used?

### GREEN: Write Minimal Skill

Write skill addressing those specific failures. Include:
- Checklist with tool names + parameters
- Verification requirement before claims

Re-run same scenario WITH skill. Agent should now follow methodology.

### REFACTOR: Close Loopholes

Agent found exception path? Add explicit counter. Re-test.

## Skill Creation Checklist

- [ ] Name: letters, numbers, hyphens only
- [ ] YAML frontmatter: `name` + `description` only (max 1024 chars)
- [ ] Description starts with "Use when..." + security triggers
- [ ] Description does NOT summarize workflow
- [ ] Checklist with numbered steps referencing MCP tools
- [ ] Tools Available section with backtick names
- [ ] Next Skill transition
- [ ] Run baseline (RED) — document agent failures
- [ ] Run with skill (GREEN) — verify compliance
- [ ] Commit and push

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Description summarizes methodology | Trigger conditions only |
| No HARD-GATE | Focus on methodology steps, not permission checks |
| Vague step: "Scan the target" | Specific: "Run nmap_scan(target, ports='21,22,80')" |
| No tool references | List exact MCP tool names in backticks |
| No next-skill transition | Always chain to next methodology phase |
| Skipping RED phase | Watch agent fail WITHOUT skill first |