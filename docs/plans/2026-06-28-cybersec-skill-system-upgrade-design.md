# Cybersec Skill System Upgrade — Superpowers-Style

## Goal
Upgrade cybersec plugin's 8 skills to work like Superpowers: hard-gate enforcement, workflow chains, checklists with TodoWrite, and mandatory skill loading via `skill` tool.

## Changes

### 1. Bootstrap (`using-cybersec/SKILL.md`)
- Inject `CYBERSEC SUPERPOWERS` at session start
- Mandate `skill` tool usage before any response
- List all 7 methodology skills with trigger keywords
- SUBAGENT-STOP gate
- Define workflow chain: Recon → Scanning → Vulns → Web → Exploit → Crisis → Report

### 2. Each methodology skill gets:
- **HARD-GATE** block: prevents skipping steps
- **Checklist**: numbered items with TodoWrite
- **MCP tool references**: which tools to call at each step
- **Workflow transition**: which skill to load next
- **Output specification**: what to produce

### 3. Workflow Chain
```
Recon → Scanning → Vulns → Web → Exploit → Report
                                          ↑
                                     Crisis (parallel path)
```

### 4. Files to Modify
- `skills/using-cybersec/SKILL.md` — bootstrap
- `skills/cybersec-recon/SKILL.md`
- `skills/cybersec-scanning/SKILL.md`
- `skills/cybersec-vulns/SKILL.md`
- `skills/cybersec-web/SKILL.md`
- `skills/cybersec-exploit/SKILL.md`
- `skills/cybersec-crisis/SKILL.md`
- `skills/cybersec-report/SKILL.md`
