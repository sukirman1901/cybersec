# Cybersec Plugin — Phase 2: Enterprise Pentesting Expansion

## Goal
Add 8 new MCP tools + 3 new methodology skills for enterprise penetration testing: Active Directory, Cloud Security, and Password Attacks.

## New Skills
1. `cybersec-ad` — AD security: domain enum, Kerberos, BloodHound, LDAP, privilege escalation
2. `cybersec-cloud` — Cloud security: bucket discovery, metadata APIs, S3 enumeration
3. `cybersec-password` — Password attacks: hash identification, brute force, cracking

## New Tools
1. `nmap_scan` — CLI wrapper for nmap (service scripts, OS detection)
2. `ldap_enum` — Pure Python LDAP enumeration (anonymous bind, user listing)
3. `bloodhound_collect` — CLI wrapper for BloodHound ingestor
4. `hash_analyze` — Pure Python hash type identification (regex-based)
5. `hydra_brute` — CLI wrapper for hydra password brute forcing
6. `cloud_enum` — Pure Python cloud bucket/service discovery
7. `s3_scanner` — Pure Python S3 bucket listing
8. `searchsploit` — CLI wrapper for exploit-db search

## Files to Create/Modify
- `mcp/cyber_tools/nmap_scan.py` (new)
- `mcp/cyber_tools/ldap_enum.py` (new)
- `mcp/cyber_tools/bloodhound_collect.py` (new)
- `mcp/cyber_tools/hash_analyze.py` (new)
- `mcp/cyber_tools/hydra_brute.py` (new)
- `mcp/cyber_tools/cloud_enum.py` (new)
- `mcp/cyber_tools/s3_scanner.py` (new)
- `mcp/cyber_tools/searchsploit.py` (new)
- `mcp/server.py` (update: register 8 tools)
- `skills/cybersec-ad/SKILL.md` (new)
- `skills/cybersec-cloud/SKILL.md` (new)
- `skills/cybersec-password/SKILL.md` (new)
- `skills/using-cybersec/SKILL.md` (update: add 3 new skills)

## Workflow Chain Update
```
Recon → OSINT → Scanning → Vulns → Web → Bug Bounty → [Password] → Exploit → Report
                                                ↑
                                          [AD] [Cloud] (parallel paths when relevant)
```
