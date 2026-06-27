---
name: cybersec-password
description: Use when user asks about password cracking, hash identification, brute force, or credential attacks
---

<HARD-GATE>
Do NOT brute force passwords without explicit authorization.
Hash cracking is offline and safe — but only crack hashes you are authorized to test.
Always identify hash type before attempting to crack.
</HARD-GATE>

## Password Security Testing Methodology

### Checklist

1. **Hash Identification** — Run `hash_analyze(hash)` to identify the hash type (MD5, SHA1, bcrypt, NTLM, etc.)
2. **Crack Command** — Use the hashcat mode from hash_analyze to construct crack command
3. **Online Brute Force** — If authorized, run `hydra_brute(target, service, username)` for online password guessing
4. **Nmap Scan** — If brute forcing services, run `nmap_scan(target, ports)` to discover available login services
5. **Credential Analysis** — Check for default credentials, weak password patterns
6. **Wordlist Suggestion** — Recommend appropriate wordlist based on target (rockyou, SecLists, custom)
7. **Document Results** — Cracked passwords, weak credentials, recommendations

### Tools Available
`hash_analyze`, `hydra_brute`, `nmap_scan`, `ssh_audit`, `smb_enum`, `cve_search`

### Next Skill
Load `cybersec-report` for final documentation.
