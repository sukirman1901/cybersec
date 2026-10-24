---
name: cybersec-password
description: Use when user asks about password cracking, hash identification, brute force, or credential attacks
---

## Password Security Testing Methodology

### Checklist

Select relevant offline or online branches from the actual input. For hash-only
identification use `hash_analyze`/`hash_detect`, explain ambiguity and stop: do not
crack, discover services or perform online guessing. Cracking needs a separately
requested offline task and owned hash material. Before active target probes require
`engagement_gate` `init` + `authorize`; confirmed `extend` only for additional
user-approved resources. Online guessing needs named service/accounts, lockout
policy, bounded attempts and stop-on-lockout/throttling, not just a supplied hash.
Record coverage and redact recovered passwords, hashes and credentials in evidence.

1. **Hash Identification** — Run `hash_analyze(hash)` or `hash_detect(hash)` to identify the hash type (MD5, SHA1, bcrypt, NTLM, argon2, 20+ more)
2. **Crack Command** — Use the hashcat mode from hash_analyze to construct crack command
3. **Online Brute Force** — Run `hydra_brute(target, service, username)` for online password guessing
4. **Nmap Scan** — If brute forcing services, run `nmap_scan(target, ports)` to discover available login services
5. **Credential Analysis** — Check for default credentials, weak password patterns
6. **Wordlist Suggestion** — Recommend appropriate wordlist based on target (rockyou, SecLists); manage custom lists with `custom_wordlist` (create, merge, generate, import, builtin, append)
7. **Document Results** — Cracked passwords, weak credentials, recommendations

### Tools Available
`hash_analyze`, `hash_detect`, `custom_wordlist`, `hydra_brute`, `nmap_scan`, `ssh_audit`, `smb_enum`, `cve_search`

### Next Skill
Load `cybersec-report` for final documentation.
