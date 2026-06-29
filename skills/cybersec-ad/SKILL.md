---
name: cybersec-ad
description: Use when user asks about Active Directory, domain enumeration, Kerberos, or AD attacks
---

## Active Directory Security Methodology

### Checklist

1. **Domain Discovery** — Run `ad_enum(domain, dc_ip, username, password)` for comprehensive AD enumeration (users, groups, computers, trusts, password policy)
2. **Port Scan DC** — Run `nmap_scan(target, ports="88,389,445,464,636,3268,3269", scripts="ldap*")` on domain controllers
3. **BloodHound Collection** — Run `bloodhound_collect(domain, username, password)` to gather AD relationship data
4. **Kerberoasting** — Run `ad_kerberoast(domain, dc_ip, username, password)` to request TGS tickets for SPN accounts and return crackable hashes
5. **AS-REP Roasting** — Run `ad_asrep_roast(domain, dc_ip, username, password)` to target accounts with DONT_REQUIRE_PREAUTH
6. **AD CS Abuse** — Run `ad_certipy("find", target, username, password, domain, dc_ip)` to enumerate certificate services (ESC1-ESC15)
7. **Password Spraying** — Run `ad_spray(domain, dc_ip, password, usernames)` to test credentials while respecting lockout policy
8. **DCSync** — Run `ad_dcsync(domain, dc_ip, username, password, target_user)` to extract password hashes (requires Domain Admin)
9. **Pass-the-Hash** — Run `ad_passthehash(target, username, nt_hash, domain, command, protocol)` for lateral movement with stolen hashes
10. **NTLM Relay** — Run `ad_ntlm_relay(target, command)` to relay captured authentications
11. **Document Findings** — Compile AD attack paths and recommended mitigations

### Tools Available
`ad_enum`, `ad_kerberoast`, `ad_asrep_roast`, `ad_dcsync`, `ad_passthehash`, `ad_certipy`, `ad_spray`, `ad_ntlm_relay`, `ldap_enum`, `nmap_scan`, `bloodhound_collect`, `smb_enum`, `ssh_audit`, `cve_search`

### Next Skill
Load `cybersec-password` if password/hash attacks are relevant, otherwise `cybersec-report`.
