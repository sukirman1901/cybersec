---
name: cybersec-ad
description: Use when user asks about Active Directory, domain enumeration, Kerberos, or AD attacks
---

<HARD-GATE>
Do NOT run AD attacks without first identifying domain controllers and understanding the domain structure.
AD attacks can disrupt production — always warn user before running kerberos or privesc attacks.
</HARD-GATE>

## Active Directory Security Methodology

### Checklist

1. **Domain Discovery** — Run `ldap_enum(domain_controller)` for LDAP anonymous bind and domain info
2. **Port Scan DC** — Run `nmap_scan(target, ports="88,389,445,464,636,3268,3269", scripts="ldap*")` on domain controllers
3. **BloodHound Collection** — Run `bloodhound_collect(domain, username, password)` to gather AD relationship data
4. **Kerberos Enum** — Check if AS-REP roasting or Kerberoasting is possible via servicePrincipalName
5. **SMB Enum** — Run `smb_enum(target)` on domain controllers for SMB access
6. **Password Policy** — Check domain password policy via SMB or LDAP
7. **Privilege Escalation** — Check for common AD privesc paths (ACL abuse, Group Policy, constrained delegation)
8. **Document Findings** — Compile AD attack paths and recommended mitigations

### Tools Available
`ldap_enum`, `nmap_scan`, `bloodhound_collect`, `smb_enum`, `ssh_audit`, `cve_search`

### Next Skill
Load `cybersec-password` if password/hash attacks are relevant, otherwise `cybersec-report`.
