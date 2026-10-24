---
name: cybersec-scanning
description: Use when user asks to scan ports, detect services, or fingerprint a target
---

## Port Scanning & Service Detection Methodology

### Checklist

Select relevant protocols/ports for the requested outcome, not every service.
Before active target probes require `engagement_gate` `init` + `authorize`;
confirmed `extend` only for additional user-approved resources. Record coverage,
request/time budget and skips; redact secrets in banners. For TLS-only requests,
use `ssl_check` on the specified host/port: no port discovery, SSH/SMB checks,
directory scans or vulnerability escalation. Deep TLS tools are optional only
within requested depth/budget. A timeout is inconclusive, not a closed/safe port.

1. **Port Scan** — Call `port_scan(target)` with common ports (21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443)
2. **Service Detection** — For each open port, identify service name and version
3. **Deep Fingerprint** — Call `service_fingerprint(target, port)` on key ports for banner grabs
4. **SSH Audit** — If port 22 open, call `ssh_audit(target)` for SSH banner + weak algorithms
5. **SMTP Enum** — If port 25 open, call `smtp_enum(target)` for user enumeration
6. **SMB Check** — If port 445 open, call `smb_enum(target)` for SMB availability
7. **SNMP Check** — If port 161 open, call `snmp_enum(target)` for SNMP info
8. **Web Probe** — For web ports (80,443,8080,8443), call `http_probe_target(target)`
9. **SSL/TLS Analysis** — If HTTPS found, call `ssl_check(target)` for cert + protocol issues
10. **Deep SSL Scan** — If SSL issues found, call `testssl_check(target)` and `sslyze_check(target)` for deeper analysis
11. **WAF Detection** — If web service found, call `waf_detection(target)`

### Tools Available
`port_scan`, `service_fingerprint`, `ssh_audit`, `smtp_enum`, `smb_enum`, `snmp_enum`, `http_probe_target`, `ssl_check`, `testssl_check`, `sslyze_check`, `waf_detection`, `masscan_scan`

### Output
Table of open ports with: port number, service name, version, banner, and security notes (weak ciphers, old protocols).

### Next Skill
Load `cybersec-vulns` only if a vulnerability assessment is requested and authorized.
