---
name: cybersec-parallel
description: Use when facing 2+ independent targets, scans, or testing tasks that can run concurrently without shared state
---

# Cybersec Parallel Agent Dispatch

## Overview

Select relevant independent tasks only when host delegation is exposed and allowed;
otherwise use sequential tools. Before active target probes require `engagement_gate`
`init` + `authorize` in the tool session; confirmed `extend` only for additional
user-approved resources, never discovered hosts/buckets. Workers must not re-init
shared scope or assume another session's authorization transfers. Record coverage,
redact secrets before delegation/output, and stop denied branches. Assign a shared
request/time/concurrency budget divided among workers; cancel remaining probes on
scope change, throttling, owner cancellation or unexpected side effects. Aggregate
completed, cancelled and skipped tasks without calling partial coverage complete.

When you have multiple independent targets to scan (different hosts, different services, different testing domains), running them sequentially wastes time. Each scan is independent and can happen in parallel.

**Core principle:** Dispatch one agent per independent target or testing domain. Let them work concurrently.

## When to Use

```
      ┌─────────────────────┐
      │ Multiple targets?   │──no──→ Sequential scan
      └──────────┬──────────┘
                 │ yes
                 ↓
      ┌─────────────────────┐
      │ Are they            │──no──→ Single agent handles all
      │ independent?        │       (related targets)
      └──────────┬──────────┘
                 │ yes
                 ↓
      ┌─────────────────────┐
      │ Can they run        │──no──→ Sequential agents
      │ in parallel?        │       (shared infra/creds)
      └──────────┬──────────┘
                 │ yes
                 ↓
      ┌─────────────────────┐
      │ PARALLEL DISPATCH   │
      └─────────────────────┘
```

**Use when:**
- Multiple target hosts to scan independently
- Different testing phases (recon AND vuln scan on different targets)
- Independent testing domains (web app AND network infra)
- Multiple S3 buckets to check simultaneously
- No shared state between investigations

**Don't use when:**
- Targets are related (findings on one affect others)
- Shared credentials or rate limits
- Second scan depends on first scan's results
- Agents would interfere (same target, resource contention)

## The Pattern

### 1. Identify Independent Testing Domains

Group by independent scope:
- **Network scan** — Target A: external perimeter
- **Network scan** — Target B: internal segment
- **Web app** — Target C: web application
- **Cloud** — S3 buckets for company X
- **OSINT** — Target D: passive recon

Each domain is a separate security concern with independent results.

### 2. Create Focused Agent Tasks

Each agent gets:
- **Specific scope:** One target or testing domain
- **Clear goal:** Complete the defined scan/test
- **Constraints:** Don't modify targets, don't exceed rate limits
- **Expected output:** Summary of findings for each test run

### 3. Dispatch in Parallel

```
Agent 1 → nmap_scan(target_A) + service_fingerprint on open ports
Agent 2 → nmap_scan(target_B) + ssl_check on web ports
Agent 3 → subdomain_enum(target_C); probe only already-authorized subdomains
Agent 4 → cloud_enum(company); s3_scanner only for authorized bucket names
```

### 4. Review and Aggregate

When agents return:
- Read each summary of findings
- Merge results into combined report
- Verify no port/service was missed
- Identify cross-cutting findings (same service on multiple targets)

## Agent Prompt Template

```
Scan [TARGET / DOMAIN] for security findings:

Target: [IP or domain]
Scope: [ports, services, or tests to run]
Tools to use: [specific tool names]

Your task:
1. Run [tool_1] with appropriate parameters
2. Run [tool_2] on findings from step 1
3. Collect minimal relevant evidence (success + errors), redacting secrets/PII
4. Return: Redacted evidence + findings/status/coverage summary

Keep request/time budget and stop reasons. Exploit requests still require scope,
technique approval and approval_artifact where required; never escalate automatically.
```

## Common Mistakes

**❌ Too broad:** "Scan everything" — agent gets lost
**✅ Specific:** "Scan target_A port 80,443 + probe HTTP services"

**❌ No output requirement:** Agent might just say "Done"
**✅ Output:** "Return redacted evidence from each tool + summary/coverage table"

**❌ No constraints:** Agent might run hydra_brute without authorization
**✅ Constraints:** "Passive recon only, no brute force"

**❌ Overlapping agents:** Two agents scanning same target
**✅ Isolation:** Each agent has unique target scope

## Security Testing Example

**Scenario:** 4 targets for initial recon

**Dispatch:**
```
Agent 1 → Target A (web app): nmap web ports + http_probe_target + waf_detection
Agent 2 → Target B (API): nmap + ssl_check + graphql_introspect + api_fuzz
Agent 3 → Target C (infra): nmap full common ports + ssh_audit
Agent 4 → Target D (cloud): cloud_enum + dns_lookup + crt_search
```

**Results:**
- Agent 1: Web app on 80/443, WAF detected (Cloudflare), tech: nginx
- Agent 2: API on 8443, no GraphQL, REST endpoints found via api_fuzz
- Agent 3: SSH on 22 (OpenSSH 8.9), SMTP on 25
- Agent 4: 2 S3 buckets found, 1 publicly accessible

**Integration:** Combined into single recon report. No overlap, no conflicts.

**Time saved:** 4 scans in parallel vs 1 at a time

## Key Benefits

1. **Parallelization** — N targets scanned in time of 1
2. **Focus** — Each agent has narrow scope
3. **Independence** — Agents don't interfere
4. **Speed** — Complete recon phase in minutes instead of hours

## Verification

After agents return:
1. **Review each summary** — What was found?
2. **Check for gaps** — Were all intended targets covered?
3. **Run cross-cutting checks** — Any findings connecting targets?
4. **Verify findings** — Use cybersec-verification on key results

## When NOT to Use

**Related targets:** Target B is inside Target A's network — scan A first
**Sequential dependency:** Need subdomain list before HTTP probing that domain
**Rate limiting:** Target has WAF/rate limits — sequential with delays
