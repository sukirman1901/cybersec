---
name: cybersec-cloud
description: Use when user asks about cloud security, AWS, Azure, GCP, S3 buckets, or cloud enumeration
---

## Cloud Security Testing Methodology

### Checklist

Select relevant resources, not all provider checks. Before active target probes,
use `engagement_gate` `init` + `authorize` with actual authorized providers,
companies, buckets and targets. For additional user-approved resources, use
`engagement_gate(action="extend", scope_json=additional_scope, confirmation="yes")`
only after actual confirmation. Discovery is not authorization; do not auto-extend.
`init` replaces the engagement and revokes prior approval; `extend` preserves it.
Honor provider/config/path/bucket-specific inputs, record coverage, redact secrets
and stop denied branches. Supplied config review stays offline; CLI/cloud-account
access requires the named account and read-only credentials, never assumed access.
1. **Cloud Resource Enumeration** — Run `cloud_enum(company)` to discover AWS S3, Azure Blob, GCP Storage resources
2. **S3 Bucket Deep Scan** — For each explicitly authorized bucket, run `s3_scanner(bucket_name=bucket)` to check public access
3. **Cloud IAM Audit** — `cloud_iam_audit(provider="aws")` selects a provider, not a target URL; require authorized account access in the configured CLI context (do not invent profile/config arguments)
4. **Cloud Infra Enum** — `cloud_infra(provider="aws")` selects a provider, not a target URL; require authorized account access in the configured CLI context
5. **Cloud Audit** — `cloud_audit(provider="aws", buckets=bucket_names)` for authorized bucket names serialized as the live schema expects; use `targets` only for explicitly authorized endpoints. Supplied local configs are reviewed offline, not passed as URLs
6. **Container/K8s/Redis** — `docker_scan(target)` (socket exposure, container escape, env leaks), `k8s_scan(target)` (unauthorized API access, secrets, RBAC), `redis_enum(target)` (auth, keyspace, version)
7. **Metadata API Check** — Only if explicitly requested on an authorized cloud instance; do not query the agent host metadata service or harvest instance credentials
8. **Cloud Config Review** — Check for exposed cloud config files (.aws/config, credentials, .env)
9. **DNS Enum** — Use `dns_lookup(target)` to find cloud services (s3, cloudfront, azurewebsites)
10. **SSL Analysis** — Check SSL certs via `ssl_check(target)` for cloud service info in CN/SAN
11. **Cloud API Mass Assignment** — If cloud API endpoints found, call `mass_assignment(target)` for privilege escalation via parameter overwriting
12. **Document Findings** — Public buckets, exposed configs, cloud services in use

### Tools Available
`cloud_enum`, `s3_scanner`, `cloud_audit`, `cloud_iam_audit`, `cloud_infra`, `docker_scan`, `k8s_scan`, `redis_enum`, `dns_lookup`, `ssl_check`, `crt_search`, `dork_search`, `mass_assignment`

### Next Skill
Load `cybersec-report` for final documentation.
