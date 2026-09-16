---
name: cybersec-cloud
description: Use when user asks about cloud security, AWS, Azure, GCP, S3 buckets, or cloud enumeration
---

## Cloud Security Testing Methodology

### Checklist

1. **Cloud Resource Enumeration** — Run `cloud_enum(company)` to discover AWS S3, Azure Blob, GCP Storage resources
2. **S3 Bucket Deep Scan** — For each discovered S3 bucket, run `s3_scanner(bucket_name)` to check public access
3. **Cloud IAM Audit** — Run `cloud_iam_audit(target)` for overly permissive roles, public access, cross-account trust
4. **Cloud Infra Enum** — Run `cloud_infra(target)` for open security groups, unencrypted storage, public endpoints
5. **Cloud Config Review** — Run `cloud_audit(target)` for a comprehensive cloud security audit (S3 public, K8s API, Docker socket, IAM, infra)
6. **Container/K8s/Redis** — `docker_scan(target)` (socket exposure, container escape, env leaks), `k8s_scan(target)` (unauthorized API access, secrets, RBAC), `redis_enum(target)` (auth, keyspace, version)
7. **Metadata API Check** — If inside cloud environment, check http://169.254.169.254/latest/meta-data/ (AWS)
8. **Cloud Config Review** — Check for exposed cloud config files (.aws/config, credentials, .env)
9. **DNS Enum** — Use `dns_lookup(target)` to find cloud services (s3, cloudfront, azurewebsites)
10. **SSL Analysis** — Check SSL certs via `ssl_check(target)` for cloud service info in CN/SAN
11. **Cloud API Mass Assignment** — If cloud API endpoints found, call `mass_assignment(target)` for privilege escalation via parameter overwriting
12. **Document Findings** — Public buckets, exposed configs, cloud services in use

### Tools Available
`cloud_enum`, `s3_scanner`, `cloud_audit`, `cloud_iam_audit`, `cloud_infra`, `docker_scan`, `k8s_scan`, `redis_enum`, `dns_lookup`, `ssl_check`, `crt_search`, `dork_search`, `mass_assignment`

### Next Skill
Load `cybersec-report` for final documentation.
