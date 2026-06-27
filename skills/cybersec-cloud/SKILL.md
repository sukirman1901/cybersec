---
name: cybersec-cloud
description: Use when user asks about cloud security, AWS, Azure, GCP, S3 buckets, or cloud enumeration
---

<HARD-GATE>
Do NOT access cloud resources without explicit authorization.
Cloud enumeration is passive (checking bucket existence, not accessing content) unless user confirms authorization.
</HARD-GATE>

## Cloud Security Testing Methodology

### Checklist

1. **Cloud Resource Enumeration** — Run `cloud_enum(company)` to discover AWS S3, Azure Blob, GCP Storage resources
2. **S3 Bucket Deep Scan** — For each discovered S3 bucket, run `s3_scanner(bucket_name)` to check public access
3. **Metadata API Check** — If inside cloud environment, check http://169.254.169.254/latest/meta-data/ (AWS)
4. **Cloud Config Review** — Check for exposed cloud config files (.aws/config, credentials, .env)
5. **DNS Enum** — Use `dns_lookup(target)` to find cloud services (s3, cloudfront, azurewebsites)
6. **SSL Analysis** — Check SSL certs via `ssl_check(target)` for cloud service info in CN/SAN
7. **Document Findings** — Public buckets, exposed configs, cloud services in use

### Tools Available
`cloud_enum`, `s3_scanner`, `dns_lookup`, `ssl_check`, `crt_search`, `dork_search`

### Next Skill
Load `cybersec-report` for final documentation.
