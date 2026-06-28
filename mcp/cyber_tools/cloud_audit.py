"""Comprehensive cloud security audit — aggregates cloud_enum, S3, IAM, infra, K8s, Docker."""
import json
import urllib.request
import socket
import hashlib

def cloud_audit(provider: str = "aws", targets: str = "", company: str = "", buckets: str = "", project: str = "") -> str:
    result = {
        "provider": provider,
        "audits": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "total_findings": 0
    }

    if company and provider == "aws":
        result["audits"].append({"audit": "cloud_enum", "result": _cloud_enum(company)})
    if buckets:
        for bucket in buckets.split(","):
            bucket = bucket.strip()
            r = _s3_check(bucket)
            result["audits"].append({"audit": "s3_public", "bucket": bucket, "result": r})
    if targets:
        for target in targets.split(","):
            target = target.strip()
            result["audits"].append({"audit": "k8s", "target": target, "result": _k8s_check(target)})
            result["audits"].append({"audit": "docker", "target": target, "result": _docker_check(target)})

    result["audits"].append({"audit": "iam_audit", "provider": provider, "result": _iam_check(provider)})
    result["audits"].append({"audit": "infra_audit", "provider": provider, "result": _infra_check(provider)})

    for a in result["audits"]:
        findings = a.get("result", {}).get("issues", a.get("result", {}).get("findings", []))
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in result["summary"]:
                result["summary"][sev] += 1
            result["total_findings"] += 1

    if result["total_findings"] == 0:
        result["overall"] = "No cloud security issues detected"
    elif result["summary"]["critical"] > 0 or result["summary"]["high"] > 0:
        result["overall"] = "Critical cloud misconfigurations detected"
    else:
        result["overall"] = "Minor cloud issues detected"

    return json.dumps(result, indent=2)


def _cloud_enum(company):
    findings = []
    for suffix in ["", "-dev", "-prod", "-staging", "-test", "-backup", "-qa"]:
        for tld in [".s3.amazonaws.com", ".storage.googleapis.com", ".blob.core.windows.net"]:
            bucket = company.lower().replace(" ", "-") + suffix
            url = f"https://{bucket}{tld}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Cybersec-CloudAudit/1.0"}, method="HEAD")
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status in (200, 403):
                    findings.append({"type": "cloud_storage_found", "url": url, "http_status": resp.status, "severity": "high" if resp.status == 200 else "medium"})
            except urllib.error.HTTPError as e:
                if e.code in (200, 403):
                    findings.append({"type": "storage_exists", "url": url, "http_status": e.code, "severity": "low"})
            except Exception:
                pass
    return {"company": company, "findings": findings, "total": len(findings)}


def _s3_check(bucket_name):
    findings = []
    for region in ["us-east-1", "eu-west-1", "ap-southeast-1"]:
        url = f"https://{bucket_name}.s3.{region}.amazonaws.com/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Cybersec-CloudAudit/1.0"})
            resp = urllib.request.urlopen(req, timeout=8)
            body = resp.read().decode("utf-8", errors="ignore")
            if "<ListBucketResult" in body:
                findings.append({"type": "s3_public_listing", "bucket": bucket_name, "region": region, "severity": "critical", "evidence": "Bucket contents are publicly listable"})
            else:
                findings.append({"type": "s3_public_access", "bucket": bucket_name, "region": region, "severity": "high"})
        except urllib.error.HTTPError as e:
            if e.code == 403:
                findings.append({"type": "s3_exists_but_denied", "bucket": bucket_name, "region": region, "severity": "info"})
            elif e.code == 404:
                pass
        except Exception:
            pass
    return {"bucket": bucket_name, "regions_checked": 3, "findings": findings, "is_public": any(f["severity"] == "critical" for f in findings)}


def _k8s_check(target):
    findings = []
    url = f"https://{target}/api/v1" if not target.startswith("http") else f"{target}/api/v1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Cybersec-CloudAudit/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read().decode("utf-8", errors="ignore")
        findings.append({"type": "k8s_api_unauthenticated", "target": target, "severity": "critical", "evidence": "K8s API accessible without auth"})
    except urllib.error.HTTPError as e:
        if e.code == 401:
            findings.append({"type": "k8s_api_protected", "target": target, "severity": "info"})
        elif e.code == 403:
            findings.append({"type": "k8s_api_auth_required", "target": target, "severity": "low"})
    except Exception:
        pass

    url2 = f"https://{target}/api/v1/namespaces/kube-system/secrets" if not target.startswith("http") else f"{target}/api/v1/namespaces/kube-system/secrets"
    try:
        req = urllib.request.Request(url2, headers={"User-Agent": "Cybersec-CloudAudit/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        findings.append({"type": "k8s_secret_access_unauthenticated", "target": target, "severity": "critical", "evidence": "K8s secrets accessible without auth"})
    except Exception:
        pass
    return {"target": target, "findings": findings}


def _docker_check(target):
    findings = []
    protocols = [
        ("unix", "unix:///var/run/docker.sock"),  # local
        ("tcp", f"tcp://{target}:2375"),
        ("tcp_tls", f"https://{target}:2376"),
    ]
    for proto, addr in protocols:
        try:
            if proto == "unix":
                import http.client
                c = http.client.HTTPConnection("localhost", 0)
                c.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c.sock.connect("/var/run/docker.sock")
                c.request("GET", "/containers/json")
                resp = c.getresponse()
                if resp.status == 200:
                    findings.append({"type": "docker_socket_exposed", "address": addr, "severity": "critical", "evidence": "Docker socket accessible"})
            else:
                url = f"{addr}/containers/json" if proto == "tcp" else f"{addr}/containers/json"
                req = urllib.request.Request(url, headers={"User-Agent": "Cybersec-CloudAudit/1.0"})
                resp = urllib.request.urlopen(req, timeout=8)
                if resp.status == 200:
                    findings.append({"type": "docker_api_exposed", "address": addr, "severity": "critical", "evidence": "Docker API accessible without auth"})
        except Exception:
            pass
    return {"target": target, "findings": findings}


def _iam_check(provider):
    return {
        "provider": provider,
        "findings": [
            {"type": "iam_audit_skipped", "severity": "info", "note": "Full IAM audit requires cloud credentials. Configure AWS CLI / gcloud / az CLI for detailed scan."},
            {"type": "recommendation", "severity": "low", "note": "Check for: overly permissive roles (*:* permissions), public S3 buckets, cross-account trust policies, unused access keys, MFA not enforced for root/admin."},
        ]
    }


def _infra_check(provider):
    return {
        "provider": provider,
        "findings": [
            {"type": "infra_audit_skipped", "severity": "info", "note": "Full infra audit requires cloud credentials. Use cloud provider CLI tools for deep scan."},
            {"type": "recommendation", "severity": "low", "note": "Check for: open security groups (0.0.0.0/0), unencrypted EBS volumes, public RDS instances, public load balancers, missing VPC flow logs."},
        ]
    }