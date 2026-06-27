import httpx
import re

GITHUB_ACTIONS_MISCONFIG = [
    ("pull_request_target", "branches: \\*", "critical", "PR target with wildcard — branch injection possible"),
    ("GITHUB_TOKEN", "write|contents: write|issues: write", "high", "Excessive token permissions"),
    ("pull_request", "ACTIONS_ALLOW_INSECURE", "high", "Insecure action execution"),
    ("env:", "secret|api_key|password", "critical", "Secrets in env block"),
]

GITLAB_CI_MISCONFIG = [
    ("script:", "curl|wget.*\\|\\s*bash", "high", "Piped curl to bash — supply chain risk"),
    ("env:", "CI_JOB_TOKEN|api_key|password", "critical", "Secrets in CI env"),
]

PATHS = [
    "/.github/workflows/",
    "/.github/workflows/main.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/.circleci/config.yml",
    "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml",
    "/Dockerfile",
    "/docker-compose.yml",
]

SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'sk-[a-zA-Z0-9]{20,}',
    r'xox[baprs]-[0-9a-zA-Z-]{10,}',
    r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
]


async def ci_cd_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        if "github" in resp_root.text.lower() or "gitlab" in resp_root.text.lower() or "docker" in resp_root.text.lower():
            findings.append({"finding": "CI/CD indicators in page source", "severity": "info"})
        for path in PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    content = resp.text
                    file_findings = []
                    for pattern in SECRET_PATTERNS:
                        matches = re.findall(pattern, content)
                        for m in matches:
                            file_findings.append({"secret_type": pattern.replace(r'[','').replace(r'\w','').replace(r'{','')[:30], "match": m[:20] + "...", "severity": "critical"})
                    if "github" in path or "actions" in path:
                        for sig_name, trigger, severity, note in GITHUB_ACTIONS_MISCONFIG:
                            if sig_name in content and trigger.replace("\\*", "*") in content:
                                file_findings.append({"finding": f"{sig_name} — {note}", "severity": severity})
                    if "gitlab" in path:
                        for sig_name, trigger, severity, note in GITLAB_CI_MISCONFIG:
                            if sig_name in content and trigger in content:
                                file_findings.append({"finding": f"{sig_name} — {note}", "severity": severity})
                    if file_findings:
                        findings.append({"path": path, "issues": file_findings})
                    else:
                        findings.append({"path": path, "status": 200, "severity": "info", "note": "CI/CD file accessible"})
            except httpx.HTTPError:
                continue
    return {"target": target, "findings": findings, "count": len(findings)}
