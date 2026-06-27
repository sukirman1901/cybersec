import httpx
import re

GIT_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.gitignore",
    "/.gitattributes",
    "/.gitmodules",
    "/.git/objects/info/packs",
    "/.git/info/exclude",
    "/.git/description",
]

INTERESTING_FILES = [
    "/.git/config",
    "/.git/logs/HEAD",
    "/.git/index",
]


async def exposed_git(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in GIT_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 5:
                    content_sample = resp.text[:200]
                    severity = "critical" if path in INTERESTING_FILES else "high"
                    findings.append({"path": path, "status": 200, "size": len(resp.text), "severity": severity, "preview": content_sample[:100]})
            except httpx.HTTPError:
                continue
    return {"target": target, "findings": findings, "git_exposed": len(findings) > 0, "count": len(findings)}
