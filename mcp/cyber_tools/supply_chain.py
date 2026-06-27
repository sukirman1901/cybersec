import httpx
import re

KNOWN_VULN_PACKAGES = {
    "lodash": {"max": "4.17.20", "cve": "CVE-2021-23337"},
    "axios": {"max": "0.21.1", "cve": "CVE-2021-3749"},
    "express": {"max": "4.17.1", "cve": "CVE-2022-24999"},
    "guzzlehttp/guzzle": {"max": "6.5.5", "cve": "CVE-2022-29248"},
    "laravel/framework": {"max": "8.83.0", "cve": "CVE-2022-31279"},
    "symfony/http-kernel": {"max": "5.4.12", "cve": "CVE-2022-24894"},
    "django": {"max": "3.2.14", "cve": "CVE-2022-36359"},
    "requests": {"max": "2.28.1", "cve": "CVE-2023-32681"},
    "jinja2": {"max": "3.1.2", "cve": "CVE-2024-22195"},
    "flask": {"max": "2.3.2", "cve": "CVE-2023-30861"},
}

MANIFEST_PATHS = [
    ("package.json", "node_modules|dependencies", r'"(.*?)":\s*"\^?(\d+\.\d+\.\d+)"'),
    ("composer.json", "require|packages", r'"(.*?)":\s*"\^?(\d+\.\d+\.\d+)"'),
    ("requirements.txt", "", r'^([a-zA-Z_][a-zA-Z0-9_-]*)[=~><]+(\d+\.\d+\.?\d*)'),
    ("go.mod", "require", r'(\S+)\s+v(\d+\.\d+\.\d+)'),
    ("Gemfile", "gem", r"gem ['\"](\S+)['\"],\s*['\"]~?>\s*(\d+\.\d+\.?\d*)"),
    ("build.gradle", "implementation", r"implementation\s+['\"](.*?):(.*?):(\d+\.\d+\.?\d*)"),
]


async def supply_chain(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path, indicator, pattern in MANIFEST_PATHS:
            url = f"{base}/{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    content = resp.text
                    deps = re.findall(pattern, content, re.MULTILINE)
                    for dep_match in deps[:50]:
                        dep_name = dep_match[0] if isinstance(dep_match, tuple) else dep_match
                        dep_ver = dep_match[1] if isinstance(dep_match, tuple) else ""
                        vuln_info = KNOWN_VULN_PACKAGES.get(dep_name)
                        if vuln_info:
                            findings.append({"manifest": path, "package": dep_name, "version": dep_ver, "max_safe": vuln_info["max"], "cve": vuln_info["cve"], "severity": "high"})
                    findings.append({"manifest": path, "status": 200, "packages_found": len(deps), "severity": "info"})
            except httpx.HTTPError:
                continue
    return {"target": target, "findings": findings, "count": len(findings)}
