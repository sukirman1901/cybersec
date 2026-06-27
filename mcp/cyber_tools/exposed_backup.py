import httpx

EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".swp", ".swo",
    "~", ".save", ".save.1", ".local", ".private", ".default",
    ".sql", ".dump", ".csv", ".tar", ".zip", ".gz", ".7z", ".rar",
]

BASE_FILES = [
    "index.php", "index.html", "index.js", "config.php", "config.json",
    "config.yaml", "config.local.php", "database.php", "db.php",
    ".env", ".env.local", ".env.production", ".env.development",
    "wp-config.php", "wp-config", "settings.php", "settings",
    "app.php", "app.conf", "nginx.conf", ".htaccess",
    "composer.json", "package.json", "yarn.lock", "package-lock.json",
    "dump.sql", "backup.sql", "export.sql",
]


async def exposed_backup(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        known_paths = list(set(BASE_FILES + __import__("re").findall(r'(?:src|href)=["\']([^"\']+)["\']', resp_root.text)[:10]))
        for base_file in known_paths[:30]:
            for ext in EXTENSIONS:
                path = f"/{base_file}{ext}" if not base_file.startswith("/") else f"{base_file}{ext}"
                url = f"{base}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        severity = "critical" if any(k in path.lower() for k in [".env", "config", "database", "dump", "backup", "wp-config"]) else "high"
                        findings.append({"path": path, "status": 200, "size": len(resp.text), "severity": severity})
                except httpx.HTTPError:
                    continue
    return {"target": target, "findings": findings, "backup_exposed": len(findings) > 0, "count": len(findings)}
