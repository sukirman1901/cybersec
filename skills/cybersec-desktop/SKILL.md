---
name: cybersec-desktop
description: Desktop application security testing methodology — static analysis, binaries, configs, Electron
---

## Desktop App Testing Methodology

### 1. Static Analysis
- Extract strings from binaries via `desktop_strings` — find secrets, API keys, URLs
- Check for hardcoded credentials, tokens, private keys
- Analyze entropy to detect obfuscated secrets

### 2. Electron Analysis
- Unpack ASAR via `desktop_electron` — check preload, main process
- Verify security flags: `contextIsolation`, `nodeIntegration`, `enableRemoteModule`
- Check for dangerous IPC patterns, exposed APIs

### 3. Configuration Review
- Scan for config files via `desktop_config` — .env, credentials, settings
- Check for saved passwords, tokens, database credentials
- Verify file permissions on sensitive files

### 4. Package Audit
- Check bundled dependencies via `desktop_packages` for known CVEs
- Review outdated libraries, transitive vulnerabilities

### 5. Entitlements & Permissions
- Check macOS entitlements via `desktop_entitlements` — camera, mic, USB, filesystem
- Review Windows manifest, Linux capabilities
- Document excessive or unnecessary permissions

### 6. Reporting
- Use `report` to generate findings
- Include evidence (file paths, strings, config content)
- Transition to `cybersec-report`

## Tools
- `desktop_strings`, `desktop_electron`, `desktop_config`, `desktop_packages`, `desktop_entitlements`
