---
name: cybersec-desktop
description: Desktop application security testing methodology — static analysis, binaries, configs, Electron
---

## Desktop App Testing Methodology

Select relevant branches by artifact type and supplied file path; local static
inspection does not launch an app or probe embedded URLs. Before separately
requested active target probes require `engagement_gate` `init` + `authorize`;
confirmed `extend` only for additional user-approved resources. Runtime/mobile
instrumentation requires the specified device/process and consent, not an assumed
connected device. Record coverage/missing tools and redact secrets from strings,
configs, keychain and memory evidence. Missing flags alone are not exploit proof.

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

### 6. Mobile Apps (APK/IPA/iOS)
- Analyze Android APK: `apk_analyze` — permissions, exported activities, package name, suspicious files
- Analyze iOS IPA: `ipa_analyze` — metadata, entitlements, plist, permissions
- iOS data at rest: `ios_data_storage` — insecure local storage patterns
- iOS runtime: `ios_frida` (SSL pinning bypass, method tracing, process list), `ios_objection` (keychain dump, sqlite, nsuserdefaults)
- iOS signing: `ios_signing` — provisioning profile, team ID, ad-hoc vs distribution
- Mobile TLS: `ssl_pinning_check` — cert verification behavior, HSTS

### 7. Reporting
- Use `generate_report` to generate findings
- Include evidence (file paths, strings, config content)
- Transition to `cybersec-report`

## Tools
- `desktop_strings`, `desktop_electron`, `desktop_config`, `desktop_packages`, `desktop_entitlements`, `binary_checksec`, `apk_analyze`, `ipa_analyze`, `ios_data_storage`, `ios_frida`, `ios_objection`, `ios_signing`, `ssl_pinning_check`
