import os
import re


# Known vulnerable packages: {name: {min_safe_version, cve}}
KNOWN_VULN_PACKAGES = {
    'electron': {'min_safe': '22.0.0', 'cve': 'CVE-2023-23623'},
    'react': {'min_safe': '18.2.0', 'cve': 'CVE-2023-44269'},
    'lodash': {'min_safe': '4.17.21', 'cve': 'CVE-2023-26136'},
    'axios': {'min_safe': '1.6.0', 'cve': 'CVE-2023-45857'},
    'express': {'min_safe': '4.18.2', 'cve': 'CVE-2023-45684'},
    'jquery': {'min_safe': '3.5.0', 'cve': 'CVE-2023-26183'},
}

# Manifest files to check
MANIFEST_PATTERNS = {
    'package.json': (r'"([^"]+)"\s*:\s*"([^"]+)"', 'npm'),
    'requirements.txt': (r'^([a-zA-Z0-9_.-]+)\s*[=~>]{1,2}\s*([\d.]+)', 'pip'),
    'Cargo.toml': (r'^([a-zA-Z0-9_-]+)\s*=\s*"([\d.]+)"', 'cargo'),
    'go.mod': (r'^\s+([a-zA-Z0-9_./-]+)\s+v?([\d.]+)', 'go'),
}


def _parse_version(version_str: str):
    """Safely parse a version string into a comparable tuple of ints."""
    try:
        # Strip leading ^, ~, >=, <=, = for npm-style semver
        cleaned = re.sub(r'^[\^~>=<]+\s*', '', version_str.strip())
        parts = []
        for part in cleaned.split('.'):
            try:
                parts.append(int(part))
            except ValueError:
                parts.append(0)
        return tuple(parts)
    except Exception:
        return None


def _scan_manifest(filepath: str, pattern: re.Pattern, pkg_type: str) -> list:
    """Scan a single manifest file for known vulnerable packages."""
    findings = []
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()

        if pkg_type == 'npm':
            # Parse package.json — look for top-level dependencies/devDependencies
            import json
            try:
                data = json.loads(content)
                for section in ['dependencies', 'devDependencies', 'peerDependencies']:
                    deps = data.get(section, {})
                    for name, ver in deps.items():
                        if name.lower() in KNOWN_VULN_PACKAGES:
                            vuln = KNOWN_VULN_PACKAGES[name.lower()]
                            parsed = _parse_version(ver)
                            safe = _parse_version(vuln['min_safe'])
                            if parsed and safe and parsed < safe:
                                findings.append({
                                    "package": name,
                                    "version": ver,
                                    "min_safe_version": vuln['min_safe'],
                                    "cve": vuln['cve'],
                                })
            except json.JSONDecodeError:
                pass
        else:
            for match in re.finditer(pattern, content, re.MULTILINE):
                name, ver = match.groups()
                base_name = name.split('/')[-1].lower()
                if base_name in KNOWN_VULN_PACKAGES:
                    vuln = KNOWN_VULN_PACKAGES[base_name]
                    parsed = _parse_version(ver)
                    safe = _parse_version(vuln['min_safe'])
                    if parsed and safe and parsed < safe:
                        findings.append({
                            "package": name,
                            "version": ver,
                            "min_safe_version": vuln['min_safe'],
                            "cve": vuln['cve'],
                        })
    except Exception:
        pass
    return findings


async def desktop_packages(path: str) -> dict:
    """Check bundled package versions in desktop apps for known CVEs."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    packages_scanned = 0
    vulnerable_packages = []

    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            # Skip node_modules to avoid massive scans
            if 'node_modules' in root.split(os.sep):
                continue
            for fname in files:
                if fname in MANIFEST_PATTERNS:
                    manifest_pattern, pkg_type = MANIFEST_PATTERNS[fname]
                    fpath = os.path.join(root, fname)
                    findings = _scan_manifest(fpath, manifest_pattern, pkg_type)
                    packages_scanned += 1
                    vulnerable_packages.extend(findings)
    elif os.path.isfile(path):
        fname = os.path.basename(path)
        if fname in MANIFEST_PATTERNS:
            manifest_pattern, pkg_type = MANIFEST_PATTERNS[fname]
            findings = _scan_manifest(path, manifest_pattern, pkg_type)
            packages_scanned += 1
            vulnerable_packages.extend(findings)
        else:
            return {
                "path": path,
                "error": f"Unrecognized manifest file: {fname}. Supported: {', '.join(MANIFEST_PATTERNS.keys())}",
            }

    risk = "HIGH" if len(vulnerable_packages) > 2 else "MEDIUM" if vulnerable_packages else "INFO"

    return {
        "path": path,
        "packages_scanned": packages_scanned,
        "vulnerable_packages": vulnerable_packages,
        "total_vulnerable": len(vulnerable_packages),
        "risk": risk,
    }
