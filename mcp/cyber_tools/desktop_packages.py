"""Offline npm version hints, not a current vulnerability/advisory database."""
import json
import os
import re
import stat

# Legacy review thresholds. Previous CVE associations were not reliably scoped
# to these packages. Do not attach CVEs without an independently verified feed.
KNOWN_VULN_PACKAGES = {
    'electron': {'min_safe': '22.0.0', 'cve': None},
    'react': {'min_safe': '18.2.0', 'cve': None},
    'lodash': {'min_safe': '4.17.21', 'cve': None},
    'axios': {'min_safe': '1.6.0', 'cve': None},
    'express': {'min_safe': '4.18.2', 'cve': None},
    'jquery': {'min_safe': '3.5.0', 'cve': None},
}
MANIFEST_PATTERNS = {
    'package.json': ('', 'npm'), 'requirements.txt': ('', 'pip'),
    'Cargo.toml': ('', 'cargo'), 'go.mod': ('', 'go'),
}
MAX_BYTES = 1024 * 1024
MAX_FILES = 100


def _parse_version(version_str: str):
    """Only exact release versions are comparable; ranges are not installations."""
    if not isinstance(version_str, str) or not re.fullmatch(r'(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})', version_str):
        return None
    return tuple(int(part) for part in version_str.split('.'))


def _unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate manifest member')
        result[key] = value
    return result


def _scan_manifest(filepath: str, pattern: re.Pattern, pkg_type: str) -> list:
    info = os.lstat(filepath)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
        raise ValueError('Unsupported or oversized manifest')
    def open_regular(name, flags):
        return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with open(filepath, 'rb', opener=open_regular) as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise OSError('File changed before open')
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Oversized manifest')
    if pkg_type != 'npm':
        # The bundled thresholds are npm-specific: names in other ecosystems
        # cannot establish package identity or applicable advisories.
        return []
    manifest = json.loads(data, object_pairs_hook=_unique_members)
    if not isinstance(manifest, dict):
        raise ValueError('Manifest must be an object')
    findings = []
    for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
        deps = manifest.get(section, {})
        if not isinstance(deps, dict):
            raise ValueError('Dependency section must be an object')
        for name, version in deps.items():
            if not isinstance(version, str):
                raise ValueError('Dependency specification must be a string')
            hint = KNOWN_VULN_PACKAGES.get(name)
            if not hint:
                continue
            parsed = _parse_version(version)
            safe = _parse_version(hint['min_safe'])
            if parsed and safe and parsed < safe:
                findings.append({"package": name, "version": version,
                                 "min_safe_version": hint['min_safe'], "cve": hint.get('cve'),
                                 "assessment": "candidate", "confidence": "low",
                                 "coverage": "Manifest declaration below legacy review threshold only; not a verified affected version, installation, safe-version guarantee or current advisory"})
    return findings


async def desktop_packages(path: str) -> dict:
    if not isinstance(path, str) or not os.path.exists(path) or os.path.islink(path):
        return {"error": "Expected an existing artifact, not a symlink", "coverage_complete": False, "execution_status": "not_started"}
    candidates = []
    errors = []
    skipped = []
    if os.path.isdir(path):
        entries = 0
        for root, dirs, files in os.walk(path, onerror=lambda _: errors.append('Directory unreadable')):
            entries += len(dirs) + len(files)
            if entries > 1000:
                errors.append('Directory entry budget exceeded')
                break
            if any(d == 'node_modules' or os.path.islink(os.path.join(root, d)) for d in dirs):
                skipped.append('node_modules or symlink directory pruned')
            dirs[:] = [d for d in dirs if d != 'node_modules' and not os.path.islink(os.path.join(root, d))]
            candidates.extend(os.path.join(root, f) for f in files if f in MANIFEST_PATTERNS)
    elif os.path.isfile(path) and os.path.basename(path) in MANIFEST_PATTERNS:
        candidates = [path]
    else:
        return {"error": "Unsupported manifest file", "coverage_complete": False, "execution_status": "not_started"}
    if len(candidates) > MAX_FILES:
        errors.append('100-file analysis limit exceeded')
    findings = []
    scanned = 0
    for index, candidate in enumerate(candidates[:MAX_FILES]):
        pattern, kind = MANIFEST_PATTERNS[os.path.basename(candidate)]
        try:
            findings.extend(_scan_manifest(candidate, pattern, kind))
            scanned += 1
            if kind != 'npm':
                skipped.append(f'{kind}: no ecosystem-specific advisory data; not assessed')
        except (OSError, ValueError, TypeError, RecursionError):
            errors.append(f'Manifest {index}: unreadable, oversized or malformed')
    complete = bool(scanned) and not errors and not skipped and len(findings) <= 100
    return {"path": path, "packages_scanned": scanned, "vulnerable_packages": findings[:100],
            "coverage_complete": complete, "execution_status": "completed" if complete else "partial" if scanned else "not_started",
            "total_vulnerable": len(findings), "risk": "MEDIUM" if findings else "UNKNOWN" if errors or skipped or not scanned else "INFO",
            "errors": errors, "skipped": skipped,
            "coverage": "Offline npm exact-release declarations only; ranges, prereleases, URLs, installed versions and current CVEs not assessed. Legacy thresholds are review hints, not verified safe versions. 1 MiB/manifest, 100 manifests, 1000 directory entries, 100 displayed candidates.",
            "truncated": len(findings) > 100}
