"""Non-destructive, version-based PHP2SHELL assessment (no network or probes)."""

import re

FIXED_VERSIONS = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
                  (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
ADVISORIES = {
    "CVE-2026-109618": ("RCE via OOM corruption", "GHSA-w8hw-w9fx-j79w"),
    "CVE-2026-109619": ("RCE via stale global state", "GHSA-6wmf-4rv5-p3rp"),
}
REFERENCES = [
    "https://www.php.net/archive/2026.php#2026-10-21-5",
    "https://www.vulncheck.com/blog/php2shell-vulnerabilities",
]
LIMITATIONS = [
    "Version correlation only; no exploit or RCE has been verified.",
    "Distro/vendor backports may fix an older version; verify the package security changelog.",
    "Headers may be stale, spoofed or supplied by a proxy; verify the running origin and all workers.",
]


def assess_version(version: str) -> dict:
    """Compare complete stable versions only, using numeric branch boundaries."""
    result = {
        "status": "unknown", "version": version or None, "fixed_version": None,
        "cves": list(ADVISORIES), "limitations": list(LIMITATIONS),
        "references": list(REFERENCES),
    }
    # Accept numeric vendor revisions, but do not mistake RC/dev builds for GA.
    # Bound untrusted numeric components before int(): oversized banners must
    # remain unknown, not abort unrelated scanner checks or hit Python's limit.
    match = re.fullmatch(r"([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(?:[-+]\d[\w.+~\-]*)?", version)
    if not match or re.search(r"(?:RC|alpha|beta|dev)", version, re.IGNORECASE):
        result["reason"] = "Missing, incomplete, malformed or prerelease PHP version; exact stable runtime required."
        return result
    parsed = tuple(int(part) for part in match.groups())
    fixed = FIXED_VERSIONS.get(parsed[:2])
    if fixed is None:
        result["reason"] = "Branch outside the supported advisory table (EOL or future branch); verify vendor advisory."
        return result
    result["fixed_version"] = ".".join(map(str, fixed))
    result["status"] = "potentially_affected" if parsed < fixed else "not_affected_by_version"
    result["reason"] = ("Advertised version is below the branch security release."
                        if parsed < fixed else "Advertised version meets the branch fix; not proof of origin safety.")
    return result


def assess_headers(headers) -> dict:
    """Use only existing response headers, retaining evidence and conflicts."""
    normalized = {key.lower(): value for key, value in headers.items()}
    evidence = []
    versions = []
    for key in ("server", "x-powered-by"):
        value = normalized.get(key, "")
        if re.search(r"\bPHP\b", value, re.IGNORECASE):
            evidence.append({"source": f"header:{key}", "value": value[:500]})
        versions.extend(re.findall(r"\bPHP/([^\s,;()]+)", value, re.IGNORECASE))
    versions = sorted(set(versions))
    result = assess_version(versions[0] if len(versions) == 1 else "")
    if len(versions) > 1:
        result["reason"] = "Conflicting PHP versions in headers; verify the running origin runtime."
    result.update({"observed_versions": versions, "evidence": evidence})
    return result


def cve_records(assessment: dict) -> list[dict]:
    """Return probable CVE records only when a supported version is below its fix."""
    if assessment["status"] != "potentially_affected":
        return []
    return [{
        "id": cve, "name": f"PHP2SHELL — {name}", "severity": "CRITICAL",
        "confidence": "probable",
        "description": (
            f"PHP {assessment['version']} may be affected by {cve} ({name}). "
            f"Upgrade to {assessment['fixed_version']} or a later supported security release. "
            "Version correlation only, not verified RCE; verify vendor backports and the running origin."
        ),
        "fixed_version": assessment["fixed_version"],
        "references": [f"https://github.com/php/php-src/security/advisories/{ghsa}", *REFERENCES],
    } for cve, (name, ghsa) in ADVISORIES.items()]
