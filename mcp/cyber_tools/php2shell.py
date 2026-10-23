"""Non-destructive, version-based PHP2SHELL assessment (no network or probes).

Confidence grades and passive SAPI/proxy caveats are inspired by techniques
documented in JoasASantos/php2shell-scanner (MIT), reimplemented here under the
cybersec MCP safety contract — no vendor copy, no probe/DoS/recon fan-out.
"""

from __future__ import annotations

import re
import shutil
import subprocess

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
    "Exposed phpinfo/static pages may differ from the serving SAPI workers.",
]

# Persistent workers reuse request state → more relevant to CVE-2026-109619.
PERSISTENT_SAPIS = ("fpm", "fpm-fcgi", "apache2handler", "mod_php", "litespeed", "phpdbg", "cli-server")
PERREQUEST_SAPIS = ("cgi", "cgi-fcgi")
PROXY_MARKERS = (
    ("Cloudflare", ("server:cloudflare", "cf-ray", "cf-cache-status")),
    ("Akamai", ("server:akamaighost", "x-akamai", "akamai")),
    ("AWS CloudFront", ("x-amz-cf-id", "via:cloudfront", "server:cloudfront")),
    ("Fastly", ("x-served-by", "x-fastly", "fastly")),
    ("Sucuri WAF", ("x-sucuri-id", "server:sucuri")),
    ("Imperva/Incapsula", ("x-iinfo", "incap_ses", "visid_incap")),
    ("Varnish", ("x-varnish", "via:varnish")),
)
DISTRO_RX = re.compile(r"(ubuntu|debian|deb\d|\+deb|\.el\d|~dfsg|\.fc\d|suse|amzn|alpine)", re.I)
# Headers that may carry a PHP version or presence signal (safe banner set).
PHP_VERSION_HEADERS = ("server", "x-powered-by", "x-php-version")
PHP_HINT_HEADERS = PHP_VERSION_HEADERS + ("x-generator", "x-redirect-by")


def assess_version(version: str) -> dict:
    """Compare complete stable versions only, using numeric branch boundaries."""
    result = {
        "status": "unknown", "version": version or None, "fixed_version": None,
        "cves": list(ADVISORIES), "limitations": list(LIMITATIONS),
        "references": list(REFERENCES), "confidence": "LOW",
        "confidence_notes": [],
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


def detect_proxy(headers) -> str | None:
    """Identify a CDN/WAF/proxy whose banner may not be the PHP origin."""
    normalized = {str(k).lower(): str(v) for k, v in headers.items()}
    blob = " ".join(f"{k}:{v}" for k, v in normalized.items()).lower()
    hits = []
    for name, markers in PROXY_MARKERS:
        if any(marker in blob for marker in markers):
            hits.append(name)
    return ", ".join(dict.fromkeys(hits)) or None


def detect_sapi(headers=None, server_api: str | None = None) -> tuple[str | None, bool | None]:
    """Infer SAPI / worker model from phpinfo Server API or headers. Passive only."""
    if server_api:
        lowered = server_api.lower()
        if any(token in lowered for token in PERSISTENT_SAPIS):
            return server_api, True
        if any(token in lowered for token in PERREQUEST_SAPIS):
            return server_api, False
        return server_api, None
    normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    xpb = normalized.get("x-powered-by", "").lower()
    server = normalized.get("server", "").lower()
    if "php-fpm" in xpb or "fpm" in xpb:
        return "fpm", True
    if "mod_php" in server or ("apache" in server and "php/" in server):
        return "apache2handler (mod_php)", True
    if "litespeed" in server:
        return "litespeed", True
    if "php-cgi" in xpb or "cgi" in xpb:
        return "cgi", False
    return None, None


def distro_build_hint(text: str) -> str | None:
    match = DISTRO_RX.search(text or "")
    return match.group(0) if match else None


def grade_confidence(*, evidence: list | None = None, observed_versions: list | None = None,
                     proxy: str | None = None, status: str = "unknown") -> tuple[str, list[str]]:
    """Grade how trustworthy a version-based verdict is (HIGH / MEDIUM / LOW)."""
    evidence = evidence or []
    versions = list(observed_versions or [])
    notes: list[str] = []
    sources = [str(item.get("source", "")) for item in evidence]
    values = " ".join(str(item.get("value", "")) for item in evidence)

    conf = "LOW"
    if any(src.startswith("phpinfo:") for src in sources):
        conf = "HIGH"
        notes.append("version from exposed phpinfo() (authoritative for that page)")
    elif any("errorpage" in src for src in sources):
        conf = "HIGH"
        notes.append("version from PHP error-page disclosure")
    elif any(src.startswith("header:") for src in sources) and len(versions) == 1:
        conf = "MEDIUM"
        notes.append("version from HTTP banner (expose_php / Server / X-Powered-By)")
    elif any(src.startswith("egg:") for src in sources) and len(versions) == 1:
        conf = "MEDIUM"
        notes.append("version from PHP credits/easter-egg page (expose_php=On)")
    else:
        notes.append("no authoritative runtime version — presence or inference only")

    if len(versions) > 1:
        conf = "LOW"
        notes.append("conflicting PHP versions observed; do not treat as a single runtime")
    elif status == "unknown" and not versions:
        conf = "LOW"

    distro = distro_build_hint(values) or next(
        (distro_build_hint(v) for v in versions if distro_build_hint(v)), None)
    if distro:
        notes.append(
            f"distro-packaged build ({distro}): fix may be backported without a version bump — "
            "verify the package changelog"
        )
        if conf == "HIGH":
            conf = "MEDIUM"
        elif conf == "MEDIUM":
            conf = "LOW"

    if proxy:
        notes.append(f"{proxy} in front: banner may reflect the proxy/CDN edge, not the PHP origin")
        if any(src.startswith("header:") for src in sources) and not any(
                src.startswith("phpinfo:") or "errorpage" in src for src in sources):
            conf = "LOW"

    if conf != "HIGH":
        notes.append("static phpinfo ≠ serving worker; CDN/proxy may hide the true PHP version")
    return conf, notes


def assess_headers(headers) -> dict:
    """Use only existing response headers, retaining evidence and conflicts."""
    normalized = {key.lower(): value for key, value in headers.items()}
    evidence = []
    versions = []
    for key in PHP_HINT_HEADERS:
        value = normalized.get(key, "")
        if not value:
            continue
        if key in PHP_VERSION_HEADERS and (
                re.search(r"\bPHP\b", value, re.IGNORECASE) or key == "x-php-version"):
            evidence.append({"source": f"header:{key}", "value": value[:500]})
        elif key not in PHP_VERSION_HEADERS and re.search(r"\bPHP\b", value, re.IGNORECASE):
            evidence.append({"source": f"header:{key}", "value": value[:500]})
        matches = re.findall(r"\bPHP(?:/|\s+)([0-9][^\s,;()]+)", value, re.IGNORECASE)
        if key == "x-php-version" and not matches:
            matches = [part.strip() for part in value.split(",") if part.strip()]
        versions.extend(matches)
    versions = sorted(set(versions))
    result = assess_version(versions[0] if len(versions) == 1 else "")
    if len(versions) > 1:
        result["reason"] = "Conflicting PHP versions in headers; verify the running origin runtime."
    proxy = detect_proxy(normalized)
    sapi, persistent = detect_sapi(normalized)
    confidence, notes = grade_confidence(
        evidence=evidence, observed_versions=versions, proxy=proxy, status=result["status"])
    if sapi:
        notes.append(
            f"persistent worker ({sapi}): more relevant to CVE-2026-109619"
            if persistent else f"per-request SAPI ({sapi}): reduced relevance to CVE-2026-109619"
            if persistent is False else f"SAPI observed ({sapi}); worker model unclear"
        )
    result.update({
        "observed_versions": versions,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_notes": notes,
        "proxy": proxy,
        "sapi": sapi,
        "worker_persistent": persistent,
    })
    return result


def finalize_assessment(assessment: dict, *, evidence: list | None = None,
                        observed_versions: list | None = None,
                        headers=None, server_api: str | None = None) -> dict:
    """Attach confidence, proxy and SAPI caveats to a merged remote assessment."""
    evidence = evidence if evidence is not None else assessment.get("evidence", [])
    versions = (observed_versions if observed_versions is not None
                else assessment.get("observed_versions", []))
    proxy = detect_proxy(headers or {})
    sapi, persistent = detect_sapi(headers or {}, server_api=server_api)
    if server_api and not sapi:
        sapi, persistent = detect_sapi(server_api=server_api)
    confidence, notes = grade_confidence(
        evidence=evidence, observed_versions=versions, proxy=proxy,
        status=assessment.get("status", "unknown"))
    if sapi:
        if persistent is True:
            notes.append(f"persistent worker ({sapi}): exposed to CVE-2026-109619 stale-state reuse risk")
        elif persistent is False:
            notes.append(f"per-request SAPI ({sapi}): reduced exposure to CVE-2026-109619")
        else:
            notes.append(f"SAPI ({sapi}): static phpinfo may differ from serving workers")
    assessment.update({
        "confidence": confidence,
        "confidence_notes": notes,
        "proxy": proxy,
        "sapi": sapi,
        "worker_persistent": persistent,
    })
    return assessment


def cve_records(assessment: dict) -> list[dict]:
    """Return probable CVE records only when a supported version is below its fix."""
    if assessment["status"] != "potentially_affected":
        return []
    confidence = assessment.get("confidence") or "LOW"
    notes = assessment.get("confidence_notes") or []
    return [{
        "id": cve, "name": f"PHP2SHELL — {name}", "severity": "CRITICAL",
        "confidence": confidence,
        "description": (
            f"PHP {assessment['version']} may be affected by {cve} ({name}). "
            f"Upgrade to {assessment['fixed_version']} or a later supported security release. "
            "Version correlation only, not verified RCE; verify vendor backports and the running origin."
            + (f" Confidence notes: {'; '.join(notes)}" if notes else "")
        ),
        "fixed_version": assessment["fixed_version"],
        "references": [f"https://github.com/php/php-src/security/advisories/{ghsa}", *REFERENCES],
        "confidence_notes": list(notes),
    } for cve, (name, ghsa) in ADVISORIES.items()]


def scan_local_php(php_bin: str = "php") -> dict:
    """Read PHP version/SAPI from the MCP host only (`php -v` / `php -i`).

    Never contacts a remote target. If the sandbox blocks subprocess execution,
    returns a skipped result with a TODO for operators to re-run outside the sandbox.
    """
    out = {"mode": "local", "php_bin": php_bin, "skipped": False}
    path = shutil.which(php_bin)
    if not path:
        out["skipped"] = True
        out["reason"] = "php binary not found in PATH on the MCP host"
        return out
    out["php_bin"] = path
    try:
        version_proc = subprocess.run(
            [path, "-v"], capture_output=True, text=True, timeout=10, check=False)
        info_proc = subprocess.run(
            [path, "-i"], capture_output=True, text=True, timeout=15, check=False)
    except (PermissionError, OSError) as error:
        # TODO: sandbox may block subprocess; re-run local check on an unconstrained host.
        out.update(skipped=True, reason=f"TODO: sandbox blocked local php probe ({type(error).__name__})")
        return out
    except subprocess.TimeoutExpired:
        out.update(skipped=True, reason="local php probe timed out")
        return out

    version_text = (version_proc.stdout or "") + (version_proc.stderr or "")
    info_text = info_proc.stdout or ""
    version_match = re.search(r"PHP\s+([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", version_text)
    version = version_match.group(1) if version_match else None
    sapi_match = re.search(r"^Server API\s*=>\s*(.+)$", info_text, re.MULTILINE)
    memory_match = re.search(r"^memory_limit\s*=>\s*(\S+)", info_text, re.MULTILINE)
    post_match = re.search(r"^post_max_size\s*=>\s*(\S+)", info_text, re.MULTILINE)
    assessment = assess_version(version or "")
    sapi, persistent = detect_sapi(server_api=sapi_match.group(1).strip() if sapi_match else None)
    evidence = [{"source": "local:php -v", "value": (version_text.strip()[:500] or "")}]
    if version:
        assessment = finalize_assessment(
            assessment, evidence=evidence, observed_versions=[version], server_api=sapi)
        assessment["observed_versions"] = [version]
        assessment["evidence"] = evidence
    else:
        assessment = finalize_assessment(assessment, evidence=evidence, observed_versions=[])
    out.update({
        "php_version": version,
        "sapi": sapi,
        "worker_persistent": persistent,
        "memory_limit": memory_match.group(1) if memory_match else None,
        "post_max_size": post_match.group(1) if post_match else None,
        "php2shell": assessment,
        "findings": cve_records(assessment),
    })
    return out
