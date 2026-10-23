"""Shared finding contract for Cybersec detectors — confidence, coverage, fingerprint.

Used by findings_manager novelty triage and by scanners that emit structured findings.
Does not perform network I/O.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

CONFIDENCE_VALUES = ("HIGH", "MEDIUM", "LOW")
TRIAGE_VALUES = ("novel", "duplicate", "regression", "changed", "untriaged")


def normalize_confidence(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 75:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"
    text = str(value).strip().upper()
    aliases = {
        "HIGH": "HIGH", "H": "HIGH", "CONFIRMED": "HIGH", "VERIFIED": "HIGH",
        "MEDIUM": "MEDIUM", "MED": "MEDIUM", "M": "MEDIUM", "PROBABLE": "MEDIUM",
        "LOW": "LOW", "L": "LOW", "INFO": "LOW", "UNKNOWN": "LOW",
    }
    return aliases.get(text)


def _host_from(finding: dict) -> str:
    for key in ("host", "target", "url", "matched_at"):
        raw = finding.get(key) or ""
        if not raw:
            continue
        text = str(raw)
        if "://" in text:
            parts = urlsplit(text)
            return (parts.hostname or text).lower()
        return text.split("/")[0].split(":")[0].lower()
    return ""


def _path_from(finding: dict) -> str:
    for key in ("path", "url", "target", "matched_at"):
        raw = finding.get(key) or ""
        if not raw:
            continue
        text = str(raw)
        if "://" in text:
            return urlsplit(text).path or "/"
        if text.startswith("/"):
            return text.split("?")[0]
    return str(finding.get("endpoint", "") or "")


def evidence_fingerprint(finding: dict) -> str:
    evidence = finding.get("evidence", finding.get("response", finding.get("description", "")))
    if isinstance(evidence, (list, dict)):
        evidence = json.dumps(evidence, sort_keys=True, default=str)
    blob = str(evidence)[:2000]
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()[:16]


def finding_fingerprint(finding: dict) -> str:
    """Stable novelty key: host|type|method|path|param|technique|evidence_fp."""
    host = _host_from(finding)
    ftype = str(finding.get("type") or finding.get("vuln_type") or finding.get("title") or "unknown").lower()
    method = str(finding.get("method") or "GET").upper()
    path = _path_from(finding)
    param = str(finding.get("param") or finding.get("parameter") or "")
    technique = str(finding.get("technique") or finding.get("payload") or "")
    ev = finding.get("evidence_hash") or evidence_fingerprint(finding)
    port = str(finding.get("port") or "")
    key = "|".join([host, port, ftype, method, path, param, technique, ev])
    return hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()[:16]


def validate_contract(finding: dict, *, require_quality: bool = True) -> dict:
    """Return {ok, errors, warnings, normalized} for one finding."""
    errors: list[str] = []
    warnings: list[str] = []
    normalized = dict(finding)

    conf = normalize_confidence(
        normalized.get("confidence")
        or (normalized.get("metadata") or {}).get("confidence")
    )
    coverage = normalized.get("coverage") or (normalized.get("metadata") or {}).get("coverage") or ""
    coverage = str(coverage).strip()

    if require_quality:
        if not conf:
            errors.append("missing confidence (HIGH|MEDIUM|LOW)")
        if not coverage:
            errors.append("missing coverage notes")
    else:
        if not conf:
            warnings.append("missing confidence")
        if not coverage:
            warnings.append("missing coverage")

    if conf:
        normalized["confidence"] = conf
    if coverage:
        normalized["coverage"] = coverage

    if not (normalized.get("type") or normalized.get("title") or normalized.get("vuln_type")):
        errors.append("missing type/title")
    if not (_host_from(normalized) or normalized.get("target")):
        warnings.append("missing host/target")

    sev = str(normalized.get("severity") or "info").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        errors.append(f"invalid severity: {sev}")
    else:
        normalized["severity"] = sev

    fp = finding_fingerprint(normalized)
    normalized["fingerprint"] = fp
    normalized["evidence_hash"] = normalized.get("evidence_hash") or evidence_fingerprint(normalized)
    if "id" not in normalized or not normalized["id"]:
        normalized["id"] = fp

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "normalized": normalized,
    }


def normalize_finding(finding: dict, *, require_quality: bool = False,
                      tool: str = "Cybersec MCP") -> dict:
    """Normalize a detector finding to the shared contract (best-effort)."""
    result = validate_contract(finding, require_quality=require_quality)
    out = result["normalized"]
    meta = dict(out.get("metadata") or {})
    meta.setdefault("tool", tool)
    meta["confidence"] = out.get("confidence")
    meta["coverage"] = out.get("coverage", "")
    meta["evidence_hash"] = out.get("evidence_hash")
    meta["fingerprint"] = out.get("fingerprint")
    meta.setdefault("detected_at", datetime.now(timezone.utc).isoformat())
    out["metadata"] = meta
    out["_contract"] = {"ok": result["ok"], "errors": result["errors"], "warnings": result["warnings"]}
    return out


def extract_findings_list(payload: Any) -> list[dict]:
    """Pull a findings/vulnerabilities list from common scan JSON shapes."""
    if payload is None:
        return []
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return []
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("findings", "vulnerabilities", "results", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    if payload.get("type") or payload.get("title") or payload.get("severity"):
        return [payload]
    return []


def attach_contract_fields(scan_result: dict, *, finding_type: str | None = None) -> dict:
    """Ensure top-level scan dict exposes confidence/coverage for pipeline gates."""
    out = dict(scan_result)
    if "confidence" not in out or not out.get("confidence"):
        # Derive from nested findings if present
        findings = extract_findings_list(out)
        grades = [normalize_confidence(f.get("confidence")) for f in findings]
        grades = [g for g in grades if g]
        if "HIGH" in grades:
            out["confidence"] = "HIGH"
        elif "MEDIUM" in grades:
            out["confidence"] = "MEDIUM"
        elif grades:
            out["confidence"] = "LOW"
        elif out.get("vulnerable") or out.get("count"):
            out["confidence"] = "MEDIUM"
        else:
            out["confidence"] = "LOW"
    else:
        out["confidence"] = normalize_confidence(out["confidence"]) or "LOW"
    if not out.get("coverage"):
        parts = []
        if out.get("preset"):
            parts.append(f"preset={out['preset']}")
        if finding_type:
            parts.append(f"type={finding_type}")
        if out.get("error"):
            parts.append(f"error={out['error']}")
        out["coverage"] = "; ".join(parts) if parts else "unspecified"
    return out


_SLUG = re.compile(r"[^a-z0-9]+")


def technique_slug(text: str) -> str:
    return _SLUG.sub("_", (text or "").lower()).strip("_")[:64]
