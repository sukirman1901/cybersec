"""Findings manager — dedup, quality gates, and novelty triage (novel/duplicate/regression)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .finding_contract import (
    TRIAGE_VALUES,
    extract_findings_list,
    finding_fingerprint,
    normalize_finding,
    validate_contract,
)

FINDINGS_DB = os.path.join(os.path.dirname(__file__), "..", ".findings_db.json")

STATUS_VALUES = {"new", "confirmed", "false_positive", "fixing", "fixed", "retested", "wont_fix"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_db():
    if os.path.exists(FINDINGS_DB):
        with open(FINDINGS_DB) as f:
            return json.load(f)
    return {"findings": [], "schema": "novelty-v1"}


def _save_db(db):
    with open(FINDINGS_DB, "w") as f:
        json.dump(db, f, indent=2)


def _index_by_fingerprint(findings: list) -> dict:
    index = {}
    for f in findings:
        fp = f.get("fingerprint") or finding_fingerprint(f)
        index[fp] = f
        # Legacy id may still match fingerprint
        if f.get("id"):
            index.setdefault(f["id"], f)
    return index


def _classify_against_db(finding: dict, index: dict) -> str:
    fp = finding.get("fingerprint") or finding_fingerprint(finding)
    existing = index.get(fp)
    if not existing:
        return "novel"
    status = (existing.get("status") or "").lower()
    if status in ("fixed", "retested", "wont_fix", "false_positive"):
        return "regression"
    return "duplicate"


def findings_manager(action: str, findings_json: str = "", finding_id: str = "",
                     status: str = "", notes: str = "", require_quality: bool = True) -> str:
    """Manage penetration testing findings.

    Actions:
    - add: Add findings (dedup by fingerprint); requires confidence+coverage when require_quality
    - novelty: Classify findings vs DB as novel|duplicate|regression (no write unless notes=add_novel)
    - triage: Set triage label on a finding_id (novel|duplicate|regression|changed|untriaged)
    - list / update / stats / export / clear: unchanged roles
    """

    db = _load_db()
    db.setdefault("findings", [])

    if action == "add":
        if not findings_json:
            return json.dumps({"error": "findings_json required for add action"})
        try:
            raw = json.loads(findings_json)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})
        new_findings = extract_findings_list(raw) if not isinstance(raw, list) else [
            x for x in raw if isinstance(x, dict)
        ]
        if isinstance(raw, dict) and not new_findings and (raw.get("type") or raw.get("title")):
            new_findings = [raw]

        added = 0
        duplicates = 0
        regressions = 0
        rejected = []
        index = _index_by_fingerprint(db["findings"])

        for f in new_findings:
            check = validate_contract(f, require_quality=require_quality)
            if not check["ok"]:
                rejected.append({
                    "title": f.get("title") or f.get("type") or "unknown",
                    "errors": check["errors"],
                })
                continue
            normalized = normalize_finding(check["normalized"], require_quality=False)
            fp = normalized["fingerprint"]
            triage = _classify_against_db(normalized, index)

            if triage == "duplicate":
                existing = index[fp]
                existing["last_seen"] = _now()
                existing["last_updated"] = _now()
                existing["seen_count"] = int(existing.get("seen_count") or 1) + 1
                existing["triage"] = "duplicate"
                if notes:
                    existing["notes"] = ((existing.get("notes") or "") + "\n" + notes).strip()
                duplicates += 1
                continue

            if triage == "regression":
                existing = index.get(fp)
                if existing:
                    existing["status"] = "new"
                    existing["triage"] = "regression"
                    existing["last_seen"] = _now()
                    existing["last_updated"] = _now()
                    existing["seen_count"] = int(existing.get("seen_count") or 1) + 1
                    existing["confidence"] = normalized.get("confidence")
                    existing["coverage"] = normalized.get("coverage")
                    existing["evidence"] = normalized.get("evidence", existing.get("evidence"))
                    regressions += 1
                    continue

            normalized["id"] = fp
            normalized["fingerprint"] = fp
            normalized["status"] = "new"
            normalized["triage"] = "novel"
            normalized["first_seen"] = _now()
            normalized["last_seen"] = normalized["first_seen"]
            normalized["last_updated"] = normalized["first_seen"]
            normalized["seen_count"] = 1
            normalized["notes"] = notes or ""
            db["findings"].append(normalized)
            index[fp] = normalized
            added += 1

        _save_db(db)
        return json.dumps({
            "action": "add",
            "added": added,
            "duplicates": duplicates,
            "regressions": regressions,
            "rejected": rejected,
            "rejected_count": len(rejected),
            "total": len(db["findings"]),
            "require_quality": require_quality,
        }, indent=2)

    if action == "novelty":
        if not findings_json:
            return json.dumps({"error": "findings_json required for novelty action"})
        try:
            raw = json.loads(findings_json)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})
        candidates = extract_findings_list(raw)
        if isinstance(raw, dict) and not candidates and (raw.get("type") or raw.get("title")):
            candidates = [raw]

        index = _index_by_fingerprint(db["findings"])
        novel, duplicate, regression, rejected = [], [], [], []
        for f in candidates:
            check = validate_contract(f, require_quality=require_quality)
            if require_quality and not check["ok"]:
                rejected.append({"title": f.get("title") or f.get("type"), "errors": check["errors"]})
                continue
            normalized = normalize_finding(check["normalized"], require_quality=False)
            label = _classify_against_db(normalized, index)
            item = {
                "fingerprint": normalized["fingerprint"],
                "title": normalized.get("title") or normalized.get("type"),
                "type": normalized.get("type"),
                "severity": normalized.get("severity"),
                "confidence": normalized.get("confidence"),
                "coverage": normalized.get("coverage"),
                "triage": label,
                "existing_status": (index.get(normalized["fingerprint"]) or {}).get("status"),
            }
            if label == "novel":
                novel.append(item)
            elif label == "duplicate":
                duplicate.append(item)
            else:
                regression.append(item)

        # Optional: persist only novel when notes == "add_novel"
        persisted = 0
        if notes == "add_novel" and novel:
            add_payload = []
            for item in novel:
                # recover full normalized from candidates by fingerprint
                for f in candidates:
                    n = normalize_finding(f, require_quality=False)
                    if n["fingerprint"] == item["fingerprint"]:
                        add_payload.append(n)
                        break
            if add_payload:
                nested = json.loads(findings_manager(
                    "add", findings_json=json.dumps(add_payload),
                    require_quality=require_quality,
                ))
                persisted = nested.get("added", 0)

        return json.dumps({
            "action": "novelty",
            "summary": {
                "novel": len(novel),
                "duplicate": len(duplicate),
                "regression": len(regression),
                "rejected": len(rejected),
            },
            "novel": novel,
            "duplicate": duplicate,
            "regression": regression,
            "rejected": rejected,
            "persisted_novel": persisted,
        }, indent=2)

    if action == "triage":
        if not finding_id:
            return json.dumps({"error": "finding_id required for triage action"})
        label = (status or notes or "").strip().lower()
        if label not in TRIAGE_VALUES:
            return json.dumps({
                "error": f"Invalid triage label. Valid: {', '.join(sorted(TRIAGE_VALUES))}",
            })
        for f in db["findings"]:
            if f.get("id") == finding_id or f.get("fingerprint") == finding_id:
                f["triage"] = label
                f["last_updated"] = _now()
                if notes and notes.lower() not in TRIAGE_VALUES:
                    f["notes"] = ((f.get("notes") or "") + "\n" + notes).strip()
                _save_db(db)
                return json.dumps({"action": "triage", "finding": f}, indent=2)
        return json.dumps({"error": f"Finding {finding_id} not found"}, indent=2)

    if action == "list":
        filter_status = status if status and status in STATUS_VALUES else None
        filter_triage = notes if notes and notes in TRIAGE_VALUES else None
        results = []
        for f in db["findings"]:
            if filter_status and f.get("status") != filter_status:
                continue
            if filter_triage and f.get("triage") != filter_triage:
                continue
            results.append(f)
        return json.dumps({"findings": results, "count": len(results)}, indent=2)

    if action == "update":
        if not finding_id:
            return json.dumps({"error": "finding_id required for update action"})
        if status and status not in STATUS_VALUES:
            return json.dumps({"error": f"Invalid status. Valid: {', '.join(sorted(STATUS_VALUES))}"})

        for f in db["findings"]:
            if f.get("id") == finding_id or f.get("fingerprint") == finding_id:
                if status:
                    f["status"] = status
                if notes:
                    f["notes"] = notes
                f["last_updated"] = _now()
                _save_db(db)
                return json.dumps({"action": "update", "finding": f}, indent=2)

        return json.dumps({"error": f"Finding {finding_id} not found"}, indent=2)

    if action == "stats":
        stats = {
            "total": len(db["findings"]),
            "by_status": {},
            "by_severity": {},
            "by_triage": {},
            "by_confidence": {},
        }
        for f in db["findings"]:
            s = f.get("status", "new")
            stats["by_status"][s] = stats["by_status"].get(s, 0) + 1
            sev = f.get("severity", "info").lower()
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            tri = f.get("triage", "untriaged")
            stats["by_triage"][tri] = stats["by_triage"].get(tri, 0) + 1
            conf = f.get("confidence", "unknown")
            stats["by_confidence"][conf] = stats["by_confidence"].get(conf, 0) + 1
        return json.dumps(stats, indent=2)

    if action == "export":
        return json.dumps(db, indent=2)

    if action == "clear":
        db["findings"] = []
        _save_db(db)
        return json.dumps({"action": "clear", "message": "All findings cleared"}, indent=2)

    return json.dumps({
        "error": f"Unknown action: {action}",
        "actions": ["add", "novelty", "triage", "list", "update", "stats", "export", "clear"],
    }, indent=2)
