"""Findings manager — centralized findings database with dedup and status tracking."""

import json
import hashlib
import os
from datetime import datetime

FINDINGS_DB = os.path.join(os.path.dirname(__file__), "..", ".findings_db.json")

STATUS_VALUES = {"new", "confirmed", "false_positive", "fixing", "fixed", "retested", "wont_fix"}


def _load_db():
    if os.path.exists(FINDINGS_DB):
        with open(FINDINGS_DB) as f:
            return json.load(f)
    return {"findings": []}


def _save_db(db):
    with open(FINDINGS_DB, "w") as f:
        json.dump(db, f, indent=2)


def _finding_hash(finding: dict) -> str:
    key = f"{finding.get('host', '')}:{finding.get('type', '')}:{finding.get('port', '')}:{finding.get('description', '')[:100]}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def findings_manager(action: str, findings_json: str = "", finding_id: str = "", status: str = "", notes: str = "") -> str:
    """Manage penetration testing findings.

    Actions:
    - add: Add new findings (dedup by hash)
    - list: List all findings (optionally filtered by status)
    - update: Update finding status by ID
    - stats: Get statistics summary
    - export: Export all findings as JSON
    - clear: Clear all findings
    """

    db = _load_db()

    if action == "add":
        if not findings_json:
            return json.dumps({"error": "findings_json required for add action"})
        try:
            new_findings = json.loads(findings_json)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})
        if not isinstance(new_findings, list):
            new_findings = [new_findings]

        added = 0
        duplicates = 0
        existing_hashes = {_finding_hash(f) for f in db["findings"]}

        for f in new_findings:
            fhash = _finding_hash(f)
            if fhash in existing_hashes:
                duplicates += 1
                continue
            f["id"] = fhash
            f["status"] = "new"
            f["first_seen"] = datetime.now().isoformat()
            f["last_updated"] = datetime.now().isoformat()
            f["notes"] = ""
            db["findings"].append(f)
            existing_hashes.add(fhash)
            added += 1

        _save_db(db)
        return json.dumps({"action": "add", "added": added, "duplicates": duplicates, "total": len(db["findings"])}, indent=2)

    elif action == "list":
        filter_status = status if status and status in STATUS_VALUES else None
        results = [f for f in db["findings"] if not filter_status or f.get("status") == filter_status]
        return json.dumps({"findings": results, "count": len(results)}, indent=2)

    elif action == "update":
        if not finding_id:
            return json.dumps({"error": "finding_id required for update action"})
        if status and status not in STATUS_VALUES:
            return json.dumps({"error": f"Invalid status. Valid: {', '.join(sorted(STATUS_VALUES))}"})

        for f in db["findings"]:
            if f.get("id") == finding_id:
                if status:
                    f["status"] = status
                if notes:
                    f["notes"] = notes
                f["last_updated"] = datetime.now().isoformat()
                _save_db(db)
                return json.dumps({"action": "update", "finding": f}, indent=2)

        return json.dumps({"error": f"Finding {finding_id} not found"}, indent=2)

    elif action == "stats":
        stats = {"total": len(db["findings"]), "by_status": {}, "by_severity": {}}
        for f in db["findings"]:
            s = f.get("status", "new")
            stats["by_status"][s] = stats["by_status"].get(s, 0) + 1
            sev = f.get("severity", "info").lower()
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
        return json.dumps(stats, indent=2)

    elif action == "export":
        return json.dumps(db, indent=2)

    elif action == "clear":
        db["findings"] = []
        _save_db(db)
        return json.dumps({"action": "clear", "message": "All findings cleared"}, indent=2)

    else:
        return json.dumps({"error": f"Unknown action: {action}. Valid: add, list, update, stats, export, clear"}, indent=2)