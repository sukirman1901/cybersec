"""Local vulnerability database — store, search, manage known vulnerabilities."""
import json
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", ".vuln_database.json")


def vuln_database(action: str, entry_json: str = "", vuln_id: str = "", search_query: str = "", severity_filter: str = "", tag_filter: str = "") -> str:
    db = _load_db()

    if action == "add":
        return _add_vuln(db, entry_json)
    elif action == "get":
        return _get_vuln(db, vuln_id)
    elif action == "search":
        return _search_vulns(db, search_query, severity_filter, tag_filter)
    elif action == "list":
        return _list_vulns(db, severity_filter)
    elif action == "update":
        return _update_vuln(db, vuln_id, entry_json)
    elif action == "delete":
        return _delete_vuln(db, vuln_id)
    elif action == "stats":
        return _stats(db)
    elif action == "export":
        return json.dumps(db, indent=2)
    elif action == "import":
        return _import_vulns(db, entry_json)
    elif action == "tags":
        return _list_tags(db)
    elif action == "clear":
        _save_db({"entries": [], "version": "1.0"})
        return json.dumps({"status": "cleared"}, indent=2)
    else:
        return json.dumps({"error": f"Unknown action: {action}", "actions": ["add", "get", "search", "list", "update", "delete", "stats", "export", "import", "tags", "clear"]}, indent=2)


def _load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"entries": [], "version": "1.0", "next_id": 1}


def _save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def _add_vuln(db, entry_json):
    try:
        entry = json.loads(entry_json) if isinstance(entry_json, str) else entry_json
    except Exception:
        return json.dumps({"error": "Invalid entry JSON"}, indent=2)

    entry["id"] = f"VD-{db.get('next_id', 1):04d}"
    entry["added"] = datetime.utcnow().isoformat() + "Z"
    entry["tags"] = entry.get("tags", [])
    db["entries"].append(entry)
    db["next_id"] = db.get("next_id", 1) + 1
    _save_db(db)
    return json.dumps({"status": "added", "id": entry["id"]}, indent=2)


def _get_vuln(db, vuln_id):
    for entry in db["entries"]:
        if entry.get("id", "").lower() == vuln_id.lower() or entry.get("cve", "").lower() == vuln_id.lower():
            return json.dumps(entry, indent=2)
    return json.dumps({"error": f"Not found: {vuln_id}"}, indent=2)


def _search_vulns(db, query, severity_filter, tag_filter):
    query = query.lower() if query else ""
    results = []
    for entry in db["entries"]:
        text = json.dumps(entry).lower()
        if query and query not in text:
            continue
        if severity_filter and entry.get("severity", "").lower() != severity_filter.lower():
            continue
        if tag_filter and tag_filter.lower() not in [t.lower() for t in entry.get("tags", [])]:
            continue
        results.append(entry)
    return json.dumps({"results": results, "total": len(results)}, indent=2)


def _list_vulns(db, severity_filter):
    entries = db["entries"]
    if severity_filter:
        entries = [e for e in entries if e.get("severity", "").lower() == severity_filter.lower()]
    return json.dumps({"entries": entries, "total": len(entries)}, indent=2)


def _update_vuln(db, vuln_id, entry_json):
    try:
        update = json.loads(entry_json) if isinstance(entry_json, str) else entry_json
    except Exception:
        return json.dumps({"error": "Invalid update JSON"}, indent=2)

    for i, entry in enumerate(db["entries"]):
        if entry.get("id", "").lower() == vuln_id.lower() or entry.get("cve", "").lower() == vuln_id.lower():
            entry.update(update)
            entry["updated"] = datetime.utcnow().isoformat() + "Z"
            db["entries"][i] = entry
            _save_db(db)
            return json.dumps({"status": "updated", "id": entry.get("id")}, indent=2)
    return json.dumps({"error": f"Not found: {vuln_id}"}, indent=2)


def _delete_vuln(db, vuln_id):
    before = len(db["entries"])
    db["entries"] = [e for e in db["entries"] if e.get("id", "").lower() != vuln_id.lower() and e.get("cve", "").lower() != vuln_id.lower()]
    _save_db(db)
    return json.dumps({"status": "deleted" if len(db["entries"]) < before else "not_found", "removed": before - len(db["entries"])}, indent=2)


def _stats(db):
    entries = db["entries"]
    by_severity = {}
    by_type = {}
    by_tag = {}
    for e in entries:
        sev = e.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        t = e.get("type", e.get("vuln_type", "unknown"))
        by_type[t] = by_type.get(t, 0) + 1
        for tag in e.get("tags", []):
            by_tag[tag] = by_tag.get(tag, 0) + 1
    return json.dumps({
        "total_entries": len(entries),
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: x[1], reverse=True)),
        "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
        "by_tag": dict(sorted(by_tag.items(), key=lambda x: x[1], reverse=True)),
    }, indent=2)


def _import_vulns(db, data_json):
    try:
        data = json.loads(data_json) if isinstance(data_json, str) else data_json
    except Exception:
        return json.dumps({"error": "Invalid import JSON"}, indent=2)
    added = 0
    entries = data.get("entries", data if isinstance(data, list) else [data])
    for entry in entries:
        if isinstance(entry, dict):
            entry["id"] = f"VD-{db.get('next_id', 1):04d}"
            entry["added"] = datetime.utcnow().isoformat() + "Z"
            db["entries"].append(entry)
            db["next_id"] = db.get("next_id", 1) + 1
            added += 1
    _save_db(db)
    return json.dumps({"status": "imported", "added": added}, indent=2)


def _list_tags(db):
    tags = {}
    for e in db["entries"]:
        for tag in e.get("tags", []):
            tags[tag] = tags.get(tag, 0) + 1
    return json.dumps({"tags": dict(sorted(tags.items(), key=lambda x: x[1], reverse=True))}, indent=2)