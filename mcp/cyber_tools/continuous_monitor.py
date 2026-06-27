"""Continuous monitoring — track target changes over time."""

import json
import os
import hashlib
from datetime import datetime

MONITOR_DB = os.path.join(os.path.dirname(__file__), "..", ".monitor_db.json")


def _load_db():
    if os.path.exists(MONITOR_DB):
        with open(MONITOR_DB) as f:
            return json.load(f)
    return {"targets": {}}


def _save_db(db):
    with open(MONITOR_DB, "w") as f:
        json.dump(db, f, indent=2)


def _snapshot_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def continuous_monitor(target: str, scan_results: str = "", action: str = "record") -> str:
    """Monitor a target for changes over time.

    Actions:
    - record: Store current scan results as snapshot
    - history: Show all snapshots for target
    - diff: Compare latest 2 snapshots
    - stats: Show monitoring statistics
    - clear: Clear monitoring data for target
    """
    db = _load_db()

    if action == "record":
        if not scan_results:
            return json.dumps({"error": "scan_results required for record action"})
        try:
            results = json.loads(scan_results)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})

        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "data": results,
            "hash": _snapshot_hash(results),
        }

        if target not in db["targets"]:
            db["targets"][target] = {"snapshots": [], "first_seen": snapshot["timestamp"]}

        snapshots = db["targets"][target]["snapshots"]
        if snapshots and snapshots[-1]["hash"] == snapshot["hash"]:
            return json.dumps({"action": "record", "target": target, "status": "no_change", "message": "No changes detected since last scan"}, indent=2)

        snapshots.append(snapshot)
        db["targets"][target]["last_seen"] = snapshot["timestamp"]

        changes = {"added": [], "removed": [], "changed": []}
        if len(snapshots) >= 2:
            changes = _diff_snapshots(snapshots[-2]["data"], snapshots[-1]["data"])

        _save_db(db)
        return json.dumps({
            "action": "record",
            "target": target,
            "snapshot_number": len(snapshots),
            "changes_detected": changes,
            "timestamp": snapshot["timestamp"],
        }, indent=2)

    elif action == "history":
        if target not in db["targets"]:
            return json.dumps({"error": f"No monitoring data for {target}"})
        snapshots = db["targets"][target]["snapshots"]
        history = [{"n": i + 1, "timestamp": s["timestamp"], "hash": s["hash"]} for i, s in enumerate(snapshots)]
        return json.dumps({"target": target, "total_snapshots": len(snapshots), "history": history}, indent=2)

    elif action == "diff":
        if target not in db["targets"]:
            return json.dumps({"error": f"No monitoring data for {target}"})
        snapshots = db["targets"][target]["snapshots"]
        if len(snapshots) < 2:
            return json.dumps({"error": "Need at least 2 snapshots for diff"}, indent=2)
        diff = _diff_snapshots(snapshots[-2]["data"], snapshots[-1]["data"])
        return json.dumps({
            "target": target,
            "snapshot_1": {"n": len(snapshots) - 1, "timestamp": snapshots[-2]["timestamp"]},
            "snapshot_2": {"n": len(snapshots), "timestamp": snapshots[-1]["timestamp"]},
            "diff": diff,
        }, indent=2)

    elif action == "stats":
        stats = {"targets_monitored": len(db["targets"]), "by_target": {}}
        for t, info in db["targets"].items():
            stats["by_target"][t] = {
                "snapshots": len(info["snapshots"]),
                "first_seen": info.get("first_seen"),
                "last_seen": info.get("last_seen"),
            }
        return json.dumps(stats, indent=2)

    elif action == "clear":
        if target in db["targets"]:
            del db["targets"][target]
            _save_db(db)
            return json.dumps({"action": "clear", "target": target, "message": "Monitoring data cleared"}, indent=2)
        return json.dumps({"error": f"No monitoring data for {target}"}, indent=2)

    else:
        return json.dumps({"error": f"Unknown action: {action}"}, indent=2)


def _diff_snapshots(old, new):
    changes = {"added": [], "removed": [], "changed": []}
    old_str = json.dumps(old, sort_keys=True)
    new_str = json.dumps(new, sort_keys=True)
    if old_str == new_str:
        return changes

    old_ports = set()
    new_ports = set()
    for p in old.get("open_ports", []):
        old_ports.add(p.get("port"))
    for p in new.get("open_ports", []):
        new_ports.add(p.get("port"))

    for port in new_ports - old_ports:
        changes["added"].append(f"New open port: {port}")
    for port in old_ports - new_ports:
        changes["removed"].append(f"Closed port: {port}")

    old_subs = set(old.get("subdomains", []))
    new_subs = set(new.get("subdomains", []))
    for sub in new_subs - old_subs:
        changes["added"].append(f"New subdomain: {sub}")
    for sub in old_subs - new_subs:
        changes["removed"].append(f"Removed subdomain: {sub}")

    old_vulns = len(old.get("vulnerabilities", []))
    new_vulns = len(new.get("vulnerabilities", []))
    if new_vulns > old_vulns:
        changes["added"].append(f"New vulnerabilities: {new_vulns - old_vulns}")
    elif new_vulns < old_vulns:
        changes["removed"].append(f"Resolved vulnerabilities: {old_vulns - new_vulns}")

    old_tech = set(old.get("technologies", []))
    new_tech = set(new.get("technologies", []))
    for tech in new_tech - old_tech:
        changes["added"].append(f"New technology detected: {tech}")
    for tech in old_tech - new_tech:
        changes["removed"].append(f"Technology removed: {tech}")

    return changes