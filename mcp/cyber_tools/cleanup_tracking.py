"""Cleanup tracking — track what was modified, created, uploaded during testing."""
import json
from datetime import datetime

def cleanup_tracking(action: str, action_type: str = "", target: str = "", tool: str = "", description: str = "", artifact: str = "", cleanup_cmd: str = "", cleanup_status: str = "pending") -> str:
    if action == "add":
        return _add_entry(action_type, target, tool, description, artifact, cleanup_cmd)
    elif action == "list":
        return _list_entries(action_type, cleanup_status)
    elif action == "update":
        return _update_status(tool, target, cleanup_status)
    elif action == "generate":
        return _generate_cleanup_script()
    elif action == "summary":
        return _summary()
    elif action == "clear":
        return _clear_completed()
    else:
        return json.dumps({"error": "Unknown action", "actions": ["add", "list", "update", "generate", "summary", "clear"]}, indent=2)


LOG = []
COUNTER = [0]


def _add_entry(action_type, target, tool, description, artifact, cleanup_cmd):
    COUNTER[0] += 1
    entry = {
        "id": f"CLN-{COUNTER[0]:04d}",
        "action": action_type or "modify",
        "target": target or "unknown",
        "tool": tool or "unknown",
        "description": description or "",
        "artifact": artifact or "",
        "cleanup_cmd": cleanup_cmd or "",
        "status": "pending",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "cleaned_at": "",
    }
    LOG.append(entry)
    return json.dumps({
        "id": entry["id"],
        "entry": entry,
        "message": f"Logged {action_type} on {target}. Run cleanup_tracking(action='generate') for cleanup script.",
    }, indent=2)


def _list_entries(action_type, cleanup_status):
    filtered = LOG
    if action_type:
        filtered = [e for e in filtered if e["action"] == action_type]
    if cleanup_status:
        filtered = [e for e in filtered if e["status"] == cleanup_status]
    return json.dumps({
        "total": len(filtered),
        "entries": filtered,
    }, indent=2)


def _update_status(tool, target, cleanup_status):
    updated = []
    for entry in LOG:
        if entry["tool"] == tool or entry["target"] == target:
            entry["status"] = cleanup_status
            if cleanup_status in ("completed", "done", "cleaned"):
                entry["cleaned_at"] = datetime.utcnow().isoformat() + "Z"
                updated.append(entry["id"])
    return json.dumps({
        "updated": len(updated),
        "ids": updated,
        "new_status": cleanup_status,
    }, indent=2)


def _generate_cleanup_script():
    pending = [e for e in LOG if e["status"] == "pending"]
    if not pending:
        return json.dumps({"script": "# No pending cleanup items", "commands": []}, indent=2)

    commands = []
    for entry in pending:
        if entry["cleanup_cmd"]:
            commands.append({
                "id": entry["id"],
                "command": entry["cleanup_cmd"],
                "description": entry["description"],
            })
        elif entry["action"] == "upload":
            commands.append({
                "id": entry["id"],
                "command": f"rm -f {entry['artifact']}",
                "description": f"Remove uploaded file: {entry['artifact']}",
            })
        elif entry["action"] == "create":
            commands.append({
                "id": entry["id"],
                "command": f"rm -rf {entry['artifact']}",
                "description": f"Remove created resource: {entry['artifact']}",
            })
        elif entry["action"] == "modify":
            commands.append({
                "id": entry["id"],
                "command": f"# Manual: revert changes to {entry['target']}",
                "description": f"Manual reversion needed for {entry['target']}",
            })

    script_lines = ["#!/bin/bash", "# Cleanup Script — generated " + datetime.utcnow().isoformat() + "Z", f"# Total items: {len(pending)}"]
    for cmd in commands:
        script_lines.append("")
        script_lines.append(f"# {cmd['description']}")
        script_lines.append(cmd["command"])
        if not cmd.get("command", "").startswith("#"):
            script_lines.append(f"# cleanup_tracking(action='update', tool='{cmd['id']}', cleanup_status='completed')")

    script = "\n".join(script_lines)
    return json.dumps({
        "total_pending": len(pending),
        "commands": commands,
        "script": script,
    }, indent=2)


def _summary():
    by_status = {}
    by_action = {}
    for entry in LOG:
        by_status[entry["status"]] = by_status.get(entry["status"], 0) + 1
        by_action[entry["action"]] = by_action.get(entry["action"], 0) + 1
    return json.dumps({
        "total_entries": len(LOG),
        "by_status": by_status,
        "by_action": by_action,
        "pending_cleanup": by_status.get("pending", 0),
    }, indent=2)


def _clear_completed():
    global LOG
    before = len(LOG)
    LOG = [e for e in LOG if e["status"] != "completed"]
    after = len(LOG)
    return json.dumps({
        "cleared": before - after,
        "remaining": after,
    }, indent=2)