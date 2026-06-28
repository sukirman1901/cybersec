"""Persistent HTTP request/response logger."""
import json
import os
import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "http_requests.jsonl")


def http_logger(action: str, request_data: str = "", response_data: str = "", request_id: str = "") -> str:
    os.makedirs(LOG_DIR, exist_ok=True)

    if action == "log":
        return _log_request(request_data, response_data, request_id)
    elif action == "list":
        return _list_logs(request_id)
    elif action == "search":
        return _search_logs(request_data)
    elif action == "stats":
        return _log_stats()
    elif action == "export":
        return _export_logs()
    elif action == "clear":
        return _clear_logs()
    else:
        return json.dumps({"error": f"Unknown action: {action}", "actions": ["log", "list", "search", "stats", "export", "clear"]}, indent=2)


def _log_request(request_data, response_data, request_id):
    entry = {
        "id": request_id or datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S%f"),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }

    if request_data:
        try:
            entry["request"] = json.loads(request_data) if isinstance(request_data, str) else request_data
        except Exception:
            entry["request"] = {"raw": request_data}

    if response_data:
        try:
            entry["response"] = json.loads(response_data) if isinstance(response_data, str) else response_data
        except Exception:
            entry["response"] = {"raw": response_data}

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return json.dumps({"status": "logged", "id": entry["id"]}, indent=2)


def _list_logs(request_id):
    entries = []
    if not os.path.exists(LOG_FILE):
        return json.dumps({"entries": [], "total": 0}, indent=2)

    with open(LOG_FILE) as f:
        for line in f:
            entry = json.loads(line)
            if request_id and entry.get("id") != request_id:
                continue
            entries.append(entry)

    return json.dumps({"entries": entries[-100:], "total": len(entries)}, indent=2)


def _search_logs(query):
    entries = []
    if not os.path.exists(LOG_FILE):
        return json.dumps({"results": [], "total": 0}, indent=2)

    query = query.lower()
    with open(LOG_FILE) as f:
        for line in f:
            if query in line.lower():
                entries.append(json.loads(line))

    return json.dumps({"results": entries[-100:], "total": len(entries)}, indent=2)


def _log_stats():
    if not os.path.exists(LOG_FILE):
        return json.dumps({"total_entries": 0}, indent=2)

    total = 0
    by_status = {}
    by_method = {}
    by_host = {}

    with open(LOG_FILE) as f:
        for line in f:
            entry = json.loads(line)
            total += 1
            req = entry.get("request", {})
            resp = entry.get("response", {})

            method = req.get("method", req.get("request_method", "UNKNOWN"))
            by_method[method] = by_method.get(method, 0) + 1

            status = resp.get("status_code", resp.get("status", "unknown"))
            by_status[str(status)] = by_status.get(str(status), 0) + 1

            url = req.get("url", req.get("path", ""))
            host = url.split("/")[2] if "/" in url and len(url.split("/")) > 2 else url.split("?")[0]
            by_host[host] = by_host.get(host, 0) + 1

    return json.dumps({
        "total_entries": total,
        "by_method": dict(sorted(by_method.items(), key=lambda x: x[1], reverse=True)),
        "by_status": dict(sorted(by_status.items())),
        "by_host": dict(sorted(by_host.items(), key=lambda x: x[1], reverse=True)[:10]),
    }, indent=2)


def _export_logs():
    if not os.path.exists(LOG_FILE):
        return json.dumps({"entries": [], "total": 0}, indent=2)

    entries = []
    with open(LOG_FILE) as f:
        for line in f:
            entries.append(json.loads(line))
    return json.dumps({"entries": entries, "total": len(entries)}, indent=2)


def _clear_logs():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    return json.dumps({"status": "cleared"}, indent=2)