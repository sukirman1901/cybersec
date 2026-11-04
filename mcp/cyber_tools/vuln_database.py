"""Local vulnerability database — store, search, manage known vulnerabilities."""
import json
import os
import re
import tempfile
import stat
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", ".vuln_database.json")
MAX_STORE = 2 * 1024 * 1024


def _check(value):
    """1 MiB input text, <=1000 items/container, <=10000 nodes, depth <=32."""
    stack, nodes, size = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 10000 or depth > 32:
            raise ValueError('Input structure budget exceeded')
        if isinstance(item, str):
            if len(item) > 1048576:
                raise ValueError('Input exceeds 1 MiB')
            size += len(item.encode('utf-8'))
            if size > 1048576:
                raise ValueError('Input exceeds 1 MiB')
        elif isinstance(item, (dict, list)):
            if len(item) > 1000:
                raise ValueError('Collection exceeds 1000 items')
            children = list(item.keys()) + list(item.values()) if isinstance(item, dict) else item
            stack.extend((v, depth + 1) for v in children)


def _redact(value, key=''):
    """Named credentials/raw payloads and HTTP URL secrets only; not arbitrary prose."""
    if re.search(r'password|passwd|secret|token|authorization|cookie|api[_-]?key', key, re.I) or key.lower() in ('raw', 'body', 'content', 'post_data'):
        return '[REDACTED]'
    if isinstance(value, dict):
        if key.lower() == 'headers':
            return {k: '[REDACTED]' for k in value}
        return {_redact(k): _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if isinstance(value, str):
        def clean(match):
            try:
                p = urlsplit(match.group())
                return urlunsplit((p.scheme, p.netloc.rsplit('@', 1)[-1], p.path,
                                   '[REDACTED]' if p.query else '', '[REDACTED]' if p.fragment else ''))
            except ValueError:
                return '[REDACTED URL]'
        return re.sub(r'https?://[^\s<>"\']+', clean, value, flags=re.I)
    return value


def _validate_entry(entry):
    _check(entry)
    if not isinstance(entry, dict) or not entry:
        raise ValueError('Expected nonempty entry object')
    if any(not isinstance(entry[k], str) for k in ('id', 'cve', 'severity', 'type', 'vuln_type', 'status') if k in entry):
        raise ValueError('Classification fields must be strings')
    if not isinstance(entry.get('tags', []), list) or any(not isinstance(t, str) for t in entry.get('tags', [])):
        raise ValueError('Tags must be a list of strings')


def vuln_database(action: str, entry_json: str = "", vuln_id: str = "", search_query: str = "", severity_filter: str = "", tag_filter: str = "") -> str:
    try:
        for value in (action, entry_json, vuln_id, search_query, severity_filter, tag_filter):
            _check(value)
        result = _dispatch(action, entry_json, vuln_id, search_query, severity_filter, tag_filter)
        result = json.dumps(_redact(json.loads(result)), indent=2)
        if len(result.encode('utf-8')) > 4 * 1024 * 1024:
            return json.dumps({'error': 'Output exceeds 4 MiB; narrow the query'})
        return result
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return json.dumps({'error': 'Invalid input, corrupt/oversize database, or storage operation failed; no success confirmed'})


def _dispatch(action, entry_json, vuln_id, search_query, severity_filter, tag_filter):
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
    try:
        expected = os.lstat(DB_FILE)
    except FileNotFoundError:
        expected = None
    if expected is not None:
        if not stat.S_ISREG(expected.st_mode) or expected.st_size > MAX_STORE:
            raise ValueError('Database must be a regular file of at most 2 MiB')
        fd = os.open(DB_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            actual = os.fstat(fd)
            if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) or actual.st_size > MAX_STORE:
                raise ValueError('Database changed before open')
            with os.fdopen(fd, 'rb', closefd=False) as f:
                raw = f.read(MAX_STORE + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_STORE:
            raise ValueError('Database exceeds 2 MiB')
        db = json.loads(raw)
        if not isinstance(db, dict) or not isinstance(db.get('entries'), list) or len(db['entries']) > 1000:
            raise ValueError('Invalid database structure')
        ids = set()
        for entry in db['entries']:
            _validate_entry(entry)
            if not isinstance(entry.get('id'), str) or entry['id'] in ids:
                raise ValueError('Invalid or duplicate entry ID')
            ids.add(entry['id'])
        minimum = max([int(i[3:]) for i in ids if re.fullmatch(r'VD-\d+', i)] or [0]) + 1
        next_id = db.get('next_id', minimum)
        if type(next_id) is not int or not minimum <= next_id <= 1000000000:
            raise ValueError('Invalid next_id')
        db['next_id'] = next_id
        return _redact(db)
    return {"entries": [], "version": "1.0", "next_id": 1}


def _save_db(db):
    if len(db['entries']) > 1000:
        raise ValueError('Database exceeds 1000 records')
    payload = json.dumps(_redact(db), indent=2).encode('utf-8')
    if len(payload) > MAX_STORE:
        raise ValueError('Database exceeds 2 MiB')
    path = None
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(DB_FILE)), delete=False) as stream:
            path = stream.name
            stream.write(payload)
        os.replace(path, DB_FILE)
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


def _add_vuln(db, entry_json):
    try:
        entry = json.loads(entry_json) if isinstance(entry_json, str) else entry_json
    except Exception:
        return json.dumps({"error": "Invalid entry JSON"}, indent=2)
    _validate_entry(entry)
    entry = _redact(entry)

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
    _validate_entry(update)
    if 'id' in update:
        raise ValueError('Entry IDs cannot be changed')
    update = _redact(update)

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
    entries = data if isinstance(data, list) else data.get('entries', [data]) if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries or len(entries) + len(db['entries']) > 1000:
        raise ValueError('Expected nonempty import list within 1000-record budget')
    for entry in entries:
        _validate_entry(entry)
    entries = _redact(entries)
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
