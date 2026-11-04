"""Persistent HTTP request/response logger."""
import json
import os
import datetime
import re
import stat
from urllib.parse import urlsplit, urlunsplit

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "http_requests.jsonl")
MAX_STORE = 2 * 1024 * 1024


def _check(value):
    """1 MiB text, 1000 items/container, 10000 nodes, nesting <=32."""
    stack, nodes, size = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 10000 or depth > 32:
            raise ValueError('Input structure budget exceeded')
        if isinstance(item, str):
            if len(item) > 1048576:
                raise ValueError('Input text exceeds 1 MiB')
            size += len(item.encode('utf-8'))
            if size > 1048576:
                raise ValueError('Input text exceeds 1 MiB')
        elif isinstance(item, (dict, list)):
            if len(item) > 1000:
                raise ValueError('Collection exceeds 1000 items')
            children = list(item.keys()) + list(item.values()) if isinstance(item, dict) else item
            stack.extend((v, depth + 1) for v in children)


def _redact(value, key=''):
    """Redact named credentials, headers, bodies/raw data and URL secrets, not arbitrary prose."""
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


def _read_logs():
    try:
        expected = os.lstat(LOG_FILE)
    except FileNotFoundError:
        return []
    if not stat.S_ISREG(expected.st_mode) or expected.st_size > MAX_STORE:
        raise ValueError('Log must be a regular file of at most 2 MiB')
    fd = os.open(LOG_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) or actual.st_size > MAX_STORE:
            raise ValueError('Log changed before open')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_STORE + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_STORE:
        raise ValueError('Log exceeds 2 MiB')
    lines = raw.decode('utf-8').splitlines()
    if len(lines) > 1000:
        raise ValueError('Log exceeds 1000 records')
    entries = []
    for line in lines:
        entry = json.loads(line)
        _check(entry)
        if not isinstance(entry, dict) or not isinstance(entry.get('id'), str) or any(
            not isinstance(entry[k], dict) for k in ('request', 'response') if k in entry
        ):
            raise ValueError('Invalid stored HTTP record')
        entries.append(entry)
    return entries


def http_logger(action: str, request_data: str = "", response_data: str = "", request_id: str = "") -> str:
    try:
        for value in (action, request_data, response_data, request_id):
            _check(value)
        if action != 'clear':
            _read_logs()
        result = _dispatch(action, request_data, response_data, request_id)
        result = json.dumps(_redact(json.loads(result)), indent=2)
        if len(result.encode('utf-8')) > 4 * 1024 * 1024:
            return json.dumps({'error': 'Output exceeds 4 MiB; narrow the query'})
        return result
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return json.dumps({'error': 'Invalid input, corrupt/oversize log, or storage operation failed; no success confirmed'})


def _dispatch(action, request_data, response_data, request_id):
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
    if not request_data and not response_data:
        raise ValueError('Request or response required')
    entry = {
        "id": request_id or datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S%f"),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }

    for key, data in (('request', request_data), ('response', response_data)):
        if not data:
            continue
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
        except ValueError:
            if not isinstance(data, str) or data.lstrip().startswith(('{', '[')):
                raise ValueError('Malformed structured HTTP data')
            parsed = {'raw': '[REDACTED]', 'raw_length': len(data)}
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError('Expected nonempty HTTP object')
        _check(parsed)
        entry[key] = _redact(parsed)
    entry = _redact(entry)
    try:
        expected = os.lstat(LOG_FILE)
    except FileNotFoundError:
        expected = None
    existing = _read_logs()
    payload = (json.dumps(entry) + '\n').encode('utf-8')
    if len(existing) >= 1000 or (expected.st_size if expected else 0) + len(payload) > MAX_STORE:
        raise ValueError('Log storage budget exceeded')
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
    if expected is None:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(LOG_FILE, flags, 0o600)
    try:
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (expected is not None and (
            actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
            raise ValueError('Log changed before append')
        if actual.st_size + len(payload) > MAX_STORE:
            raise ValueError('Log storage budget exceeded')
        with os.fdopen(fd, 'ab', closefd=False) as f:
            f.write(payload)
    finally:
        os.close(fd)

    return json.dumps({"status": "logged", "id": entry["id"]}, indent=2)


def _list_logs(request_id):
    entries = [_redact(e) for e in _read_logs() if not request_id or e.get('id') == request_id]

    return json.dumps({"entries": entries[-100:], "total": len(entries)}, indent=2)


def _search_logs(query):
    query = query.lower()
    entries = [_redact(e) for e in _read_logs()]
    entries = [e for e in entries if query in json.dumps(e).lower()]

    return json.dumps({"results": entries[-100:], "total": len(entries)}, indent=2)


def _log_stats():
    if not os.path.exists(LOG_FILE):
        return json.dumps({"total_entries": 0}, indent=2)

    total = 0
    by_status = {}
    by_method = {}
    by_host = {}

    for entry in map(_redact, _read_logs()):
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

    entries = list(map(_redact, _read_logs()))
    return json.dumps({"entries": entries, "total": len(entries)}, indent=2)


def _clear_logs():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    return json.dumps({"status": "cleared"}, indent=2)
