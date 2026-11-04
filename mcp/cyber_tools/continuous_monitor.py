"""Continuous monitoring — track target changes over time."""

import json
import os
import hashlib
import stat
import tempfile
import re
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime

MONITOR_DB = os.path.join(os.path.dirname(__file__), "..", ".monitor_db.json")
MAX_STORE=2*1024*1024


def _check(value):
    """1 MiB text, 1000 items/container, 10000 nodes, depth 32."""
    stack, nodes, size = [(value, 0)], 0, 0
    while stack:
        v, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 10000:
            raise ValueError('Structure budget exceeded')
        if isinstance(v, str):
            if len(v) > 1048576:
                raise ValueError('Text budget exceeded')
            size += len(v.encode('utf-8'))
            if size > 1048576:
                raise ValueError('Text budget exceeded')
        elif isinstance(v, (list, dict)):
            if len(v) > 1000:
                raise ValueError('Collection budget exceeded')
            stack.extend((x, depth + 1) for x in (list(v.keys()) + list(v.values()) if isinstance(v, dict) else v))


def _redact(value, key=''):
    """Named secrets/raw evidence and HTTP URL secrets, not arbitrary prose."""
    if re.search(r'password|secret|token|authorization|cookie|api[_-]?key', key, re.I) or key.lower() in ('evidence','response','raw','body','headers'):
        return '[REDACTED]'
    if isinstance(value, dict):
        if key == 'targets':
            return {_redact(k): _redact(v) for k,v in value.items()}
        return {_redact(k): _redact(v,k) for k,v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        def clean(m):
            try:
                p=urlsplit(m.group())
                return urlunsplit((p.scheme,p.netloc.rsplit('@',1)[-1],p.path,'[REDACTED]' if p.query else '', '[REDACTED]' if p.fragment else ''))
            except ValueError:
                return '[REDACTED URL]'
        return re.sub(r'https?://[^\s<>"\']+',clean,value,flags=re.I)
    return value


def _validate_results(results):
    _check(results)
    if not isinstance(results,dict) or not results:
        raise ValueError('Nonempty scan object required')
    for key in ('open_ports','vulnerabilities','subdomains','technologies'):
        if key in results and not isinstance(results[key],list):
            raise ValueError('Expected observation lists')
    for key in ('open_ports','vulnerabilities'):
        if any(not isinstance(v,dict) for v in results.get(key,[])):
            raise ValueError('Expected observation objects')
    if any(type(p.get('port')) is not int or not 0<=p['port']<=65535 for p in results.get('open_ports',[])):
        raise ValueError('Invalid ports')
    for key in ('subdomains','technologies'):
        if any(not isinstance(v,str) for v in results.get(key,[])):
            raise ValueError('Expected string observations')


def _load_db():
    try:
        expected=os.lstat(MONITOR_DB)
    except FileNotFoundError:
        return {'targets':{}}
    if not stat.S_ISREG(expected.st_mode) or expected.st_size>MAX_STORE:
        raise ValueError('Store must be a regular file <=2 MiB')
    fd=os.open(MONITOR_DB,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        actual=os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino) or actual.st_size>MAX_STORE:
            raise ValueError('Store changed before open')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            raw=stream.read(MAX_STORE+1)
    finally:
        os.close(fd)
    if len(raw)>MAX_STORE:
        raise ValueError('Store too large')
    db=json.loads(raw)
    if not isinstance(db,dict) or not isinstance(db.get('targets'),dict) or len(db['targets'])>100:
        raise ValueError('Invalid monitor store')
    total=0
    for target,info in db['targets'].items():
        if not isinstance(info,dict) or not isinstance(info.get('snapshots'),list) or len(info['snapshots'])>100:
            raise ValueError('Invalid history')
        total+=len(info['snapshots'])
        for snapshot in info['snapshots']:
            if not isinstance(snapshot,dict) or not isinstance(snapshot.get('timestamp'),str) or not isinstance(snapshot.get('hash'),str):
                raise ValueError('Invalid snapshot')
            _validate_results(snapshot.get('data'))
    if total>1000:
        raise ValueError('Snapshot budget exceeded')
    return _redact(db)


def _save_db(db):
    if len(db['targets'])>100 or any(len(i['snapshots'])>100 for i in db['targets'].values()) or sum(len(i['snapshots']) for i in db['targets'].values())>1000:
        raise ValueError('History budget exceeded (100 targets, 100 snapshots/target, 1000 total)')
    payload=json.dumps(_redact(db),indent=2).encode('utf-8')
    if len(payload)>MAX_STORE:
        raise ValueError('Store exceeds 2 MiB')
    path=None
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(MONITOR_DB)),delete=False) as stream:
            path=stream.name
            stream.write(payload)
        os.replace(path,MONITOR_DB)
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


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
    try:
        for value in (target,scan_results,action):
            _check(value)
        if not isinstance(target,str) or (action!='stats' and not target.strip()):
            raise ValueError('Target required')
        result=_dispatch(_redact(target),scan_results,action)
        if len(result.encode('utf-8'))>1048576:
            raise ValueError('Output exceeds 1 MiB')
        return result
    except (OSError,ValueError,TypeError,AttributeError,KeyError,RecursionError):
        return json.dumps({'error':'Invalid input, corrupt/oversized store, or persistence failure','status':'incomplete'})


def _dispatch(target,scan_results,action):
    db = _load_db()

    if action == "record":
        if not scan_results:
            return json.dumps({"error": "scan_results required for record action"})
        try:
            results = json.loads(scan_results)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})
        _validate_results(results)
        results=_redact(results)

        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "data": results,
            "hash": _snapshot_hash(results),
        }

        if target not in db["targets"]:
            db["targets"][target] = {"snapshots": [], "first_seen": snapshot["timestamp"]}

        snapshots = db["targets"][target]["snapshots"]
        if snapshots and snapshots[-1]["hash"] == snapshot["hash"]:
            return json.dumps({"action": "record", "target": target, "status": "no_change", "message": "Redacted supplied observations unchanged; not proof of scan coverage or safety"}, indent=2)

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
        changes["removed"].append(f"Findings no longer reported (remediation unverified): {old_vulns - new_vulns}")

    old_tech = set(old.get("technologies", []))
    new_tech = set(new.get("technologies", []))
    for tech in new_tech - old_tech:
        changes["added"].append(f"New technology detected: {tech}")
    for tech in old_tech - new_tech:
        changes["removed"].append(f"Technology removed: {tech}")

    for key in sorted(set(old)|set(new)):
        if old.get(key)!=new.get(key):
            changes['changed'].append(f'Changed supplied field: {key}')
    return changes
