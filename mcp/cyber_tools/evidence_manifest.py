"""Evidence manifest — local SHA256 consistency checks, not proof of provenance."""
import json
import hashlib
import time
from datetime import datetime


def _input_ok(value):
    """Bound each input: 1 MiB UTF-8 text, 1000/container, 10000 nodes, depth 64."""
    stack, size, nodes = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 10000 or depth > 64:
            return False
        if isinstance(item, str):
            if len(item) > 1048576:
                return False
            size += len(item.encode('utf-8', errors='replace'))
            if size > 1048576:
                return False
        elif isinstance(item, (dict, list)):
            if len(item) > 1000:
                return False
            children = list(item.keys()) + list(item.values()) if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return True

def evidence_manifest(action: str, evidence_json: str = "", manifest_id: str = "", filter_type: str = "", chain_depth: int = 0, verify_hash: str = "") -> str:
    if not all(_input_ok(v) for v in (action, evidence_json, manifest_id, filter_type, verify_hash)):
        return json.dumps({'error': 'Input exceeds 1 MiB/1000-item/10000-node/depth-64 budget'})
    if type(chain_depth) is not int or not 0 <= chain_depth <= 1000:
        return json.dumps({'error': 'chain_depth must be an integer from 0 to 1000'})
    if action == 'add' and len(CHAIN) >= 1000:
        return json.dumps({'error': 'Session manifest budget is 1000 evidence records'})
    if manifest_id and manifest_id not in MANIFESTS:
        return json.dumps({"error": "Manifest not found"})
    if action == "add":
        return _add_evidence(evidence_json)
    elif action == "chain":
        return _get_chain(manifest_id, chain_depth)
    elif action == "verify":
        return _verify_integrity(manifest_id, verify_hash)
    elif action == "export":
        return _export_manifest(manifest_id, filter_type)
    elif action == "diff":
        return _diff_manifests(manifest_id, filter_type)
    elif action == "summary":
        return _summary(manifest_id)
    else:
        return json.dumps({"error": "Unknown action", "actions": ["add", "chain", "verify", "export", "diff", "summary"]}, indent=2)


MANIFESTS = {}
EVIDENCE_STORE = []
CHAIN = []
COUNTER = [0]


def _add_evidence(evidence_json):
    try:
        ev = json.loads(evidence_json) if isinstance(evidence_json, str) else evidence_json
    except (ValueError, TypeError, RecursionError):
        return json.dumps({"error": "Invalid evidence JSON"})
    if not _input_ok(ev):
        return json.dumps({'error': 'Parsed input exceeds collection/depth budget'})
    if not isinstance(ev, dict) or not ev or '_meta' in ev or any(not isinstance(ev[k], str) for k in ('type', 'source') if k in ev):
        return json.dumps({"error": "Expected nonempty evidence object; _meta is reserved"})
    ev = json.loads(json.dumps(ev))
    COUNTER[0] += 1

    ev_id = f"EV-{COUNTER[0]:04d}"
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Create content hash
    content_str = json.dumps(ev, sort_keys=True)
    content_hash = hashlib.sha256(content_str.encode()).hexdigest()

    # Build chain entry
    prev_hash = CHAIN[-1].get("hash") if CHAIN else "0000000000000000000000000000000000000000000000000000000000000000"
    chain_entry = {
        "index": len(CHAIN),
        "evidence_id": ev_id,
        "timestamp": timestamp,
        "content_hash": content_hash,
        "previous_hash": prev_hash,
        "hash": hashlib.sha256(f"{prev_hash}{content_hash}{timestamp}".encode()).hexdigest(),
        "evidence_type": ev.get("type", "generic"),
        "source": ev.get("source", "unknown"),
    }

    CHAIN.append(chain_entry)
    ev["_meta"] = {"evidence_id": ev_id, "chain_index": len(CHAIN) - 1}
    EVIDENCE_STORE.append(ev)

    mid = f"MANIFEST-{len(MANIFESTS) + 1:04d}"
    MANIFESTS[mid] = {
        "created_at": timestamp,
        "total_evidence": len(EVIDENCE_STORE),
        "chain_length": len(CHAIN),
        "last_hash": chain_entry["hash"],
    }

    return json.dumps({
        "evidence_id": ev_id,
        "manifest_id": mid,
        "chain_index": chain_entry["index"],
        "content_hash": content_hash,
        "chain_hash": chain_entry["hash"],
        "integrity": f"Chain integrity: block {chain_entry['index']} linked to {chain_entry['previous_hash'][:16]}...",
    }, indent=2)


def _get_chain(manifest_id, chain_depth):
    chain, _ = _view(manifest_id)
    length = len(chain)
    if chain_depth > 0:
        chain = chain[-chain_depth:]
    result = {
        "chain_length": length,
        "integrity": _check_integrity(manifest_id),
        "blocks": chain,
    }
    if manifest_id and manifest_id in MANIFESTS:
        result["manifest"] = MANIFESTS[manifest_id]
    return json.dumps(result, indent=2)


def _verify_integrity(manifest_id, verify_hash):
    chain, evidence = _view(manifest_id)
    if not chain:
        return json.dumps({"valid": False, "total_blocks": 0, "integrity": "NOT_ASSESSED"})
    if len(chain) != len(evidence):
        return json.dumps({"valid": False, "integrity": "Evidence count mismatch"})
    # Full chain verification
    for i, block in enumerate(chain):
        content = {k: v for k, v in evidence[i].items() if k != '_meta'}
        content_hash = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
        if content_hash != block['content_hash'] or evidence[i].get('_meta', {}).get('evidence_id') != block['evidence_id']:
            return json.dumps({"valid": False, "broken_at": i, "integrity": "Evidence content mismatch"})
        if i == 0 and block['previous_hash'] != '0' * 64:
            return json.dumps({"valid": False, "broken_at": 0, "integrity": "Invalid genesis link"})
        expected_hash = hashlib.sha256(
            f"{block['previous_hash']}{block['content_hash']}{block['timestamp']}".encode()
        ).hexdigest()
        if expected_hash != block["hash"]:
            return json.dumps({
                "valid": False,
                "broken_at": i,
                "evidence_id": block["evidence_id"],
                "expected": expected_hash,
                "found": block["hash"],
            }, indent=2)

        if i > 0:
            prev_block = chain[i - 1]
            if block["previous_hash"] != prev_block["hash"]:
                return json.dumps({
                    "valid": False,
                    "broken_link": i,
                    "expected_prev": prev_block["hash"],
                    "found_prev": block["previous_hash"],
                }, indent=2)

    result = {
        "valid": True,
        "total_blocks": len(chain),
        "integrity": "Local chain and stored content consistent; provenance and external authenticity not verified",
    }
    expected_tip = verify_hash or (MANIFESTS[manifest_id]['last_hash'] if manifest_id else '')
    if expected_tip:
        result["hash_match"] = chain[-1]["hash"] == expected_tip
        result['valid'] = result['hash_match']
    return json.dumps(result, indent=2)


def _export_manifest(manifest_id, filter_type):
    chain, evidence = _view(manifest_id)
    if filter_type:
        evidence = [e for e in evidence if e.get("type", "generic") == filter_type]
    return json.dumps({
        "manifest_id": manifest_id or "all",
        "total_evidence": len(evidence),
        "chain_length": len(chain),
        "chain_integrity": _check_integrity(manifest_id),
        "evidence": evidence,
        "ledger": chain,
    }, indent=2)


def _diff_manifests(manifest_id, compare_id):
    if not manifest_id or compare_id not in MANIFESTS:
        return json.dumps({"error": "Specify two existing manifest IDs"})
    left, _ = _view(manifest_id)
    right, _ = _view(compare_id)
    left_ids = {e['evidence_id'] for e in left}
    right_ids = {e['evidence_id'] for e in right}
    return json.dumps({
        "manifest_id": manifest_id, "compare_id": compare_id,
        "added": sorted(right_ids - left_ids), "removed": sorted(left_ids - right_ids),
    }, indent=2)


def _summary(manifest_id):
    chain, evidence = _view(manifest_id)
    type_counts = {}
    source_counts = {}
    for ev in evidence:
        t = ev.get("type", "generic")
        s = ev.get("source", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
        source_counts[s] = source_counts.get(s, 0) + 1
    return json.dumps({
        "total_evidence": len(evidence),
        "chain_blocks": len(chain),
        "chain_integrity": _check_integrity(manifest_id),
        "by_type": type_counts,
        "by_source": source_counts,
        "last_block": chain[-1] if chain else None,
    }, indent=2)


def _view(manifest_id):
    length = MANIFESTS[manifest_id]['chain_length'] if manifest_id else len(CHAIN)
    return CHAIN[:length], EVIDENCE_STORE[:length]


def _check_integrity(manifest_id=""):
    result = json.loads(_verify_integrity(manifest_id, ""))
    return "INTACT" if result['valid'] else result.get('integrity', 'BROKEN')
