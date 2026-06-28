"""Evidence manifest — integrity chain with SHA256 hash for court-admissible evidence."""
import json
import hashlib
import time
from datetime import datetime

def evidence_manifest(action: str, evidence_json: str = "", manifest_id: str = "", filter_type: str = "", chain_depth: int = 0, verify_hash: str = "") -> str:
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
    COUNTER[0] += 1
    try:
        ev = json.loads(evidence_json) if isinstance(evidence_json, str) else evidence_json
    except Exception:
        ev = {"raw": evidence_json}

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
    chain = CHAIN
    if chain_depth > 0:
        chain = CHAIN[-chain_depth:]
    result = {
        "chain_length": len(CHAIN),
        "integrity": _check_integrity(),
        "blocks": chain,
    }
    if manifest_id and manifest_id in MANIFESTS:
        result["manifest"] = MANIFESTS[manifest_id]
    return json.dumps(result, indent=2)


def _verify_integrity(manifest_id, verify_hash):
    # Full chain verification
    for i, block in enumerate(CHAIN):
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
            prev_block = CHAIN[i - 1]
            if block["previous_hash"] != prev_block["hash"]:
                return json.dumps({
                    "valid": False,
                    "broken_link": i,
                    "expected_prev": prev_block["hash"],
                    "found_prev": block["previous_hash"],
                }, indent=2)

    result = {
        "valid": True,
        "total_blocks": len(CHAIN),
        "integrity": "Chain integrity verified — all blocks linked correctly",
    }
    if verify_hash and CHAIN:
        result["hash_match"] = CHAIN[-1]["hash"] == verify_hash
    return json.dumps(result, indent=2)


def _export_manifest(manifest_id, filter_type):
    evidence = EVIDENCE_STORE
    if filter_type:
        evidence = [e for e in evidence if e.get("_meta", {}).get("evidence_type") == filter_type]
    return json.dumps({
        "manifest_id": manifest_id or "all",
        "total_evidence": len(evidence),
        "chain_length": len(CHAIN),
        "chain_integrity": _check_integrity(),
        "evidence": evidence,
        "ledger": CHAIN,
    }, indent=2)


def _diff_manifests(manifest_id, compare_id):
    return json.dumps({
        "note": "Evidence diff. Compare last and specific manifest.",
        "current_total": len(EVIDENCE_STORE),
        "current_chain": len(CHAIN),
    }, indent=2)


def _summary(manifest_id):
    type_counts = {}
    source_counts = {}
    for ev in EVIDENCE_STORE:
        t = ev.get("_meta", {}).get("evidence_type", "unknown")
        s = ev.get("_meta", {}).get("source", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
        source_counts[s] = source_counts.get(s, 0) + 1
    return json.dumps({
        "total_evidence": len(EVIDENCE_STORE),
        "chain_blocks": len(CHAIN),
        "chain_integrity": _check_integrity(),
        "by_type": type_counts,
        "by_source": source_counts,
        "last_block": CHAIN[-1] if CHAIN else None,
    }, indent=2)


def _check_integrity():
    for i, block in enumerate(CHAIN):
        expected = hashlib.sha256(
            f"{block['previous_hash']}{block['content_hash']}{block['timestamp']}".encode()
        ).hexdigest()
        if expected != block["hash"]:
            return f"BROKEN at block {i}"
    return "INTACT"