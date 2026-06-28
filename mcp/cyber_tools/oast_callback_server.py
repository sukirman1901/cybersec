"""OAST callback server — blind SSRF/XXE/OOB correlation with retry."""
import json
import urllib.request
import socket
import threading
import random
import string
import time

CALLBACKS = {}

def oast_callback_server(action: str, payload: str = "", callback_id: str = "", poll_url: str = "", max_wait: int = 15, platform: str = "auto") -> str:
    if action == "generate":
        return _generate_callback(payload, platform)
    elif action == "poll":
        return _poll_callback(callback_id, max_wait)
    elif action == "status":
        return _status(callback_id)
    elif action == "clear":
        CALLBACKS.clear()
        return json.dumps({"status": "cleared"}, indent=2)
    else:
        return json.dumps({"error": "Unknown action", "actions": ["generate", "poll", "status", "clear"]}, indent=2)


def _generate_callback(payload, platform):
    cid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    # For blind testing, we generate a unique OOB URL
    oob_domain = "oastify.com"  # example — real OOB needs a server

    entry = {
        "callback_id": cid,
        "payload": payload,
        "generated_at": time.time(),
        "oob_urls": {},
        "hits": [],
    }

    # Generate URLs for different protocols
    entry["oob_urls"]["http"] = f"http://{cid}.{oob_domain}/"
    entry["oob_urls"]["dns"] = f"{cid}.{oob_domain}"
    entry["oob_urls"]["http_sub"] = payload.replace("BURPCOLLABORATOR", f"{cid}.{oob_domain}") if "BURPCOLLABORATOR" in payload else f"http://{cid}.{oob_domain}/payload"

    CALLBACKS[cid] = entry
    return json.dumps(entry, indent=2)


def _poll_callback(callback_id, max_wait):
    if callback_id not in CALLBACKS:
        return json.dumps({"error": "Callback not found", "callback_id": callback_id}, indent=2)

    entry = CALLBACKS[callback_id]
    start = time.time()
    waited = 0
    while waited < max_wait:
        # Simulate checking for OOB callbacks
        # In production, this would check a real server log or database
        hits = entry.get("hits", [])
        if hits:
            return json.dumps({
                "callback_id": callback_id,
                "received": True,
                "hits": hits,
                "total_hits": len(hits),
                "wait_time": round(waited, 1),
                "interaction_found": True,
            }, indent=2)
        time.sleep(1)
        waited = time.time() - start

    return json.dumps({
        "callback_id": callback_id,
        "received": False,
        "hits": [],
        "total_hits": 0,
        "wait_time": round(waited, 1),
        "interaction_found": False,
    }, indent=2)


def _status(callback_id):
    if callback_id:
        entry = CALLBACKS.get(callback_id)
        if not entry:
            return json.dumps({"error": "Not found"}, indent=2)
        return json.dumps({
            "callback_id": callback_id,
            "generated_ago": round(time.time() - entry["generated_at"], 1),
            "hits": entry.get("hits", []),
            "total_hits": len(entry.get("hits", [])),
        }, indent=2)
    return json.dumps({
        "total_callbacks": len(CALLBACKS),
        "callbacks": list(CALLBACKS.keys()),
    }, indent=2)