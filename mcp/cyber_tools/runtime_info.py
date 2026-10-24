"""Read-only source identity; never attest client state or in-memory bytecode."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys

ALGORITHM = "sha256-source-v1"


def _manifest(root, paths, scope, missing=()):
    entries, errors = [], list(missing)
    for path in sorted(set(paths)):
        relative = path.relative_to(root).as_posix()
        try:
            if not path.resolve().is_relative_to(root):
                errors.append(f"outside_package:{relative}")
                continue
            if path.stat().st_size > 4_000_000:
                errors.append(f"file_too_large:{relative}")
                continue
            entries.append((relative, hashlib.sha256(path.read_bytes()).hexdigest()))
        except (OSError, RuntimeError):
            errors.append(f"unreadable:{relative}")
    if not entries:
        errors.append("no_files")
    complete = not errors
    return {"algorithm": ALGORITHM, "scope": scope,
            "status": "complete" if complete else "incomplete",
            "fingerprint": hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()
            if complete else None,
            "file_count": len(entries), "errors": errors}


def source_manifest(root):
    """Hash allowlisted sources only, independent of install location or git."""
    root = Path(root).resolve()
    required = [root / name for name in ("package.json", "mcp/requirements.txt", "mcp/server.py")]
    paths = list((root / "mcp/cyber_tools").rglob("*.py"))
    missing = [] if paths else ["missing:cyber_tools_sources"]
    return _manifest(root, required + paths, "mcp", missing)


def _compare(left, right):
    def valid(value):
        return (isinstance(value, dict) and value.get("status") == "complete"
                and value.get("algorithm") == ALGORITHM
                and isinstance(value.get("fingerprint"), str)
                and re.fullmatch(r"[0-9a-f]{64}", value["fingerprint"]) is not None)
    if not valid(left) or not valid(right) or left.get("scope") != right.get("scope"):
        return "unknown"
    return "match" if left["fingerprint"] == right["fingerprint"] else "different"


def capture_runtime(root):
    """Capture once during server initialization, not on each health call.

    This is a startup source-file snapshot, not proof that imported modules were
    never patched or that files stayed unchanged during startup.
    """
    root = Path(root).resolve()
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        version = package.get("version") if isinstance(package, dict) else None
        version = version if isinstance(version, str) else None
    except (OSError, ValueError):
        version = None
    return {"schema_version": 1, "package_version": version,
            "installation_path": str(root), "entrypoint": str(root / "mcp/server.py"),
            "pid": os.getpid(), "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "server_initialized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "identity_kind": "startup_source_snapshot",
            "startup_build": source_manifest(root)}


def inspect_runtime(identity):
    """Keep captured startup evidence immutable; separately inspect current disk."""
    root = Path(identity["installation_path"]).resolve()
    current = source_manifest(root)
    return {"runtime": deepcopy(identity),
            "files_on_disk": {
                "mcp": current, "mcp_vs_startup": _compare(identity.get("startup_build"), current),
                "plugin": _manifest(root, [root / ".opencode/plugins/cybersec.js"], "plugin"),
                "skills": _manifest(root, list((root / "skills").glob("*/SKILL.md")), "skills")},
            "client_plugin_state": "unknown", "client_skill_state": "unknown",
            "runtime_limitations": [
                "Startup source snapshot, not in-memory bytecode or dependency attestation.",
                "Plugin and skill digests describe current disk files, not client registration/loading.",
                "No atomic filesystem snapshot; concurrent edits during hashing may require a retry.",
                "Compare a response from the connected live MCP; a newly spawned process is not the existing client.",
            ]}


def compare_reference(payload, reference_root):
    """Compare saved live health evidence to an explicitly selected checkout."""
    runtime = payload.get("runtime") if isinstance(payload, dict) else None
    runtime = runtime if isinstance(runtime, dict) else {}
    observed = runtime.get("startup_build")
    reference = source_manifest(reference_root)
    status = (_compare(observed, reference) if runtime.get("identity_kind") == "startup_source_snapshot"
              and runtime.get("schema_version") == 1 else "unknown")
    return {"status": status, "scope": "MCP startup sources versus reference disk sources",
            "runtime_fingerprint": observed.get("fingerprint") if isinstance(observed, dict) else None,
            "reference_build": reference, "reference_path": str(Path(reference_root).resolve()),
            "client_plugin_state": "unknown", "client_skill_state": "unknown",
            "note": "Saved self-reported evidence only; no client config, cache, reload or process was changed."}
