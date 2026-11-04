import shutil
from .cli_tools import _run_cli


async def ios_objection(action: str = "keychain", package: str = "") -> dict:
    """Run objection iOS runtime exploration — keychain dump, sqlite, nsuserdefaults."""
    if (not isinstance(action, str) or action not in ("keychain", "sqlite", "nsuserdefaults")
            or not isinstance(package, str) or not package.strip() or len(package) > 256
            or any(ord(c) < 32 for c in package)):
        return {"available": False, "error_kind": "invalid_input", "error": "Valid action and package required"}
    if not shutil.which("objection"):
        return {"available": False, "error_kind": "unavailable", "error": "Required CLI not found"}

    action_map = {
        "keychain": ["objection", "-g", package, "run", "ios", "keychain", "dump"],
        "sqlite": ["objection", "-g", package, "run", "ios", "sqlite", "dump"],
        "nsuserdefaults": ["objection", "-g", package, "run", "ios", "nsuserdefaults"],
    }

    cmd = action_map.get(action)
    try:
        result = await _run_cli(cmd, timeout=120)
    except Exception:
        result = {"exit_code": -1, "error_kind": "runtime_error"}
    # Keychain/database output may consist entirely of secrets.
    result.pop("stdout", None)
    result.pop("stderr", None)
    result.update(action=action, available=result.get("error_kind") != "spawn_error",
                  confirmed=False, output_redacted=True,
                  status="completed" if result.get("exit_code") == 0 and not result.get("error_kind") else "failed")
    return result
