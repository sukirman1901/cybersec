import shutil
from .cli_tools import _run_cli


async def ios_frida(action: str = "ssl_pinning", process: str = "") -> dict:
    """Run existing runtime queries; CLI completion does not confirm device findings."""
    if not isinstance(action, str) or action not in ("ssl_pinning", "methods", "ps"):
        return {"available": False, "error_kind": "invalid_input", "error": "Unknown action"}
    if action == "ssl_pinning":
        return {"available": False, "error_kind": "unsupported", "confirmed": False,
                "error": "The former logging-only hook does not implement pinning bypass"}
    if action != "ps" and (not isinstance(process, str) or not process.strip() or len(process) > 256 or any(ord(c) < 32 for c in process)):
        return {"available": False, "error_kind": "invalid_input", "error": "Valid process name required"}
    executable = "frida-ps" if action == "ps" else "frida"
    if not shutil.which(executable):
        return {"available": False, "error_kind": "unavailable", "error": "Required CLI not found"}

    if action == "ps":
        cmd = ["frida-ps", "-U"]
    else:
        action_map = {
            "methods": [
                "frida", "-U", "-n", process, "--runtime", "objc", "-e",
                "ObjC.classes['NSURLSession'].$methods",
            ],
        }

        cmd = action_map.get(action)
    try:
        result = await _run_cli(cmd, timeout=120)
    except Exception:
        result = {"exit_code": -1, "error_kind": "runtime_error"}
    # Device output can contain arbitrary secrets; do not expose either stream.
    result.pop("stdout", None)
    result.pop("stderr", None)
    result.update(action=action, available=result.get("error_kind") != "spawn_error",
                  confirmed=False, output_redacted=True,
                  status="completed" if result.get("exit_code") == 0 and not result.get("error_kind") else "failed")
    return result
