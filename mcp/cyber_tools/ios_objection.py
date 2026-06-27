import shutil
import asyncio


async def ios_objection(action: str = "keychain", package: str = "") -> dict:
    """Run objection iOS runtime exploration — keychain dump, sqlite, nsuserdefaults."""
    if not shutil.which("objection"):
        return {"available": False, "error": "'objection' CLI not found in PATH. Install with: pip install objection"}

    if not package:
        return {"available": False, "error": "package name is required for objection runtime exploration"}

    action_map = {
        "keychain": ["objection", "-g", package, "run", "ios", "keychain", "dump"],
        "sqlite": ["objection", "-g", package, "run", "ios", "sqlite", "dump"],
        "nsuserdefaults": ["objection", "-g", package, "run", "ios", "nsuserdefaults"],
    }

    cmd = action_map.get(action)
    if not cmd:
        return {"available": False, "error": f"Unknown action: '{action}'. Use: keychain, sqlite, nsuserdefaults"}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        return {
            "action": action,
            "package": package,
            "stdout": stdout.decode("utf-8", errors="replace")[:1000],
            "stderr": stderr.decode("utf-8", errors="replace")[:500],
            "exit_code": proc.returncode,
            "available": True,
        }
    except asyncio.TimeoutError:
        return {"action": action, "package": package, "error": "timed out", "exit_code": -1, "available": True}
    except Exception as e:
        return {"action": action, "package": package, "error": str(e), "available": True}
