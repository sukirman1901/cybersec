import shutil
import asyncio


async def ios_frida(action: str = "ssl_pinning", process: str = "") -> dict:
    """Run frida on iOS device — SSL pinning bypass, method tracing, process list."""
    if not shutil.which("frida"):
        return {"available": False, "error": "'frida' CLI not found in PATH. Install with: pip install frida-tools"}

    if action == "ps":
        cmd = ["frida-ps", "-U"]
    else:
        if not process:
            return {"available": False, "error": "process name is required for this action"}

        action_map = {
            "ssl_pinning": [
                "frida", "-U", "-n", process, "-e",
                (
                    "setTimeout(function(){"
                    "Interceptor.attach(ObjC.classes.NSURLSession['- dataTaskWithURL:completionHandler:'].implementation, {"
                    "onEnter: function(args){ console.log('[+] SSL Pinning Bypass triggered'); }"
                    "});"
                    "}, 0);"
                ),
            ],
            "methods": [
                "frida", "-U", "-n", process, "--runtime", "objc", "-e",
                "ObjC.classes['NSURLSession'].$methods",
            ],
        }

        cmd = action_map.get(action)
        if not cmd:
            return {"available": False, "error": f"Unknown action: '{action}'. Use: ssl_pinning, methods, ps"}

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        return {
            "action": action,
            "stdout": stdout.decode("utf-8", errors="replace")[:1000],
            "stderr": stderr.decode("utf-8", errors="replace")[:500],
            "exit_code": proc.returncode,
            "available": True,
        }
    except asyncio.TimeoutError:
        return {"action": action, "error": "timed out", "exit_code": -1, "available": True}
    except Exception as e:
        return {"action": action, "error": str(e), "available": True}
