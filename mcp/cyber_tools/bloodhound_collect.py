import asyncio
from .cli_tools import _run_cli


async def bloodhound_collect(domain: str, username: str = "", password: str = "", collector: str = "sharphound") -> dict:
    if not domain.strip() or domain.startswith("-") or any(c in domain for c in "\x00\r\n"):
        return {"error": "Invalid domain.", "success": False}
    if collector not in {"sharphound", "bloodhound-python"}:
        return {"error": "Unsupported collector.", "success": False}
    if collector == "sharphound":
        cmd = f"SharpHound.exe -c All -d {domain}"
        return {
            "domain": domain,
            "collector": "SharpHound",
            "command": cmd,
            "note": "SharpHound must be run from a Windows domain-joined machine. "
                    "Transfer SharpHound.exe to the target and run the command above.",
        }

    cmd = ["bloodhound-python", "-d", domain, "-u", username, "-p", password, "-c", "All"]
    try:
        run = await _run_cli(cmd, timeout=120)
        failed = run["exit_code"] != 0 or run.get("error_kind") or run.get("output_truncated")
        output = run["stdout"] + run["stderr"]
        if password:
            output = output.replace(password, "[REDACTED]")
        return {"domain": domain, "collector": "bloodhound-python",
                "output": "" if failed else output[:500],
                "output_truncated": bool(run.get("output_truncated") or len(output) > 500),
                "success": not bool(failed) and "Done" in output,
                "error": "Collection incomplete or failed." if failed else None}
    except FileNotFoundError:
        return {"domain": domain, "error": "bloodhound-python not found. Install: pip install bloodhound", "instructions": "Then run: bloodhound-python -d <domain> -u <user> -p <pass> -c All"}
    except asyncio.TimeoutError:
        return {"domain": domain, "error": "BloodHound collection timed out"}
    except Exception:
        return {"domain": domain, "success": False, "error": "Collection failed."}
