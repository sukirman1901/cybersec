import asyncio


async def bloodhound_collect(domain: str, username: str = "", password: str = "", collector: str = "sharphound") -> dict:
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
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        return {"domain": domain, "collector": "bloodhound-python", "output": output[:500], "success": "Done" in output}
    except FileNotFoundError:
        return {"domain": domain, "error": "bloodhound-python not found. Install: pip install bloodhound", "instructions": "Then run: bloodhound-python -d <domain> -u <user> -p <pass> -c All"}
    except asyncio.TimeoutError:
        return {"domain": domain, "error": "BloodHound collection timed out"}
