import asyncio


async def hydra_brute(target: str, service: str = "ssh", username: str = "root", wordlist: str = "") -> dict:
    cmd = ["hydra", "-l", username, "-P", wordlist or "/usr/share/wordlists/rockyou.txt", f"{service}://{target}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = stdout.decode(errors="replace")
        lines = output.split("\n")
        results = [l for l in lines if "password:" in l.lower() or "login:" in l.lower() or "host:" in l.lower()]
        return {"target": target, "service": service, "results": results[:20], "count": len(results)}
    except FileNotFoundError:
        return {"target": target, "error": "hydra not found. Install: brew install hydra"}
    except asyncio.TimeoutError:
        return {"target": target, "error": "hydra timed out (300s)"}
