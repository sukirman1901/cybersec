import asyncio


async def searchsploit(search_term: str) -> dict:
    cmd = ["searchsploit", search_term]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode(errors="replace")
        lines = [l.strip() for l in output.split("\n") if l.strip() and not l.startswith("--")]
        exploits = []
        for line in lines:
            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                exploits.append({
                    "path": parts[0] if len(parts) > 0 else "",
                    "title": parts[1] if len(parts) > 1 else "",
                    "type": parts[2] if len(parts) > 2 else "",
                })
        return {"search": search_term, "results": exploits[:30], "count": len(exploits)}
    except FileNotFoundError:
        return {"search": search_term, "error": "searchsploit not found. Install: git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb && ln -sf /opt/exploitdb/searchsploit /usr/bin/searchsploit"}
    except asyncio.TimeoutError:
        return {"search": search_term, "error": "searchsploit timed out"}
