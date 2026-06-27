import asyncio


async def nuclei_scan(target: str, template: str = "", severity: str = "") -> dict:
    cmd = ["nuclei", "-u", target, "-json", "-silent"]
    if template:
        cmd.extend(["-t", template])
    if severity:
        cmd.extend(["-severity", severity])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode(errors="replace").strip()

        findings = []
        for line in output.split("\n"):
            if line.strip():
                try:
                    import json
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    findings.append({"raw": line})

        return {"target": target, "findings": findings, "count": len(findings), "template": template or "all"}
    except FileNotFoundError:
        return {"target": target, "error": "nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "findings": []}
    except asyncio.TimeoutError:
        return {"target": target, "error": "nuclei scan timed out (120s)", "findings": []}
