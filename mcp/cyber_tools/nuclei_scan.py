import asyncio


async def nuclei_scan(target: str, template: str = "", severity: str = "") -> dict:
    # Nuclei v3 uses -j / -jsonl; legacy -json is rejected ("flag provided but not defined").
    cmd = ["nuclei", "-u", target, "-j", "-silent"]
    if template:
        cmd.extend(["-t", template])
    if severity:
        cmd.extend(["-severity", severity])

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        communication = asyncio.create_task(proc.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), timeout=120)
        output = stdout.decode(errors="replace").strip()
        err = stderr.decode(errors="replace").strip()

        findings = []
        for line in output.split("\n"):
            if line.strip():
                try:
                    import json
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    findings.append({"raw": line})

        result = {
            "target": target,
            "findings": findings,
            "count": len(findings),
            "template": template or "all",
            "confidence": "HIGH" if findings else "LOW",
            "coverage": "nuclei_cli; jsonl_stdout",
            "exit_code": proc.returncode,
            "coverage_complete": proc.returncode == 0,
            "execution_status": "completed" if proc.returncode == 0 else "error",
        }
        if proc.returncode != 0:
            result["error"] = err[-1000:] or f"nuclei exited {proc.returncode}"
        if err and not findings:
            result["stderr_tail"] = err[-500:]
        return result
    except FileNotFoundError:
        return {"target": target, "error": "nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "findings": [], "confidence": "LOW", "coverage": "cli_missing"}
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
        stdout, stderr = await communication
        import json
        partial = []
        for line in stdout.decode(errors="replace").splitlines():
            try:
                partial.append(json.loads(line))
            except ValueError:
                pass
        return {"target": target, "error": "nuclei scan timed out (120s)", "findings": partial,
                "count": len(partial), "confidence": "LOW", "coverage": "timeout; partial stdout",
                "coverage_complete": False, "execution_status": "partial"}
    except asyncio.CancelledError:
        if proc is not None:
            if proc.returncode is None:
                proc.kill()
            await communication
        raise
