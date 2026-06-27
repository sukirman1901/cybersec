import asyncio
import re


async def binary_checksec(target: str) -> dict:
    findings = []
    try:
        proc = await asyncio.create_subprocess_exec("file", target, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        file_type = stdout.decode(errors="replace").strip()
        findings.append({"check": "file_type", "value": file_type})
    except (FileNotFoundError, asyncio.TimeoutError):
        file_type = "unknown"
    is_elf = "ELF" in file_type
    is_macho = "Mach-O" in file_type
    is_pe = "PE32" in file_type
    try:
        proc = await asyncio.create_subprocess_exec("strings", target, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        strings_output = stdout.decode(errors="replace")
        interesting = ["password", "secret", "api_key", "token", "http://", "https://", "admin", "root", "debug"]
        found = [s for s in interesting if s in strings_output.lower()]
        if found:
            findings.append({"check": "strings_interesting", "value": found, "severity": "high"})
    except (FileNotFoundError, asyncio.TimeoutError):
        findings.append({"check": "strings", "note": "strings command not available"})
    if is_elf:
        try:
            proc = await asyncio.create_subprocess_exec("readelf", "-l", target, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            readelf_out = stdout.decode(errors="replace")
            findings.append({"check": "PIE/ASLR", "enabled": "GNU_STACK" in readelf_out and "RWE" not in readelf_out.split("GNU_STACK")[1][:10] if "GNU_STACK" in readelf_out else "unknown"})
        except (FileNotFoundError, asyncio.TimeoutError):
            pass
    elif is_pe:
        findings.append({"check": "binary_type", "value": "Windows PE — use checksec.exe on Windows"})
    try:
        proc = await asyncio.create_subprocess_exec("otool", "-L", target, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        deps = stdout.decode(errors="replace")
        if deps:
            libs = [l.strip() for l in deps.split("\n") if l.strip()][:20]
            findings.append({"check": "linked_libraries", "libraries": libs})
    except (FileNotFoundError, asyncio.TimeoutError):
        pass
    return {"target": target, "file_type": file_type, "findings": findings, "count": len(findings)}
