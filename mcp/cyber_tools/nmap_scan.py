import asyncio


async def nmap_scan(target: str, ports: str = "", scripts: str = "") -> dict:
    cmd = ["nmap", "-oX", "-", target]
    if ports:
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443"])
    if scripts:
        cmd.extend(["--script", scripts])
    cmd.append("-sV")

    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

        import xml.etree.ElementTree as ET
        root = ET.fromstring(stdout)
        hosts = []
        for host in root.findall(".//host"):
            addr = host.find(".//address")
            ip = addr.get("addr") if addr is not None else ""
            ports_found = []
            for p in host.findall(".//port"):
                state = p.find("state")
                svc = p.find("service")
                if state is not None and state.get("state") == "open":
                    ports_found.append({
                        "port": p.get("portid"),
                        "protocol": p.get("protocol"),
                        "service": svc.get("name") if svc is not None else "",
                        "product": svc.get("product") if svc is not None else "",
                        "version": svc.get("version") if svc is not None else "",
                    })
            hosts.append({"ip": ip, "open_ports": ports_found, "count": len(ports_found)})

        return {"target": target, "hosts": hosts, "total_open": sum(h["count"] for h in hosts)}
    except FileNotFoundError:
        return {"target": target, "error": "nmap not found. Install: brew install nmap"}
    except asyncio.TimeoutError:
        return {"target": target, "error": "nmap scan timed out (180s)"}
