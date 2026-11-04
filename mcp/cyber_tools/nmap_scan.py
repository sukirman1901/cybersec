import asyncio
import xml.etree.ElementTree as ET

from .cli_tools import _run_cli


async def nmap_scan(target: str, ports: str = "", scripts: str = "") -> dict:
    cmd = ["nmap", "-oX", "-", target]
    if ports:
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443"])
    if scripts:
        cmd.extend(["--script", scripts])
    cmd.append("-sV")

    run = await _run_cli(cmd, timeout=180)
    hosts = []
    problem = ''
    try:
        root = ET.fromstring(run.get('stdout', ''))
        if root.tag != 'nmaprun':
            raise ValueError('Unexpected XML root')
        finished = root.find('runstats/finished')
        if finished is None or finished.get('exit') != 'success':
            problem = 'Nmap completion not confirmed by XML'
        for host in root.findall("host"):
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

    except (ET.ParseError, ValueError):
        problem = 'Invalid Nmap XML output'
    if run.get('exit_code') != 0:
        problem = 'Nmap execution failed or timed out; scan incomplete'
    return {"target": target, "hosts": hosts, "total_open": sum(h["count"] for h in hosts),
            'exit_code': run.get('exit_code'), 'coverage_complete': not problem,
            'execution_status': 'error' if problem else 'completed',
            'confidence': 'LOW' if problem else 'MEDIUM',
            'coverage': 'External Nmap XML port observations; no independent service verification',
            **({'error': problem} if problem else {})}
