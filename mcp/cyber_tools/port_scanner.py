"""Bounded TCP reachability and banner hints, not vulnerability proof."""
import socket
import asyncio
import re
import time
import math
import ipaddress

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer, _banner_identity


COMMON_PORTS = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'dns', 67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http',
    88: 'kerberos', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
    137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn',
    143: 'imap', 161: 'snmp', 162: 'snmptrap', 389: 'ldap',
    443: 'https', 445: 'smb', 464: 'kerberos', 465: 'smtps',
    514: 'syslog', 515: 'lpd', 554: 'rtsp', 587: 'smtp',
    631: 'ipp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s',
    1080: 'socks', 1099: 'rmiregistry', 1433: 'mssql',
    1434: 'mssql-m', 1521: 'oracle', 1723: 'pptp',
    2049: 'nfs', 2181: 'zookeeper', 3306: 'mysql',
    3389: 'rdp', 5432: 'postgresql', 5672: 'rabbitmq',
    5900: 'vnc', 5901: 'vnc', 6379: 'redis', 6443: 'kubernetes',
    8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt',
    9090: 'prometheus', 9200: 'elasticsearch', 9418: 'git',
    9999: 'http-alt', 10000: 'webmin', 11211: 'memcached',
    27017: 'mongodb', 27018: 'mongodb', 50000: 'sap',
    50070: 'hdfs', 60010: 'hbase', 60020: 'hbase',
}
COMMON_SERVICE_PORTS = COMMON_PORTS
UNSUPPORTED_BANNERS = (443, 8443, 465, 636, 993, 995, 27017, 27018)
MAX_PORTS = 1024
MAX_BANNERS = 16
SCAN_SECONDS = 30


def _validate(target, selected, timeout, concurrency):
    host, _ = _normalize_host(target)
    if host != target or not math.isfinite(timeout) or not 0 < timeout <= 10:
        raise ValueError('invalid_input')
    if not isinstance(concurrency, int) or not 1 <= concurrency <= 200:
        raise ValueError('invalid_input')
    if len(selected) > MAX_PORTS or not selected or any(type(p) is not int or not 1 <= p <= 65535 for p in selected):
        raise ValueError('invalid_ports')
    return host


async def _resolve(host):
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return await asyncio.wait_for(asyncio.to_thread(socket.gethostbyname, host), timeout=5)


async def _check_port(ip: str, port: int, timeout: float = 1.0) -> int | None:
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return port
    except ConnectionRefusedError:
        return None
    finally:
        await _close_writer(writer)


async def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    writer = None
    try:
        if port in UNSUPPORTED_BANNERS:
            raise ValueError('negotiation_unsupported')
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(ip, port)
            payload = None
            if port in (80, 8080, 8888, 9090, 10000, 50000):
                payload = f'HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode()
            elif port == 9200:
                payload = f'GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode()
            elif port == 6379:
                payload = b'PING\r\n'
            elif port == 11211:
                payload = b'version\r\n'
            elif port not in (21, 22, 25, 587, 161, 445, 139):
                payload = b'\r\n'
            if payload:
                writer.write(payload)
                await writer.drain()
            return (await reader.read(4096)).decode(errors='replace')
    finally:
        await _close_writer(writer)


def _fingerprint_service(banner: str, port: int) -> dict:
    service, details = _banner_identity(banner)
    result = {'port': port, 'service': COMMON_PORTS.get(port, 'unknown'),
              'banner': '[raw banner withheld]' if banner else '', 'protocol': 'tcp',
              'version': details.get('protocol_version', ''), 'risk': 'info', 'vuln_hints': [],
              'confidence': 'LOW', 'coverage': 'Port-label or protocol banner hint only; authentication and vulnerabilities not tested'}
    if service != 'unknown':
        result['detected_service'] = service
    return result


async def _concurrent_scan(ip: str, ports: list[int], timeout: float = 1.0, concurrency: int = 200) -> list[int]:
    _validate(ip, ports, timeout, concurrency)
    semaphore = asyncio.Semaphore(concurrency)
    async def check(port):
        async with semaphore:
            return await _check_port(ip, port, timeout)
    # Collect errors before raising, so no sibling probes outlive the call.
    async with asyncio.timeout(SCAN_SECONDS):
        observations = await asyncio.gather(*(check(p) for p in sorted(set(ports))), return_exceptions=True)
    if any(isinstance(value, BaseException) for value in observations):
        raise OSError('TCP scan incomplete; unknown ports cannot be classified')
    return sorted(value for value in observations if value is not None)


def scan_ports(target: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Legacy list API raises on incomplete observations instead of returning clean []."""
    host = _validate(target, ports, timeout, 100)
    async def run():
        async with asyncio.timeout(SCAN_SECONDS):
            return await _concurrent_scan(await _resolve(host), ports, timeout, concurrency=100)
    try:
        return asyncio.run(run())
    except (OSError, asyncio.TimeoutError):
        raise OSError('TCP scan incomplete') from None


def detect_service(target: str, port: int, timeout: float = 1.0) -> dict:
    try:
        host = _validate(target, [port], timeout, 1)
        async def run():
            async with asyncio.timeout(5 + timeout):
                return await _grab_banner(await _resolve(host), port, timeout)
        banner = asyncio.run(run())
        return {**_fingerprint_service(banner, port), 'coverage_complete': bool(banner)}
    except (ValueError, TypeError, OSError, asyncio.TimeoutError):
        return {**_fingerprint_service('', port), 'coverage_complete': False, 'error': 'Service observation incomplete'}


async def port_scanner(target: str, ports: str = '', timeout: float = 1.0, concurrency: int = 200) -> dict:
    result = {'target': None, 'open_ports': [], 'closed_ports': [], 'unknown_ports': [],
              'services': [], 'total_open': 0, 'ports_scanned': 0, 'requests_attempted': 0,
              'coverage_complete': False, 'execution_status': 'partial', 'errors': [],
              'critical_services': [], 'high_risk_services': [],
              'coverage': 'TCP only; max 1024 ports/200 concurrency/30s plus bounded cleanup, at most 16 banner samples. TLS/binary negotiation unsupported. DNS names use IPv4; no vulnerability verification.'}
    try:
        selected = set()
        if ports:
            for part in ports.split(','):
                if not re.fullmatch(r'\d+(?:-\d+)?', part.strip()):
                    raise ValueError('invalid_ports')
                bounds = [int(value) for value in part.strip().split('-')]
                low, high = bounds[0], bounds[-1]
                if not 1 <= low <= high <= 65535 or high - low >= MAX_PORTS:
                    raise ValueError('invalid_ports')
                selected.update(range(low, high + 1))
                if len(selected) > MAX_PORTS:
                    raise ValueError('port_budget')
        else:
            selected.update(COMMON_PORTS)
        host = _validate(target, selected, timeout, concurrency)
        port_list = sorted(selected)
        result['target'] = host
    except (ValueError, TypeError, AttributeError):
        result.update(error='Invalid target, ports or scan budget', errors=['invalid_input'])
        return result
    start = time.monotonic()
    completed = set()
    try:
        async with asyncio.timeout(SCAN_SECONDS):
            ip = await _resolve(host)
            result['ip'] = ip
            semaphore = asyncio.Semaphore(concurrency)
            async def check(port):
                async with semaphore:
                    result['requests_attempted'] += 1
                    try:
                        opened = await _check_port(ip, port, timeout)
                        result['open_ports' if opened is not None else 'closed_ports'].append(port)
                    except (OSError, asyncio.TimeoutError):
                        result['unknown_ports'].append(port)
                    completed.add(port)
            await asyncio.gather(*(check(port) for port in port_list))
            for port in sorted(result['open_ports']):
                info = _fingerprint_service('', port)
                if len(result['services']) >= MAX_BANNERS or port in UNSUPPORTED_BANNERS:
                    info.update(coverage_complete=False, error='Banner budget or unsupported negotiation')
                else:
                    result['requests_attempted'] += 1
                    try:
                        banner = await _grab_banner(ip, port, timeout=min(timeout, 2))
                        info = {**_fingerprint_service(banner, port), 'coverage_complete': bool(banner)}
                    except (OSError, asyncio.TimeoutError, ValueError):
                        info.update(coverage_complete=False, error='Banner observation incomplete')
                result['services'].append(info)
    except (OSError, asyncio.TimeoutError):
        result['errors'].append('resolution_or_scan_incomplete')
    result['unknown_ports'] = sorted(set(result['unknown_ports']) | (set(port_list) - completed))
    result['open_ports'].sort()
    result['closed_ports'].sort()
    result['ports_scanned'] = len(completed)
    result['total_open'] = len(result['open_ports'])
    result['scan_time_seconds'] = round(time.monotonic() - start, 2)
    result['risk_summary'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': len(result['services'])}
    if result['unknown_ports'] or any(not s.get('coverage_complete') for s in result['services']) or len(result['services']) != result['total_open']:
        result['errors'].append('port_or_banner_coverage_incomplete')
    result['coverage_complete'] = not result['errors']
    result['execution_status'] = 'completed' if result['coverage_complete'] else 'partial'
    if result['errors']:
        result['error'] = 'Scan incomplete; unknown ports are not closed observations'
    return result
