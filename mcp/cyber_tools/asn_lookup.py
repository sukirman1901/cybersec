"""ASN lookup for an IP address via Team Cymru."""

import socket
import asyncio
import ipaddress
import re


async def asn_lookup(ip: str) -> dict:
    result = {'ip': '[unresolved]', 'coverage_complete': False, 'assessment': 'incomplete',
              'coverage': 'Single IPv4 Team Cymru response; no route ownership or freshness attestation'}
    writer = None
    try:
        async with asyncio.timeout(15):
            try:
                address = ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                if not isinstance(ip, str) or len(ip) > 253 or not re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', ip):
                    raise ValueError('Unsupported IPv4 address/hostname')
                address = ipaddress.IPv4Address(await asyncio.to_thread(socket.gethostbyname, ip))
            result['ip'] = str(address)
            reader, writer = await asyncio.wait_for(asyncio.open_connection('whois.cymru.com', 43), timeout=5)
            writer.write(f'begin\nverbose\n{address}\nend\n'.encode())
            await writer.drain()
            data = bytearray()
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                if not chunk:
                    break
                if len(data) + len(chunk) > 65536:
                    raise ValueError('Response size limit')
                data.extend(chunk)
        for line in data.decode(errors="replace").split("\n"):
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 5 or parts[0] in ('AS', 'ASN'):
                continue
            if parts[1] != str(address):
                continue
            if parts[0] == 'NA' and parts[2] == 'NA':
                return {**result, 'coverage_complete': True, 'assessment': 'no_results_in_response'}
            if not re.fullmatch(r'\d{1,10}', parts[0]) or not 1 <= int(parts[0]) <= 4294967295:
                continue
            network = ipaddress.IPv4Network(parts[2], strict=True)
            if address not in network or not re.fullmatch(r'[A-Z]{2}', parts[3]) or not re.fullmatch(r'[A-Za-z-]{1,32}', parts[4]):
                continue
            return {**result, 'asn': parts[0], 'cidr': str(network), 'country': parts[3],
                    'registry': parts[4], 'coverage_complete': True, 'assessment': 'provider_record'}
        result['error'] = 'No valid matching provider record'
    except (OSError, ValueError, TypeError, asyncio.TimeoutError) as exc:
        result['error'] = type(exc).__name__
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except (OSError, asyncio.TimeoutError):
                pass
    return result
