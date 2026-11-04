"""Legacy TCP/161 reachability only; SNMP/UDP and communities are unverified."""
import asyncio

from .ssl_analyzer import _normalize_host
from .service_fingerprint import _close_writer


async def snmp_enum(target: str, community: str = 'public') -> dict:
    result = {'target': None, 'port': None, 'tcp_open': None, 'snmp_available': None,
              'community_validated': False, 'connection_state': 'not_started',
              'coverage_complete': False, 'execution_status': 'partial', 'confidence': 'LOW',
              'coverage': 'TCP reachability only; SNMP protocol, UDP/161 and supplied community are unverified. No community values transmitted or returned.'}
    writer = None
    try:
        host, port = _normalize_host(target, 161)
        result.update(target=host, port=port, connection_state='unknown')
        async with asyncio.timeout(5):
            _, writer = await asyncio.open_connection(host, port)
            result.update(tcp_open=True, connection_state='open')
    except ConnectionRefusedError:
        result.update(tcp_open=False, connection_state='refused', error='TCP connection refused; UDP/SNMP remain unverified')
    except (OSError, asyncio.TimeoutError, ValueError):
        result['error'] = 'TCP observation incomplete or target invalid; SNMP unverified'
    finally:
        await _close_writer(writer)
    return result
