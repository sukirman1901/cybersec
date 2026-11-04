"""MCP dependency health check — reports installed/missing CLI tools and Python modules."""

import shutil
from .tool_paths import which_cli
from typing import Any

# Some brew packages use a different binary name on PATH
_CLI_ALIASES: dict[str, list[str]] = {
    "testssl": ["testssl", "testssl.sh"],
}


def _which_cli(tool: str) -> str | None:
    for name in _CLI_ALIASES.get(tool, [tool]):
        path = which_cli(name)
        if path:
            return path
    return None

# Core CLI tools referenced across cyber_tools
CLI_TOOLS: dict[str, str] = {
    "nmap": "brew install nmap",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf": "brew install ffuf",
    "gobuster": "brew install gobuster",
    "sqlmap": "brew install sqlmap",
    "nikto": "brew install nikto",
    "masscan": "brew install masscan",
    "amass": "brew install amass",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "wpscan": "gem install wpscan",
    "testssl": "brew install testssl",
    "gitleaks": "brew install gitleaks",
    "whois": "brew install whois",
    "searchsploit": "brew install exploitdb",
    "hydra": "brew install hydra",
    "bandit": "pipx install bandit",
    "semgrep": "pipx install semgrep",
    "sslyze": "pipx install sslyze",
    "xsstrike": "Install XSStrike in an isolated environment",
    "cmseek": "Install CMSeeK in an isolated environment",
    "certipy": "pipx install certipy-ad (isolated from core MCP)",
    "bloodhound-python": "pipx install bloodhound",
    "frida": "pipx install frida-tools",
    "objection": "pipx install objection",
    "aws": "Install AWS CLI and configure an authorized account",
    "az": "Install Azure CLI and configure an authorized account",
    "gcloud": "Install Google Cloud CLI and configure an authorized account",
}

OPTIONAL_API_KEYS = {
    "SHODAN_API_KEY": "Enables shodan_lookup",
    "SERPAPI_API_KEY": "Enables dork_scan/dork_hunt via engines=serpapi",
}

SMOKE_ARGS = {'nuclei': ['-version'], 'sqlmap': ['--version'], 'nmap': ['--version'],
              'amass': ['-version'], 'bandit': ['--version'], 'semgrep': ['--version'],
              'sslyze': ['--help'], 'certipy': ['-h']}


def check_cli_runtime(tool):
    import os
    import subprocess
    binary = _which_cli(tool)
    result = {'executable_present': bool(binary), 'execution_verified': False}
    if not binary or tool not in SMOKE_ARGS:
        result['status'] = 'missing' if not binary else 'not_probed'
        return result
    try:
        proc = subprocess.run([binary, *SMOKE_ARGS[tool]], capture_output=True, text=True, timeout=5,
                              env={**os.environ, 'SEMGREP_ENABLE_VERSION_CHECK': '0', 'SEMGREP_SEND_METRICS': 'off'})
        result.update(exit_code=proc.returncode, execution_verified=proc.returncode == 0,
                      status='smoke_passed' if proc.returncode == 0 else 'failed',
                      detail=(proc.stdout + proc.stderr)[:500])
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.update(status='failed', detail=type(exc).__name__)
    return result


def check_tool_health(include_optional: bool = True) -> dict[str, Any]:
    """Return install status for bundled CLI dependencies."""
    installed: list[str] = []
    missing: list[dict[str, str]] = []

    for tool, hint in CLI_TOOLS.items():
        if _which_cli(tool):
            installed.append(tool)
        else:
            missing.append({"tool": tool, "install_hint": hint})

    result: dict[str, Any] = {
        "installed_count": len(installed),
        "missing_count": len(missing),
        "total_checked": len(CLI_TOOLS),
        "coverage_percent": round(len(installed) / len(CLI_TOOLS) * 100, 1),
        "installed": sorted(installed),
        "missing": missing,
        "ready_for_bug_bounty": False,
        "readiness": "not_assessed; executable presence is not operational readiness",
        "limitations": ["Version/argument compatibility, templates, API credentials, authentication and target-specific coverage require separate checks"],
        "capabilities": {name: {"executable_present": name in installed, "execution_verified": False}
                         for name in CLI_TOOLS},
        "recommendation": (
            "Run scripts/install-deps.sh to install missing core scanners."
            if missing
            else "All core CLI dependencies are available."
        ),
    }

    if include_optional:
        import os

        api_status = {}
        for key, purpose in OPTIONAL_API_KEYS.items():
            api_status[key] = {"set": bool(os.environ.get(key)), "purpose": purpose}
        result["api_keys"] = api_status
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=4) as pool:
            for name, state in zip(SMOKE_ARGS, pool.map(check_cli_runtime, SMOKE_ARGS)):
                result['capabilities'][name] = state

    return result
