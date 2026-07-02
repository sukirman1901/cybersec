"""MCP dependency health check — reports installed/missing CLI tools and Python modules."""

import shutil
from typing import Any

# Some brew packages use a different binary name on PATH
_CLI_ALIASES: dict[str, list[str]] = {
    "testssl": ["testssl", "testssl.sh"],
}


def _which_cli(tool: str) -> str | None:
    for name in _CLI_ALIASES.get(tool, [tool]):
        path = shutil.which(name)
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
}

OPTIONAL_API_KEYS = {
    "SHODAN_API_KEY": "Enables shodan_lookup",
    "SERPAPI_API_KEY": "Enables dork_scan/dork_hunt via engines=serpapi",
}


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
        "ready_for_bug_bounty": len(missing) <= 5,
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

    return result
