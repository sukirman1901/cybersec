import os
import json
import shutil
import subprocess
from .tool_paths import isolated_cli


async def semgrep_scan(path: str, pattern: str = "") -> dict:
    """Run semgrep multi-language SAST — auto or custom pattern."""
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    executable = shutil.which('semgrep') or isolated_cli('semgrep')
    if not executable:
        return {"error": "semgrep CLI not found. Install with: pip install semgrep"}

    try:
        if pattern:
            language = {'.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                        '.java': 'java', '.go': 'go', '.php': 'php', '.rb': 'ruby'}.get(os.path.splitext(path)[1])
            if not language:
                return {'error': 'Custom pattern requires a single file with a supported language extension', 'coverage_complete': False}
            cmd = [executable, "--json", "--metrics=off", '--lang', language, "-e", pattern, path]
        else:
            cmd = [executable, "--json", "--metrics=off", "--config=auto", path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                                env={**os.environ, 'SEMGREP_ENABLE_VERSION_CHECK': '0', 'SEMGREP_SEND_METRICS': 'off'})
        output = result.stdout
    except subprocess.TimeoutExpired:
        return {"error": "semgrep scan timed out"}
    except Exception as e:
        return {"error": f"Failed to run semgrep: {str(e)}"}

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"error": "Failed to parse semgrep JSON output", "raw_output": output[:500]}

    results = data.get("results", [])

    findings = []
    for r in results[:100]:
        findings.append({
            "path": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "check_id": r.get("check_id", ""),
            "severity": r.get("extra", {}).get("severity", ""),
            "message": r.get("extra", {}).get("message", ""),
        })

    response = {
        "path": path,
        "findings": findings,
        "total_findings": len(results),
        "exit_code": result.returncode,
        "coverage_complete": result.returncode in (0, 1) and not data.get('errors'),
        "errors": data.get('errors', []),
        "coverage": "Semgrep selected rules; inspect skipped files and parser errors",
    }
    if not response['coverage_complete']:
        response['error'] = result.stderr[-1000:] or 'Semgrep reported errors'
    return response
