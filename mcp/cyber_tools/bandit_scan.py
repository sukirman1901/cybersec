import os
import json
import shutil
import subprocess
from .tool_paths import isolated_cli


async def bandit_scan(path: str, severity: str = "medium") -> dict:
    """Run bandit SAST scanner on a Python codebase."""
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    executable = shutil.which('bandit') or isolated_cli('bandit')
    if not executable:
        return {"error": "bandit CLI not found. Install with: pip install bandit"}

    severity_map = {"low": "low", "medium": "medium", "high": "high"}
    sev = severity_map.get(severity.lower(), "medium")

    try:
        result = subprocess.run(
            [executable, "-r", path, "-f", "json", "--severity-level", sev],
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        return {"error": "bandit scan timed out"}
    except Exception as e:
        return {"error": f"Failed to run bandit: {str(e)}"}

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"error": "Failed to parse bandit JSON output", "raw_output": output[:500]}

    results = data.get("results", [])
    metrics = data.get("metrics", {})

    # Extract summary metrics
    totals = metrics.get('_totals', {}) if isinstance(metrics, dict) else {}
    summary = {'total': len(results), **{sev: totals.get('SEVERITY.' + sev.upper(), 0)
                                       for sev in ('high', 'medium', 'low')}}

    findings = []
    for r in results[:100]:
        findings.append({
            "filename": r.get("filename", ""),
            "line_number": r.get("line_number", 0),
            "issue_severity": r.get("issue_severity", ""),
            "issue_confidence": r.get("issue_confidence", ""),
            "cwe": r.get("issue_cwe", {}).get("id", ""),
            "issue_text": r.get("issue_text", ""),
        })

    response = {
        "path": path,
        "summary": summary,
        "findings": findings,
        "total_findings": len(results),
        "exit_code": result.returncode,
        "coverage_complete": result.returncode in (0, 1) and not data.get('errors'),
        "coverage": "Bandit Python source rules; no runtime exploitability verification",
    }
    if not response['coverage_complete']:
        response['error'] = result.stderr[-1000:] or str(data.get('errors', 'Bandit failed'))
    return response
