import os
import json
import shutil
import subprocess


async def semgrep_scan(path: str, pattern: str = "") -> dict:
    """Run semgrep multi-language SAST — auto or custom pattern."""
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    if not shutil.which("semgrep"):
        return {"error": "semgrep CLI not found. Install with: pip install semgrep"}

    try:
        if pattern:
            cmd = ["semgrep", "--json", "-e", pattern, path]
        else:
            cmd = ["semgrep", "--json", "--config=auto", path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
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

    return {
        "path": path,
        "findings": findings,
        "total_findings": len(results),
    }
