import os
import json
import shutil
import subprocess


async def bandit_scan(path: str, severity: str = "medium") -> dict:
    """Run bandit SAST scanner on a Python codebase."""
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    if not shutil.which("bandit"):
        return {"error": "bandit CLI not found. Install with: pip install bandit"}

    severity_map = {"low": "low", "medium": "medium", "high": "high"}
    sev = severity_map.get(severity.lower(), "medium")

    try:
        result = subprocess.run(
            ["bandit", "-r", path, "-f", "json", "-s", sev],
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
    summary = {
        "total": metrics.get("total", len(results)),
    }
    if isinstance(metrics, dict):
        # bandit metrics are keyed by severity level
        summary["high"] = metrics.get("high", 0) if isinstance(metrics.get("high"), int) else 0
        summary["medium"] = metrics.get("medium", 0) if isinstance(metrics.get("medium"), int) else 0
        summary["low"] = metrics.get("low", 0) if isinstance(metrics.get("low"), int) else 0
    else:
        summary["high"] = 0
        summary["medium"] = 0
        summary["low"] = 0

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

    return {
        "path": path,
        "summary": summary,
        "findings": findings,
        "total_findings": len(results),
    }
