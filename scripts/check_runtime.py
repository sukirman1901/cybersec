"""Compare a saved live tool_health JSON response against explicit repo sources.

Read-only: no client discovery, server spawn, config/cache changes or reload.
Exit 0=match, 1=different, 2=unknown/invalid input. Input may contain local paths;
redact diagnostics before publishing them.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mcp"))
from cyber_tools.runtime_info import compare_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-json", required=True, help="Saved live tool_health result, or - for stdin")
    parser.add_argument("--reference-root", required=True, help="Explicit Cybersec checkout root")
    args = parser.parse_args()
    try:
        if args.runtime_json == "-":
            content = sys.stdin.read(1_000_001)
        else:
            with Path(args.runtime_json).open(encoding="utf-8") as stream:
                content = stream.read(1_000_001)
        if len(content) > 1_000_000:
            raise ValueError("input exceeds limit")
        result = compare_reference(json.loads(content), args.reference_root)
    except (OSError, ValueError, RuntimeError):
        result = {"status": "unknown", "error": "Cannot read valid bounded runtime JSON or reference files"}
    print(json.dumps(result, indent=2))
    return {"match": 0, "different": 1, "unknown": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
