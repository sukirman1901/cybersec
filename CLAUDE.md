# Cybersec — Cybersecurity Tools for Claude Code

@./skills/using-cybersec/SKILL.md

## MCP Server Setup

The Cybersec MCP server provides 172+ security tools. To use them in Claude Code, add the MCP server to your Claude Code configuration:

### Option 1: Project-level MCP config

Create or edit `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "cybersec": {
      "command": "python3",
      "args": ["-m", "server"],
      "cwd": "/path/to/cybersec/mcp"
    }
  }
}
```

### Option 2: Global Claude Code config

Add to `~/.claude/config.json`:

```json
{
  "mcpServers": {
    "cybersec": {
      "command": "python3",
      "args": ["-m", "server"],
      "cwd": "/path/to/cybersec/mcp"
    }
  }
}
```

### Prerequisites

```bash
cd /path/to/cybersec/mcp
python3 -m venv .venv
source .venv/bin/activate
pip install fastmcp>=0.4.0 httpx dnspython
```

Use the venv python path in the MCP config: `"/path/to/cybersec/mcp/.venv/bin/python3"` instead of `python3`.

## Tool Mapping for Claude Code

Cybersec skills reference MCP tools by name (e.g., `port_scan`, `dns_lookup`). These are available via the MCP server and called directly by tool name.

- Create or update todos → `TodoWrite`
- Invoke a skill → `Skill` tool
- Run shell commands → `Bash`
- Read files → `Read`
- Create, edit files → `Edit`, `Write`
- Search files → `Grep`, `Glob`
- Security tools (port_scan, dns_lookup, etc.) → MCP tools via `cybersec` server