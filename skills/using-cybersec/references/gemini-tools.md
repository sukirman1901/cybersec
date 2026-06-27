# Gemini CLI Tool Mapping for Cybersec Skills

## Tool Equivalents

When a Cybersec skill references an action, use the Gemini CLI equivalent:

| Cybersec Action | Gemini CLI Tool |
|----------------|-----------------|
| Invoke a skill | `activate_skill` tool |
| Create/update todos | Native todo/task tool if available |
| Read a file | `read_file` |
| Create/edit a file | `write_file`, `edit_file` |
| Run a shell command | `run_shell_command` |
| Search file contents | `grep` / `search_file_content` |
| Find files by pattern | `glob` / `list_directory` |
| Fetch a URL | `web_fetch` |
| Search the web | `google_web_search` |
| Security tools (port_scan, dns_lookup, etc.) | MCP tools via `cybersec` server |
| Dispatch a subagent | `generate_content` with sub-agent config |

## MCP Server Configuration

To use Cybersec MCP tools in Gemini CLI, configure the MCP server:

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

Use the venv python path: `"/path/to/cybersec/mcp/.venv/bin/python3"`.

## Skills

Cybersec skills are loaded via Gemini's `activate_skill` tool. Gemini loads
skill metadata at session start and activates the full content on demand.

Available skills: cybersec-recon, cybersec-osint, cybersec-scanning,
cybersec-vulns, cybersec-web, cybersec-bugbounty, cybersec-ad, cybersec-cloud,
cybersec-password, cybersec-exploit, cybersec-crisis, cybersec-report,
cybersec-ai, cybersec-ai-safety, cybersec-desktop, cybersec-code-audit,
cybersec-ctf, cybersec-verification, cybersec-parallel, cybersec-review,
cybersec-skill-dev.