#!/usr/bin/env bash
set -euo pipefail

MCP_DIR="/Users/aaa/Documents/Developer/cybersec/mcp"
export FASTMCP_SHOW_SERVER_BANNER=false
export FASTMCP_CHECK_FOR_UPDATES=off
export NO_COLOR=1

# Load local secrets (gitignored) — SERPAPI_API_KEY, SHODAN_API_KEY, etc.
if [[ -f "$MCP_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$MCP_DIR/.env"
  set +a
fi

cd "$MCP_DIR"
exec "$MCP_DIR/.venv/bin/python3" "$MCP_DIR/server.py"
