#!/usr/bin/env bash
# Install core CLI dependencies for cybersec MCP tools (macOS).
set -euo pipefail

echo "==> Installing Homebrew packages..."
brew install nmap nikto sqlmap ffuf gobuster masscan amass gitleaks testssl whois exploitdb hydra 2>/dev/null || true

echo "==> Installing Go-based scanners..."
if command -v go >/dev/null 2>&1; then
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  echo "Add Go bin to PATH if needed: export PATH=\"\$PATH:$(go env GOPATH)/bin\""
else
  echo "WARN: Go not installed — skip nuclei/subfinder/httpx or install from https://go.dev/dl/"
fi

echo "==> Nuclei templates..."
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates 2>/dev/null || true
fi

echo "==> Optional: wpscan (Ruby gem)..."
if command -v gem >/dev/null 2>&1; then
  gem install wpscan 2>/dev/null || echo "WARN: wpscan gem install failed"
fi

echo "==> Isolated Python scanners (keeps Certipy dependencies out of core MCP)..."
if command -v python3 >/dev/null 2>&1; then
  python3 "$(dirname "$0")/install-python-tools.py" bandit semgrep sslyze certipy
fi

echo "Done. Run tool_health and scanner smoke checks; executable presence does not establish readiness."
