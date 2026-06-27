#!/usr/bin/env bash
# Hook wrapper for cybersec plugin (cross-platform)
# Usage: ./hooks/run-hook.cmd <hook-name>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_NAME="${1:-session-start}"
HOOK_SCRIPT="${SCRIPT_DIR}/${HOOK_NAME}"

if [ -f "${HOOK_SCRIPT}" ]; then
  exec bash "${HOOK_SCRIPT}"
else
  echo "Error: Hook script not found: ${HOOK_SCRIPT}" >&2
  exit 1
fi