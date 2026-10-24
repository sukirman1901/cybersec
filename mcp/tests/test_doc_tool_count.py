"""Documented MCP tool counts must match the live in-process server registry.

The 2026-10-23/24 sessions drifted twice (207 → 208 → 209 documented while the
server registered a different number). This guard fails build/docs review when
any documented count no longer equals the actual registered tool count.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO = Path(__file__).resolve().parents[2]

# Exact doc phrases that carry a tool-count claim. Deliberately narrow so that
# years, URLs, CVE/RFC numbers and other "20xx" text never trigger a match.
DOC_PATTERNS = (
    r"registers \*\*(\d+) tools\*\*",
    r"provides (\d+) security tools",
    r"provides (\d+) cybersecurity MCP tools",
    r"Expected: (\d+) tools listed",
)


class TestDocToolCount(unittest.IsolatedAsyncioTestCase):
    async def test_documented_tool_counts_match_server_registry(self):
        from fastmcp import Client
        from server import mcp

        async with Client(mcp) as client:
            tools = await client.list_tools()
        actual = len(tools)

        claims = []
        for doc_name in ("README.md", "AGENTS.md"):
            text = (REPO / doc_name).read_text(encoding="utf-8")
            for pattern in DOC_PATTERNS:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    claims.append((doc_name, match.group(0), int(match.group(1))))

        self.assertGreater(len(claims), 0,
                           "No documented tool-count claim found; "
                           "update DOC_PATTERNS or the docs")
        wrong = [claim for claim in claims if claim[2] != actual]
        self.assertFalse(
            wrong,
            f"Server registers {actual} tools but docs claim otherwise: {wrong}")
