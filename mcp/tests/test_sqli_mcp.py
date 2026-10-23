"""MCP transport compatibility for the existing SQLi tool name/signature."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import httpx
from fastmcp import Client

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestSqliMcp(unittest.IsolatedAsyncioTestCase):
    async def test_existing_tool_signature_and_confirmed_evidence_survive_mcp(self):
        from server import mcp
        real = httpx.AsyncClient

        def handler(request):
            if "'" in request.url.params.get("id", ""):
                return httpx.Response(500, text="SQL syntax error MySQL")
            return httpx.Response(200, text="stable")

        async with Client(mcp) as client:
            tools = {tool.name: tool for tool in await client.list_tools()}
            self.assertEqual(len(tools), 209)
            schema = tools["sqli_detect"].inputSchema
            self.assertEqual(set(schema["properties"]), {"target", "param", "preset"})
            self.assertEqual(schema["required"], ["target"])
            with patch("httpx.AsyncClient", side_effect=lambda **kw:
                       real(transport=httpx.MockTransport(handler), **kw)):
                response = await client.call_tool("sqli_detect", {
                    "target": "https://example.test/item?id=7&tenant=qa", "param": "id"})
            self.assertFalse(response.is_error)
            out = json.loads(response.content[0].text)
            self.assertTrue(out["vulnerable"])
            self.assertEqual(out["assessment"], "confirmed")
            self.assertEqual(json.loads(out["findings"][0]["evidence"])["confirmation_rounds"], 2)
