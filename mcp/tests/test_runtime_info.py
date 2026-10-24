"""Runtime startup snapshots and read-only reference comparisons."""
import json
import sys
import tempfile
import unittest
import subprocess
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.runtime_info import capture_runtime, inspect_runtime, compare_reference


def package(root):
    for relative, contents in {
        "package.json": '{"name":"cybersec", "version":"1.0.0"}',
        "mcp/requirements.txt": "fastmcp\n",
        "mcp/server.py": "print('server')\n",
        "mcp/cyber_tools/example.py": "VALUE = 1\n",
        ".opencode/plugins/cybersec.js": "export default {};\n",
        "skills/example/SKILL.md": "example skill\n",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)


class TestRuntimeInfo(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "one"
        package(self.root)

    def test_hash_does_not_depend_on_install_location_or_git(self):
        other = Path(self.temp.name) / "two"
        package(other)
        first = capture_runtime(self.root)
        second = capture_runtime(other)
        self.assertEqual(first["startup_build"]["fingerprint"], second["startup_build"]["fingerprint"])
        self.assertEqual(first["package_version"], "1.0.0")
        self.assertNotEqual(first["installation_path"], second["installation_path"])
        self.assertTrue(first["server_initialized_at"].endswith("Z"))

    def test_startup_identity_is_preserved_when_disk_changes(self):
        identity = capture_runtime(self.root)
        saved = deepcopy(identity)
        (self.root / "mcp/cyber_tools/example.py").write_text("VALUE = 2\n")
        out = inspect_runtime(identity)
        self.assertEqual(out["runtime"], saved)
        self.assertEqual(out["files_on_disk"]["mcp_vs_startup"], "different")
        self.assertEqual(compare_reference(out, self.root)["status"], "different")
        out["runtime"]["startup_build"]["fingerprint"] = "tampered"
        self.assertEqual(identity, saved)

    def test_plugin_and_skills_are_disk_evidence_only(self):
        identity = capture_runtime(self.root)
        before = inspect_runtime(identity)
        (self.root / "skills/example/SKILL.md").write_text("changed skill")
        (self.root / ".opencode/plugins/cybersec.js").write_text("changed plugin")
        after = inspect_runtime(identity)
        self.assertEqual(after["files_on_disk"]["mcp_vs_startup"], "match")
        for field in ("skills", "plugin"):
            self.assertNotEqual(before["files_on_disk"][field]["fingerprint"],
                                after["files_on_disk"][field]["fingerprint"])
        self.assertEqual(after["client_plugin_state"], "unknown")
        self.assertEqual(after["client_skill_state"], "unknown")

    def test_old_payload_and_missing_reference_never_match(self):
        self.assertEqual(compare_reference({"installed": []}, self.root)["status"], "unknown")
        identity = capture_runtime(self.root)
        payload = inspect_runtime(identity)
        (self.root / "mcp/server.py").unlink()
        self.assertEqual(compare_reference(payload, self.root)["status"], "unknown")
        self.assertEqual(inspect_runtime(identity)["files_on_disk"]["mcp_vs_startup"], "unknown")

    def test_incompatible_manifest_is_unknown_not_different(self):
        payload = inspect_runtime(capture_runtime(self.root))
        payload["runtime"]["startup_build"]["algorithm"] = "unknown-algorithm"
        self.assertEqual(compare_reference(payload, self.root)["status"], "unknown")

    def test_symlink_loop_is_unknown_not_a_health_failure(self):
        identity = capture_runtime(self.root)
        source = self.root / "mcp/cyber_tools/example.py"
        source.unlink()
        source.symlink_to(source)
        self.assertEqual(inspect_runtime(identity)["files_on_disk"]["mcp_vs_startup"], "unknown")

    def test_same_source_matches_and_non_source_files_are_ignored(self):
        identity = capture_runtime(self.root)
        (self.root / ".env").write_text("SECRET=not-part-of-the-build")
        out = compare_reference(inspect_runtime(identity), self.root)
        self.assertEqual(out["status"], "match")
        self.assertNotIn("not-part-of-the-build", json.dumps(out))

    def test_external_symlink_is_not_hashed_as_package_content(self):
        identity = capture_runtime(self.root)
        source = self.root / "mcp/cyber_tools/example.py"
        source.unlink()
        outside = Path(self.temp.name) / "outside.py"
        outside.write_text("outside-source")
        source.symlink_to(outside)
        self.assertEqual(compare_reference(inspect_runtime(identity), self.root)["status"], "unknown")

    def test_comparison_cli_match_different_unknown_and_invalid_input(self):
        identity = capture_runtime(self.root)
        snapshot = Path(self.temp.name) / "health.json"
        snapshot.write_text(json.dumps(inspect_runtime(identity)))
        script = Path(__file__).resolve().parents[2] / "scripts/check_runtime.py"
        command = [sys.executable, str(script), "--runtime-json", str(snapshot),
                   "--reference-root", str(self.root)]
        matched = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(matched.returncode, 0, matched.stderr)
        self.assertEqual(json.loads(matched.stdout)["status"], "match")
        (self.root / "mcp/server.py").write_text("changed server")
        different = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(different.returncode, 1)
        self.assertEqual(json.loads(different.stdout)["status"], "different")
        for contents in ('{"installed":[]}', 'invalid-json'):
            snapshot.write_text(contents)
            unknown = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(unknown.returncode, 2)
            self.assertEqual(json.loads(unknown.stdout)["status"], "unknown")


class TestRuntimeInfoMcp(unittest.IsolatedAsyncioTestCase):
    async def test_live_tool_health_exposes_startup_identity_and_keeps_signature(self):
        from fastmcp import Client
        from server import mcp
        async with Client(mcp) as client:
            tools = {tool.name: tool for tool in await client.list_tools()}
            self.assertEqual(len(tools), 209)
            self.assertEqual(set(tools["tool_health"].inputSchema["properties"]), {"include_optional"})
            response = await client.call_tool("tool_health", {"include_optional": False})
        self.assertFalse(response.is_error)
        result = json.loads(response.content[0].text)
        self.assertIn("installed", result)
        self.assertIn("missing", result)
        self.assertEqual(result["runtime"]["startup_build"]["status"], "complete")
        self.assertEqual(result["files_on_disk"]["mcp_vs_startup"], "match")
        self.assertEqual(result["client_plugin_state"], "unknown")
