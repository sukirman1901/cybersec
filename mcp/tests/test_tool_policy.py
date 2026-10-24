"""Tool-kind dispatch, useful evidence, and concurrent MCP regression tests.

No real scanner, account enumeration, search engine or exploit is invoked.
"""
import asyncio
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

from fastmcp import Client
from fastmcp.exceptions import ToolError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools.engagement_gate import engagement_context, engagement_gate, new_engagement
from cyber_tools.scope_middleware import check_dispatch

SCOPE = {"domains": ["fixture.test"], "ips": ["192.0.2.10"],
         "providers": ["aws"], "buckets": ["fixture-bucket"],
         "companies": ["fixture"], "repositories": ["fixture/project"]}


class TestToolKinds(unittest.TestCase):
    def setUp(self):
        self.context = engagement_context(new_engagement())
        self.context.__enter__()

    def tearDown(self):
        self.context.__exit__(None, None, None)

    def authorize(self):
        engagement_gate("init", scope_json=json.dumps(SCOPE))
        engagement_gate("authorize", confirmation="yes")

    def test_local_tools_do_not_need_a_website_scope(self):
        for name, args in [("gitleaks_check", {"path": "/local/source"}),
                           ("jwt_forgery", {"token": "synthetic"}),
                           ("ios_frida", {"action": "list", "process": "local-app"}),
                           ("ios_objection", {"action": "list", "package": "local-app"})]:
            with self.subTest(tool=name):
                check_dispatch(name, args)

    def test_search_and_identity_tools_do_not_need_a_website_scope(self):
        cases = {"dork_search": {"query": "site:fixture.test"},
                 "shodan_lookup": {"query": "hostname:fixture.test"},
                 "ghdb_search": {"query": "fixture"}, "dork_scan": {"dorks": "site:fixture.test"},
                 "exploit_db_download": {"exploit_id": "123"},
                 "people_osint": {"query": "fixture"}, "social_osint": {"username": "fixture"},
                 "telegram_osint": {"username": "fixture"}, "phone_osint": {"phone_number": "+12025550123"},
                 "email_osint": {"email": "fixture@example.test"}}
        for name, args in cases.items():
            with self.subTest(tool=name):
                check_dispatch(name, args)

    def test_typed_scope_can_be_authorized_without_a_domain(self):
        engagement_gate("init", scope_json=json.dumps({"buckets": ["fixture-bucket"]}))
        result = json.loads(engagement_gate("authorize", confirmation="yes"))
        self.assertEqual(result["status"], "authorized")
        check_dispatch("s3_scanner", {"bucket_name": "fixture-bucket"})

    def test_resource_tools_use_their_actual_resource_identity(self):
        self.authorize()
        for name, args in [("s3_scanner", {"bucket_name": "fixture-bucket"}),
                           ("cloud_enum", {"company": "fixture"}),
                           ("cloud_iam_audit", {"provider": "aws"}),
                           ("cloud_infra", {"provider": "aws"}),
                           ("github_issue", {"repo": "fixture/project"})]:
            with self.subTest(tool=name):
                check_dispatch(name, args)

    def test_other_resources_are_denied(self):
        self.authorize()
        for name, args in [("s3_scanner", {"bucket_name": "another-bucket"}),
                           ("cloud_enum", {"company": "another"}),
                           ("cloud_iam_audit", {"provider": "gcp"}),
                           ("github_issue", {"repo": "another/project"})]:
            with self.subTest(tool=name), self.assertRaises(ToolError):
                check_dispatch(name, args)

    def test_injection_shaped_resource_names_are_denied(self):
        for key, value in [("buckets", "fixture@outside.test"),
                           ("companies", "fixture/path"), ("repositories", "owner/repo/../else")]:
            with self.subTest(kind=key):
                result = json.loads(engagement_gate("init", scope_json=json.dumps({key: [value]})))
                self.assertIn("error", result)

    def test_discovery_is_not_blanket_rejected(self):
        self.authorize()
        check_dispatch("dork_hunt", {"target": "fixture.test", "probe": True})
        check_dispatch("dork_and_scan", {"target": "fixture.test", "urls": "https://fixture.test/a"})

    def test_search_only_dork_hunt_does_not_need_scanner_scope(self):
        check_dispatch("dork_hunt", {"probe": False, "validate": True})


class TestDiscoveryBoundaries(unittest.IsolatedAsyncioTestCase):
    async def test_pipeline_filters_discovered_hosts_before_scanning(self):
        from cyber_tools.dork_pipeline import dork_and_scan
        with engagement_context(new_engagement()):
            engagement_gate("init", target="fixture.test")
            engagement_gate("authorize", confirmation="yes")
            with patch("cyber_tools.dork_pipeline._scan_one", new_callable=AsyncMock,
                       return_value={"finding_count": 0, "sqli": None, "vulnerabilities": []}) as scan:
                result = await dork_and_scan(urls="https://fixture.test/a,https://outside.test/b")
            self.assertEqual(scan.await_count, 1)
            self.assertIn("fixture.test", scan.call_args.args[0])
            self.assertEqual(result["summary"]["scan_targets"], 1)
            self.assertTrue(result["warnings"])

    async def test_hunt_does_not_probe_out_of_scope_search_results(self):
        import httpx
        from cyber_tools.dork_hunt import dork_hunt
        seen = []

        def respond(request):
            seen.append(request.url.host)
            return httpx.Response(200, text="public fixture")

        real = httpx.AsyncClient
        search = AsyncMock(return_value=[{"url": "https://fixture.test/a", "title": "a", "engine": "ddg", "dork": "fixture"},
                                         {"url": "https://outside.test/b", "title": "b", "engine": "ddg", "dork": "fixture"}])
        with engagement_context(new_engagement()):
            engagement_gate("init", target="fixture.test")
            engagement_gate("authorize", confirmation="yes")
            with patch.dict("cyber_tools.dork_hunt._ENGINE_MAP", {"ddg": search}), patch(
                "cyber_tools.dork_hunt.httpx.AsyncClient",
                side_effect=lambda **kw: real(transport=httpx.MockTransport(respond), **kw)
            ):
                await dork_hunt(target="fixture.test", engines="ddg", max_dorks=1, delay=0)
        self.assertEqual(seen, ["fixture.test"])


class TestMcpParallelism(unittest.IsolatedAsyncioTestCase):
    async def test_two_calls_can_start_in_the_same_session(self):
        from server import mcp
        tool = await mcp.get_tool("http_probe_target")
        started = 0
        both = asyncio.Event()

        async def probe(target: str) -> str:
            nonlocal started
            started += 1
            if started == 2:
                both.set()
            await asyncio.wait_for(both.wait(), timeout=0.5)
            return json.dumps({"target": target})

        async with Client(mcp) as client:
            await client.call_tool("engagement_gate", {"action": "init", "target": "fixture.test"})
            await client.call_tool("engagement_gate", {"action": "authorize", "confirmation": "yes"})
            with patch.object(tool, "fn", probe):
                results = await asyncio.gather(*[
                    client.call_tool("http_probe_target", {"target": "https://fixture.test"}, raise_on_error=False)
                    for _ in range(2)
                ])
            self.assertFalse(any(result.is_error for result in results))
            self.assertEqual(started, 2)


class TestEvidenceScoring(unittest.TestCase):
    def proof(self, **extra):
        return {"type": "lfi", "baseline_signal": False, "control_signal": False,
                "probe_signals": [True, True], "statuses": [200, 200, 200, 200],
                "baseline_hash": "a" * 64, "control_hash": "a" * 64,
                "probe_hashes": ["b" * 64, "b" * 64], "signal": "file_content", **extra}

    def test_invalid_or_uncontrolled_proof_stays_below_threshold(self):
        from cyber_tools.vuln_validate import vuln_validate
        for changes in ({"control_signal": True}, {"baseline_signal": True},
                        {"probe_signals": [True, False]}, {"type": "ssrf"},
                        {"statuses": [200, 200, 403, 403]}, {"control_hash": "c" * 64},
                        {"probe_hashes": ["a" * 64, "a" * 64]}):
            with self.subTest(changes=changes):
                result = json.loads(vuln_validate(json.dumps({"type": "lfi", "evidence": "marker",
                                      "verification": self.proof(**changes), "reproducible": True})))
                self.assertLess(result["confidence"], 60)

    def test_html_reflection_is_not_browser_execution_proof(self):
        from cyber_tools.vuln_validate import vuln_validate
        proof = self.proof(type="xss", signal="html_reflection")
        result = json.loads(vuln_validate(json.dumps({"type": "xss", "verification": proof,
                                                      "evidence": "reflected", "reproducible": True})))
        self.assertLess(result["confidence"], 60)

    def test_repeated_controlled_verification_can_reach_threshold(self):
        from cyber_tools.vuln_validate import vuln_validate
        proof = {"type": "lfi", "baseline_signal": False, "control_signal": False,
                 "probe_signals": [True, True], "statuses": [200, 200, 200, 200],
                 "baseline_hash": "a" * 64, "control_hash": "a" * 64,
                 "probe_hashes": ["b" * 64, "b" * 64], "signal": "file_content"}
        result = json.loads(vuln_validate(json.dumps({"type": "lfi", "evidence": "controlled fixture",
                                                      "verification": proof, "reproducible": True})))
        self.assertGreaterEqual(result["confidence"], 60)

    def test_raw_response_markers_do_not_get_promoted_to_verified_proof(self):
        from cyber_tools.vuln_validate import vuln_validate
        result = json.loads(vuln_validate(json.dumps({"type": "lfi", "evidence": "root:x:0:0 /etc/passwd " * 10,
                                                      "reproducible": True})))
        self.assertLess(result["confidence"], 60)

    def test_approved_auto_flow_with_controlled_proof_can_reach_existing_phase(self):
        from cyber_tools.auto_exploit import auto_exploit
        from cyber_tools.approval_artifact import approval_artifact
        request = json.loads(approval_artifact("request", tool_name="auto_exploit", target="https://fixture.test/"))
        approval_artifact("approve", artifact_id=request["artifact_id"], approver="offline-fixture")
        with patch("cyber_tools.auto_exploit._verify", return_value=(True, json.dumps(self.proof()))), patch(
            "cyber_tools.auto_exploit._exploit", return_value={"success": True, "evidence_ok": True, "evidence": "mock-only"}
        ) as exploit:
            result = json.loads(auto_exploit("https://fixture.test/", "lfi", approval_id=request["artifact_id"]))
        exploit.assert_called_once()
        self.assertTrue(result["exploited"])

    def test_verifier_collects_controls_and_two_probes(self):
        from cyber_tools.auto_exploit import _verify
        safe = {"status": 200, "body": "normal page", "headers": {}, "url": "https://fixture.test/"}
        hit = {**safe, "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh"}
        with patch("cyber_tools.auto_exploit._fetch", side_effect=[safe, safe, hit, hit], create=True) as fetch:
            verified, evidence = _verify("https://fixture.test/?tenant=qa", "lfi", "file")
        self.assertTrue(verified)
        self.assertEqual(fetch.call_count, 4)
        proof = json.loads(evidence)
        self.assertEqual(proof["probe_signals"], [True, True])
        self.assertNotIn("root:x", evidence)

    def test_static_content_cannot_pass_controlled_verification(self):
        from cyber_tools.auto_exploit import _verify
        static = {"status": 200, "body": "root:x:0:0:root:/root:/bin/bash", "headers": {}, "url": "https://fixture.test/"}
        with patch("cyber_tools.auto_exploit._fetch", return_value=static, create=True):
            verified, _ = _verify("https://fixture.test/", "lfi", "file")
        self.assertFalse(verified)


if __name__ == "__main__":
    unittest.main()
