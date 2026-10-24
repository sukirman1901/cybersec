"""Offline contract checks against all published MCP tool signatures (no dispatch)."""
import ast
import copy
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyber_tools.pentest_workflow import WORKFLOW_TEMPLATES, pentest_workflow
from cyber_tools.scan_template import TEMPLATES, scan_template


def tool_contracts():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "server.py").read_text())
    contracts = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                   and isinstance(d.func.value, ast.Name) and d.func.value.id == "mcp"
                   and d.func.attr == "tool" for d in node.decorator_list):
            continue
        positional = node.args.posonlyargs + node.args.args
        required = positional[:len(positional) - len(node.args.defaults)]
        required += [arg for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
                     if default is None]
        contracts[node.name] = ({a.arg for a in positional + node.args.kwonlyargs},
                                {a.arg for a in required})
    return contracts


def plans():
    for templates, render in ((WORKFLOW_TEMPLATES, pentest_workflow), (TEMPLATES, scan_template)):
        for name in templates:
            yield name, json.loads(render("example.test", name))


class WorkflowContractTests(unittest.TestCase):
    def test_all_tools_and_template_steps_have_valid_argument_contracts(self):
        contracts = tool_contracts()
        self.assertEqual(len(contracts), 209)
        self.assertEqual((len(WORKFLOW_TEMPLATES), len(TEMPLATES)), (8, 10))
        for name, plan in plans():
            self.assertEqual(plan["total_steps"], len(plan["steps"]))
            self.assertGreater(len(plan["steps"]), 0)
            for index, step in enumerate(plan["steps"], 1):
                with self.subTest(template=name, step=index, tool=step["tool"]):
                    self.assertEqual(step["step"], index)
                    self.assertIn(step["tool"], contracts)
                    allowed, required = contracts[step["tool"]]
                    self.assertFalse(set(step["params"]) - allowed, step)
                    self.assertFalse(required - set(step["params"]), step)

    def test_plans_explicitly_do_not_execute_or_resolve_authorization(self):
        for name, plan in plans():
            with self.subTest(template=name):
                self.assertEqual(plan.get("status"), "plan_only")
                self.assertIs(plan.get("executed"), False)
                self.assertEqual(plan.get("authorization"), "unknown")
                prerequisites = " ".join(plan["prerequisites"])
                for text in ("init", "authorize", "same MCP session", "revokes", "approval"):
                    self.assertIn(text, prerequisites)
                self.assertIn("not evaluated", plan["note"])

    def test_every_unresolved_input_is_declared_and_blocks_step(self):
        for name, plan in plans():
            for step in plan["steps"]:
                with self.subTest(template=name, tool=step["tool"]):
                    unresolved = sorted(set(re.findall(r"\{([a-z_]+)\}", json.dumps(step["params"]))))
                    self.assertEqual(step.get("unresolved_inputs"), unresolved)
                    self.assertTrue(set(unresolved) <= set(plan["required_inputs"]))
                    self.assertEqual(step.get("status"), "requires_input" if unresolved else "not_executed")
                    for key in unresolved:
                        self.assertTrue(plan["required_inputs"][key])

    def test_no_embedded_authorization_or_scope_reset(self):
        for name, plan in plans():
            for step in plan["steps"]:
                if step["tool"] == "engagement_gate":
                    with self.subTest(template=name):
                        self.assertNotIn(step["params"]["action"], ("init", "authorize", "extend"))
                        self.assertNotIn("confirmation", step["params"])

    def test_recon_query_is_hostname_scoped(self):
        steps = json.loads(pentest_workflow("example.test", "recon-full"))["steps"]
        params = {s["tool"]: s["params"] for s in steps}
        self.assertEqual(params["crt_search"], {"domain": "example.test"})
        self.assertEqual(params["wayback_urls"], {"domain": "example.test"})
        self.assertEqual(params["shodan_lookup"], {"query": "hostname:example.test"})

    def test_tokens_and_cloud_resources_are_not_invented_from_target(self):
        for name, plan in plans():
            for step in plan["steps"]:
                tool, params = step["tool"], step["params"]
                with self.subTest(template=name, tool=tool):
                    if tool in ("jwt_analyze", "jwt_forgery"):
                        self.assertEqual(params.get("token"), "{token}")
                    if tool in ("cloud_iam_audit", "cloud_infra"):
                        self.assertEqual(params.get("provider"), "{provider}")
                    if tool == "cloud_enum":
                        self.assertEqual(params.get("company"), "{company}")
                    if tool == "s3_scanner":
                        self.assertEqual(params.get("bucket_name"), "{bucket_name}")

    def test_evidence_and_retest_inputs_are_not_fake_results(self):
        for name, plan in plans():
            for step in plan["steps"]:
                with self.subTest(template=name, tool=step["tool"]):
                    for key in ("findings_json", "finding_json"):
                        if key in step["params"]:
                            self.assertEqual(step["params"][key], "{findings}" if key == "findings_json" else "{finding}")
                            self.assertIn("evidence", " ".join(step.get("prerequisites", [])))
                    if step["tool"] == "retest_vuln":
                        self.assertEqual(step["params"]["vuln_type"], "{vuln_type}")

    def test_rendering_does_not_mutate_templates_or_engagement(self):
        from cyber_tools.engagement_gate import ENGAGEMENT
        before = copy.deepcopy((WORKFLOW_TEMPLATES, TEMPLATES, ENGAGEMENT))
        list(plans())
        self.assertEqual(before, (WORKFLOW_TEMPLATES, TEMPLATES, ENGAGEMENT))

    def test_target_is_substituted_as_data_not_json_source(self):
        target = 'example.test/"quoted"\\path'
        for render in (pentest_workflow, scan_template):
            try:
                plan = json.loads(render(target))
            except json.JSONDecodeError as error:
                self.fail(f"Target data broke JSON rendering: {error}")
            self.assertEqual(plan["steps"][0]["params"]["target"], target)

    def test_conditions_are_preserved_without_claiming_they_passed(self):
        plan = json.loads(pentest_workflow("example.test", "web-audit"))
        step = plan["steps"][2]
        self.assertEqual(step["condition"], "port_scan.open_ports.length > 0")
        self.assertEqual(step["depends_on"], "port_scan")
        self.assertEqual(step.get("status"), "not_executed")

    def test_custom_workflow_preserves_shape_and_declares_placeholders(self):
        custom = {"name": "custom", "steps": [{"tool": "jwt_analyze", "params": {"token": "{token}"}}]}
        plan = json.loads(pentest_workflow("example.test", custom_json=json.dumps(custom)))
        self.assertEqual(plan["workflow_name"], "custom")
        self.assertIn("token", plan.get("required_inputs", {}))
        self.assertEqual(plan["steps"][0]["params"], {"token": "{token}"})

    def test_invalid_template_and_invalid_json_remain_errors(self):
        self.assertIn("error", json.loads(pentest_workflow("example.test", "missing")))
        self.assertIn("error", json.loads(scan_template("example.test", "missing")))
        self.assertIn("error", json.loads(pentest_workflow("example.test", custom_json="{")))

    def test_non_object_custom_json_is_a_structured_error(self):
        for value in ([], None, True, 42, "workflow", {"steps": None}, {"steps": [False]}, {"steps": [{"params": []}]}):
            with self.subTest(value=value):
                try:
                    result = json.loads(pentest_workflow("example.test", custom_json=json.dumps(value)))
                except (AttributeError, TypeError) as error:
                    self.fail(f"Malformed custom plan must return an error, not throw: {error}")
                self.assertIn("error", result)

    def test_approval_requests_require_explicit_tool_selection(self):
        for name, plan in plans():
            for step in plan["steps"]:
                if step["tool"] == "approval_artifact":
                    with self.subTest(template=name):
                        self.assertEqual(step["params"].get("tool_name"), "{approval_tool}")
                        self.assertEqual(step["params"]["action"], "request")
                        description = plan["required_inputs"]["approval_tool"]
                        self.assertIn("explicit", description.lower())
                        self.assertIn("not blanket authorization", description)

    def test_source_audit_contains_only_local_path_tools(self):
        steps = json.loads(scan_template("/source/repository", "code-audit"))["steps"]
        self.assertEqual({s["tool"] for s in steps},
                         {"bandit_scan", "semgrep_scan", "secret_scanner", "sast_review"})
        self.assertTrue(all(s["params"] == {"path": "/source/repository"} for s in steps))

    def test_candidate_findings_preserve_uncertainty(self):
        plan = json.loads(pentest_workflow("example.test"))
        for description in (plan["required_inputs"]["findings"],
                            json.loads(pentest_workflow("example.test", "staging-deep"))["required_inputs"]["finding"]):
            self.assertIn("candidate", description)
            self.assertIn("verdict", description)
            self.assertIn("coverage", description)
            self.assertIn("uncertainty", description)
            self.assertNotIn("verified finding", description)

    def test_condition_selectors_match_real_mocked_result_shapes(self):
        # Execute the real server wrapper bodies without importing/registering MCP.
        # The actual producer implementations run against mocked transport/DNS only.
        from cyber_tools.http_probe import http_probe
        from cyber_tools.dns_enum import dns_enum
        tree = ast.parse((Path(__file__).resolve().parents[1] / "server.py").read_text())
        wrappers = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name in ("http_probe_target", "dns_lookup", "port_scan")]
        for node in wrappers:
            node.decorator_list = []
        namespace = {"json": json, "http_probe": http_probe, "dns_enum": dns_enum,
                     "scan_ports": lambda *_: [22, 443], "detect_service": lambda *_: "mock"}
        exec(compile(ast.Module(body=wrappers, type_ignores=[]), "server-wrappers", "exec"), namespace)
        response = Mock(status=200, headers={})
        response.getheader.return_value = "mock"
        connection = Mock()
        connection.getresponse.return_value = response
        with patch("cyber_tools.http_probe.http.client.HTTPConnection", return_value=connection):
            http = json.loads(namespace["http_probe_target"]("http://example.test:8080"))
        with patch("cyber_tools.dns_enum.socket.getaddrinfo", return_value=[(None, None, None, None, ("192.0.2.1", 0))]), patch("cyber_tools.dns_enum.socket.gethostbyname", return_value="192.0.2.1"):
            dns = json.loads(namespace["dns_lookup"]("example.test"))
        ports = json.loads(namespace["port_scan"]("example.test"))
        self.assertIn(200, [p["status"] for p in http["probes"]])
        self.assertEqual(dns["records"]["records"]["A"], ["192.0.2.1"])
        self.assertIn(443, [p["port"] for p in ports["open_ports"]])
        web = json.loads(pentest_workflow("example.test", "web-audit"))
        with self.subTest(selector="http"):
            self.assertEqual(web["steps"][3]["condition"], "http_probe_target.probes[*].status contains 200")
        recon = json.loads(pentest_workflow("example.test", "recon-full"))
        for step in recon["steps"][4:6]:
            with self.subTest(selector=step["tool"]):
                self.assertEqual(step["condition"], "dns_lookup.records.records.A contains a valid IPv4 address (ignore error strings)")
        network = json.loads(pentest_workflow("example.test", "network-scan"))
        for step, port in zip(network["steps"][1:3], (443, 22)):
            with self.subTest(selector=step["tool"]):
                self.assertEqual(step["condition"], f"port_scan.open_ports[*].port contains {port}")


if __name__ == "__main__":
    unittest.main()
