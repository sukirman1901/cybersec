"""Offline contract checks against all published MCP tool signatures (no dispatch)."""
import ast
import copy
import json
from pathlib import Path
import re
import sys
import unittest

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
    def test_all_209_tools_and_144_steps_have_valid_argument_contracts(self):
        contracts = tool_contracts()
        self.assertEqual(len(contracts), 209)
        self.assertEqual((len(WORKFLOW_TEMPLATES), len(TEMPLATES)), (8, 10))
        self.assertEqual(sum(len(t["steps"]) for t in WORKFLOW_TEMPLATES.values()), 78)
        self.assertEqual(sum(len(t["steps"]) for t in TEMPLATES.values()), 66)
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


if __name__ == "__main__":
    unittest.main()
