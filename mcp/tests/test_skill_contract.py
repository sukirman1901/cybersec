"""Offline prose/schema regression evidence, NOT measured model behavior.

Fixtures are adversarial requests whose required boundaries must remain discoverable
in the relevant package. No model, target, credentials or network is used.
"""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILLS = {p.parent.name: p.read_text() for p in (ROOT / "skills").glob("*/SKILL.md")}


class TestSkillContracts(unittest.TestCase):
    def test_inventory(self):
        self.assertEqual(len(SKILLS), 24)
        for name, text in SKILLS.items():
            self.assertIn("name: " + name, text)

    def test_no_execute_all_or_automatic_escalation(self):
        forbidden = ["execute all steps immediately", "transitions to the next automatically",
                     "ALWAYS auto-detect and test captcha bypass", "there is no scope-extension action",
                     "skills override default system", "user instructions always take precedence"]
        for name, text in SKILLS.items():
            for phrase in forbidden:
                with self.subTest(skill=name, phrase=phrase):
                    self.assertNotIn(phrase.lower(), text.lower())

    def test_no_nonexistent_reporting_or_wrong_resource_calls(self):
        for name, text in SKILLS.items():
            with self.subTest(skill=name):
                self.assertNotRegex(text, r"`report`")
                self.assertNotIn("oast_callback_server(target)", text)
                self.assertNotIn("cloud_iam_audit(target)", text)
                self.assertNotIn("cloud_infra(target)", text)

    def test_concrete_request_fixtures(self):
        fixtures = [
            ("cybersec-password", "Identify this hash only", ["hash-only", "stop", "offline"]),
            ("cybersec-scanning", "TLS-only assessment", ["TLS-only", "ssl_check", "no port"]),
            ("cybersec-code-audit", "Review supplied source only", ["source-only", "no remote", "path"]),
            ("cybersec-cloud", "A discovered bucket is not authorized", ["extend", "confirmation", "provider", "user-approved"]),
            ("cybersec-osint", "Dork results only", ["probe=False", "validate=False", "discovery is not authorization"]),
            ("cybersec-ctf", "SQLi challenge", ["sqli_detect", "sqlmap_check"]),
            ("cybersec-ctf", "XSS challenge", ["xss_detect", "xsstrike_check", "reflection"]),
            ("cybersec-vulns", "EPSS for this CVE", ["epss_lookup", "cves="]),
            ("cybersec-review", "All probes got 403 or timed out", ["403", "timeout", "inconclusive"]),
            ("cybersec-ctem", "Score says confirmed", ["claims", "not execution", "not_reproduced"]),
            ("cybersec-verification", "Reflected marker and missing scanner", ["reflection", "JavaScript", "cli_missing", "verified-fixed"]),
            ("cybersec-report", "Fix recommendation without source", ["templates", "not verified patches", "source", "retest"]),
            ("using-cybersec", "Return a test plan only", ["return plans", "not execution", "capability", "redact", "extend"]),
        ]
        for skill, request, terms in fixtures:
            for term in terms:
                with self.subTest(skill=skill, request=request, term=term):
                    self.assertIn(term.lower(), SKILLS[skill].lower())

    def test_named_example_signatures(self):
        # Literal examples only, not pseudo-code placeholders or tool inventory.
        tree = ast.parse((ROOT / "mcp" / "server.py").read_text())
        signatures = {node.name: node.args for node in ast.walk(tree)
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        examples = [
            ('cybersec-web', 'oast_callback_server(action="generate")'),
            ('cybersec-cloud', 'cloud_iam_audit(provider="aws")'),
            ('cybersec-cloud', 'cloud_infra(provider="aws")'),
            ('cybersec-vulns', 'epss_lookup(cves=["CVE-2026-109618"])'),
            ('cybersec-report', 'generate_report(target=target, findings=findings_json, format="markdown")'),
            ('cybersec-cloud', 'cloud_audit(provider="aws", buckets=bucket_names)'),
        ]
        for skill, example in examples:
            with self.subTest(example=example):
                self.assertIn(example, SKILLS[skill])
                call = ast.parse(example, mode="eval").body
                args = signatures[call.func.id]
                allowed = {a.arg for a in args.args + args.kwonlyargs}
                self.assertLessEqual({k.arg for k in call.keywords}, allowed)
                required = [a.arg for a in args.args[:len(args.args) - len(args.defaults)]]
                self.assertLessEqual(set(required), {k.arg for k in call.keywords})

    def test_methodology_body_does_not_undo_boundaries(self):
        forbidden = {
            "cybersec-osint": ['probe=True, validate=True', 'dork_and_scan(category="vuln_sites")', 'If scanning not yet done'],
            "cybersec-web": ['action="all"', 'Auto-run', 'note captcha is effective'],
            "cybersec-review": ['403. False positive', 'Verified: Ran again with -validate'],
            "cybersec-ctem": ['vuln_validate` to confirm exploitability', 'Filter out false positives (vuln_validate'],
            "cybersec-exploit": ['If file upload or RCE found, deploy', 'auto_exploit(target)'],
            "cybersec-code-audit": ['Run `ci_cd_scan`', 'Check Python pickle deserialization: `pickle_deserialize(target)`'],
            "cybersec-vulns": ['Otherwise load `cybersec-exploit` skill directly'],
        }
        for skill, phrases in forbidden.items():
            for phrase in phrases:
                with self.subTest(skill=skill, phrase=phrase):
                    self.assertNotIn(phrase, SKILLS[skill])

    def test_primary_agent_generation_and_conditional_pipeline(self):
        for directory in ("agents", ".opencode/agents"):
            text = (ROOT / directory / "pentester.md").read_text()
            with self.subTest(directory=directory):
                self.assertNotIn("180+", text)
                self.assertNotIn("22 methodology", text)
                self.assertNotIn("pipeline (always)", text)
                self.assertIn("plans", text)
                self.assertIn("extend", text)

    def test_code_only_poc_section_is_offline_not_active_tool_generation(self):
        text = SKILLS["cybersec-exploit"]
        body = text.split("3. **Generate PoC**", 1)[1].split("4. **Web Shell Deployment**", 1)[0]
        self.assertNotRegex(body, r"(?:sqli_exploit|xss_exploit|webshell_gen)\(")
        for term in ("offline", "do not call", "sqli_exploit", "xss_exploit",
                     "do not execute", "local", "synthetic"):
            with self.subTest(term=term):
                self.assertIn(term, body.lower())

    def test_active_exploit_section_requires_explicit_non_auto_selection(self):
        text = SKILLS["cybersec-exploit"]
        body = text.split("5. **Execute**", 1)[1].split("7. **Document Results**", 1)[0]
        for term in ("explicitly approved", "request", "budget", "sqli_exploit",
                     "xss_exploit", 'technique="auto"', 'xss_type="auto"',
                     "never", "stacked", "destructive", "approval_artifact"):
            with self.subTest(term=term):
                self.assertIn(term, body.lower())

    def test_people_osint_flow_and_output_do_not_prescribe_a_dossier(self):
        text = SKILLS["cybersec-people-osint"]
        # Check the actual routing/output body, excluding the safety prefix.
        flow = text.split("### Investigation Flow", 1)[1].split("### Tools Available", 1)[0]
        output = text.split("### Output", 1)[1].split("### Next Skill", 1)[0]
        self.assertNotIn("↓", flow)
        self.assertNotIn("Identity profile:", flow + output)
        self.assertNotIn("email breach history", output)
        for term in ("optional", "phone", "telegram", "social", "email", "only"):
            with self.subTest(flow_term=term):
                self.assertIn(term, flow.lower())
        for term in ("minimum requested", "retrieved", "candidate matches",
                     "unvisited", "not breach retrieval", "source", "no dossier"):
            with self.subTest(output_term=term):
                self.assertIn(term, output.lower())

    def test_preserve_php_and_feed_uncertainty(self):
        text = SKILLS["cybersec-vulns"]
        for term in ("in_kev=null", "stale_in_kev", "not proof of safety", "php2shell_scan",
                     "backports", "Composer", "identification-only", "OOM", "workers"):
            self.assertIn(term, text)

    def test_all_parseable_registered_tool_call_examples(self):
        tree = ast.parse((ROOT / "mcp" / "server.py").read_text())
        signatures = {node.name: node.args for node in ast.walk(tree)
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        checked = 0
        for skill, text in SKILLS.items():
            for example in re.findall(r"`([^`\n]+)`", text):
                try:
                    call = ast.parse(example, mode="eval").body
                except SyntaxError:
                    continue  # Pseudo-code inventory is not an executable example.
                if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                    continue
                if call.func.id not in signatures:
                    continue  # Host functions and explanatory non-tool notation.
                checked += 1
                args = signatures[call.func.id]
                allowed = {a.arg for a in args.args + args.kwonlyargs}
                supplied = {a.arg for a in args.args[:len(call.args)]}
                supplied.update(k.arg for k in call.keywords)
                required = {a.arg for a in args.args[:len(args.args) - len(args.defaults)]}
                with self.subTest(skill=skill, example=example):
                    self.assertLessEqual(len(call.args), len(args.args))
                    self.assertLessEqual({k.arg for k in call.keywords}, allowed)
                    self.assertLessEqual(required, supplied)
        self.assertGreater(checked, 200)  # Guard accidental zero-coverage extraction.


def _boundary_test(name):
    def test(self):
        text = SKILLS[name].lower()
        for term in ("relevant", "init", "authorize", "extend", "user-approved", "redact", "coverage"):
            self.assertIn(term, text)
    return test


for _name in SKILLS:
    setattr(TestSkillContracts, "test_boundaries_" + _name.replace("-", "_"), _boundary_test(_name))


if __name__ == "__main__":
    unittest.main()
