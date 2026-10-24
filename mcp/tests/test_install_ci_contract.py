"""Core dependency isolation and explicit offline CI selection contracts."""
import runpy
import unittest
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


ROOT = Path(__file__).resolve().parents[2]


class TestInstallCiContract(unittest.TestCase):
    def test_certipy_is_not_a_core_dependency(self):
        requirements = (ROOT / "mcp/requirements.txt").read_text().splitlines()
        names = {
            canonicalize_name(Requirement(line.strip()).name)
            for line in requirements
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertNotIn("certipy-ad", names, "Install Certipy separately via pipx")

    def test_offline_runner_selects_policy_and_install_contracts(self):
        runner = runpy.run_path(str(ROOT / "scripts/run_offline_tests.py"))
        for name in ("test_tool_policy", "test_install_ci_contract"):
            with self.subTest(module=name):
                self.assertEqual(runner["MODULES"].count(name), 1)


if __name__ == "__main__":
    unittest.main()
