"""Run mock/contract regressions with outbound socket connections disabled.

Intentionally excludes loopback fixture integration tests. No new environment,
network server, scanner installation or external test target is required.
"""
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "mcp"), str(ROOT / "mcp/tests"), str(ROOT)]
MODULES = (
    "test_audit_regressions", "test_pipeline_quality", "test_detector_accuracy",
    "test_detector_benchmark", "test_sqli_mcp",
    "test_sqli_evidence", "test_sqli_or_evidence", "test_php2shell",
    "test_php2shell_remote", "test_epss_lookup", "test_epss_freshness",
    "test_vuln_diff_intel", "test_vuln_scan_epss_intel", "test_novelty_engine",
    "test_doc_tool_count", "test_runtime_info",
    "test_tool_policy", "test_install_ci_contract",
)


def deny_network(*args, **kwargs):
    raise RuntimeError("Outbound network disabled in offline regression suite")


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in MODULES)
    with patch.object(socket.socket, "connect", deny_network), patch.object(
        socket.socket, "connect_ex", deny_network
    ):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
