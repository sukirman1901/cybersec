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
    "test_workflow_contract",
    "test_skill_contract",
    "test_redirect_contract",
    "test_routing_eval",
    "test_remediation_20261104",
    "test_accuracy_tuning",
    "test_web_surface_accuracy",
    "test_discovery_accuracy",
    "test_rails_accuracy",
    "test_metrics_accuracy",
    "test_framework_accuracy",
    "test_csrf_accuracy",
    "test_crlf_accuracy",
    "test_auth_surface_accuracy",
    "test_desktop_config_accuracy",
    "test_offline_crypto_accuracy",
    "test_local_utility_accuracy",
    "test_cors_accuracy",
    "test_remaining_http_accuracy",
    "test_hash_detect_accuracy",
    "test_gf_patterns_accuracy",
    "test_intel_adapter_accuracy",
    "test_report_utility_accuracy",
    "test_cli_adapter_accuracy",
    "test_cli_remaining_accuracy",
    "test_artifact_accuracy",
    "test_cli_collection_limits",
    "test_store_report_accuracy",
    "test_protocol_adapter_accuracy",
    "test_discovery_intel_accuracy",
    "test_source_artifact_accuracy",
    "test_phone_metadata_accuracy",
    "test_dork_generation_accuracy",
    "test_remaining_protocol_accuracy",
    "test_integration_adapter_accuracy",
    "test_credential_adapter_accuracy",
    "test_mobile_artifact_accuracy",
    "test_web_observation_accuracy",
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
