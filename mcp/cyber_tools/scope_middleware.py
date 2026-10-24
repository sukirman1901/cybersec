"""Fail-closed MCP dispatch policy, not a redirect/subprocess network sandbox."""
import asyncio
import re
from weakref import WeakKeyDictionary

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from .engagement_gate import engagement_context, new_engagement, validate_target


# Explicit offline/metadata tools: a 'target' label in a report is not network I/O.
OFFLINE_TOOLS = frozenset("""
engagement_gate approval_artifact tool_health generate_report jwt_analyze
hash_analyze hash_detect gf_patterns attack_surface_map findings_manager
vuln_validate pentest_workflow continuous_monitor vuln_diff report_export
risk_score scan_template executive_summary compliance_map http_logger
branded_report vuln_database custom_wordlist report_schema_v2 session_verification
http_ingest evidence_manifest cleanup_tracking webshell_gen dork_gen
binary_checksec ipa_analyze ios_data_storage ios_signing
desktop_strings desktop_electron desktop_config desktop_packages desktop_entitlements
secret_scanner sast_review bandit_scan semgrep_scan stego_detect
""".split())

# Read-only public intelligence lookups do not scan a supplied target.
INTELLIGENCE_TOOLS = frozenset({"cve_search", "epss_lookup", "exploit_db_search",
                               "exploit_db_detail", "searchsploit"})

TARGET_KEYS = ("target", "target_url", "shell_url", "domain", "dc_ip", "url",
               "login_url", "upload_url", "endpoint", "poll_url", "callback_server",
               "oob_domain", "webhook_url", "jira_url")


def check_dispatch(name, arguments):
    """Validate all explicit destinations; reject opaque/unbounded destinations."""
    if name in OFFLINE_TOOLS or name in INTELLIGENCE_TOOLS:
        return
    if name == "raw_replay" and arguments.get("action") in ("preview", "template"):
        return
    if name == "oast_callback_server" and arguments.get("action") in ("generate", "status", "clear"):
        return
    targets = [arguments[k] for k in TARGET_KEYS if arguments.get(k)]
    for key in ("targets", "urls"):
        value = arguments.get(key, "")
        if value:
            targets.extend(re.split(r"[,\s]+", value.strip()))
    # Discovery/proxy inputs need per-destination enforcement before enabling.
    if name in ("dork_and_scan", "dork_hunt"):
        raise ToolError("Scope policy: discovered-target scanning is not scope-enforced; use individual scoped tools")
    if arguments.get("targets_file") or (name == "cloud_audit" and arguments.get("company")):
        raise ToolError("Scope policy: opaque/generated target lists are not supported by this dispatch gate")
    if name == "raw_replay" and arguments.get("raw_request"):
        from .raw_replay import _parse_host
        host = _parse_host(arguments["raw_request"])
        if not host:
            raise ToolError("Scope policy: raw request requires a valid Host header")
        targets.append(host)
    if not targets:
        raise ToolError("Scope policy: no explicit verifiable destination; use a bounded target-specific tool")
    for target in targets:
        result = validate_target(target)
        if not result["validated"]:
            raise ToolError("Scope policy denied: " + "; ".join(result["checks"]["violations"]))


class EngagementMiddleware(Middleware):
    """State is bound to the transport session and released with that session."""
    def __init__(self):
        self._sessions = WeakKeyDictionary()

    async def on_call_tool(self, context, call_next):
        try:
            session = context.fastmcp_context.session
        except (AttributeError, RuntimeError):
            # Direct server calls cannot inherit an authorized transport session.
            state, lock = new_engagement(), asyncio.Lock()
        else:
            if session not in self._sessions:
                self._sessions[session] = (new_engagement(), asyncio.Lock())
            state, lock = self._sessions[session]
        # Serialize mutations and calls so init cannot race with authorization.
        async with lock:
            with engagement_context(state):
                check_dispatch(context.message.name, context.message.arguments or {})
                return await call_next(context)
