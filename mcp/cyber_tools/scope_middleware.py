"""Fail-closed MCP dispatch policy, not a redirect/subprocess network sandbox."""
import asyncio
import copy
import re
from weakref import WeakKeyDictionary

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from .engagement_gate import (current_engagement, engagement_context, new_engagement,
                              validate_resource, validate_target)


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
gitleaks_check jwt_forgery ios_objection ios_frida
""".split())

# Read-only public intelligence lookups do not scan a supplied target.
INTELLIGENCE_TOOLS = frozenset({"cve_search", "epss_lookup", "exploit_db_search",
                               "exploit_db_detail", "searchsploit", "exploit_db_download",
                               "dork_search", "shodan_lookup", "ghdb_search", "dork_scan"})

# These query known services by identity, not a user-supplied scanner destination.
IDENTITY_TOOLS = frozenset({"people_osint", "social_osint", "telegram_osint",
                           "phone_osint", "email_osint"})

TARGET_KEYS = ("target", "target_url", "shell_url", "domain", "dc_ip", "url",
               "login_url", "upload_url", "endpoint", "poll_url", "callback_server",
               "oob_domain", "webhook_url", "jira_url")


def require_resource(kind, value):
    if not validate_resource(kind, value):
        raise ToolError(f"Scope policy denied: include this {kind} resource in scope_json and authorize the engagement")


def require_authorized_engagement():
    state = current_engagement()
    if not state["active"] or not state["scope"]["authorized"]:
        raise ToolError("Scope policy denied: initialize and authorize the engagement once before active probing")


def check_dispatch(name, arguments):
    """Validate all explicit destinations; reject opaque/unbounded destinations."""
    if name in OFFLINE_TOOLS or name in INTELLIGENCE_TOOLS or name in IDENTITY_TOOLS:
        return
    if name == "s3_scanner":
        bucket = arguments.get("bucket_name", "")
        if not validate_target(f"https://{bucket}.s3.amazonaws.com")["validated"]:
            require_resource("buckets", bucket)
        return
    if name == "cloud_enum":
        require_resource("companies", arguments.get("company", ""))
        return
    if name in ("cloud_iam_audit", "cloud_infra"):
        # Provider authorization covers the credentials/account configured in its CLI.
        require_resource("providers", arguments.get("provider", "aws"))
        return
    if name == "github_issue":
        require_resource("repositories", arguments.get("repo", ""))
        return
    if name == "cloud_audit":
        require_resource("providers", arguments.get("provider", "aws"))
        if arguments.get("company"):
            require_resource("companies", arguments["company"])
        for bucket in arguments.get("buckets", "").split(","):
            if bucket.strip():
                require_resource("buckets", bucket.strip())
        # Other explicit targets still go through hostname/IP checks below.
        if not arguments.get("targets"):
            return
    if name == "raw_replay" and arguments.get("action") in ("preview", "template"):
        return
    if name == "oast_callback_server" and arguments.get("action") in ("generate", "status", "clear"):
        return
    if name == "dork_hunt" and arguments.get("probe", True) is False:
        return
    if name in ("dork_hunt", "dork_and_scan"):
        # Discovered destinations are checked again at each scan/probe boundary.
        require_authorized_engagement()
    targets = [arguments[k] for k in TARGET_KEYS if arguments.get(k)]
    for key in ("targets", "urls"):
        value = arguments.get(key, "")
        if value:
            targets.extend(re.split(r"[,\s]+", value.strip()))
    if arguments.get("targets_file"):
        raise ToolError("Scope policy: opaque/generated target lists are not supported by this dispatch gate")
    if name == "raw_replay" and arguments.get("raw_request"):
        from .raw_replay import _parse_host
        host = _parse_host(arguments["raw_request"])
        if not host:
            raise ToolError("Scope policy: raw request requires a valid Host header")
        targets.append(host)
    if not targets and name in ("dork_hunt", "dork_and_scan"):
        return  # Search may be global; active probes are restricted to the engagement.
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
        # Mutations are atomic; ordinary tool execution does not hold this lock.
        # In-flight calls keep their dispatch-time scope; init affects new calls.
        async with lock:
            if context.message.name == "engagement_gate":
                with engagement_context(state):
                    return await call_next(context)
            snapshot = copy.deepcopy(state)
            with engagement_context(snapshot):
                check_dispatch(context.message.name, context.message.arguments or {})
        with engagement_context(snapshot):
            return await call_next(context)
