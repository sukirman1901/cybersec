"""Bounded opt-in execution of supported plan steps with per-call scope checks."""
import asyncio
import json
import time

from .scope_middleware import check_dispatch, require_authorized_engagement
from .finding_contract import extract_findings_list, normalize_finding
from .sqli_detect import sqli_detect
from .xss_detect import xss_detect
from .vuln_scanner import scan_vulnerabilities
from .param_discovery import discover_params
from .http_probe import http_probe
from .tech_detect import detect_technologies
from .cors_check import cors_check
from .nuclei_scan import nuclei_scan
from .lfi_detect import lfi_detect

EXECUTORS = {
    'sqli_detect': sqli_detect, 'xss_detect': xss_detect,
    'vuln_scan': scan_vulnerabilities, 'param_discovery': discover_params,
    'http_probe_target': http_probe, 'tech_detect': detect_technologies,
    'cors_check': cors_check, 'nuclei_scan': nuclei_scan, 'lfi_detect': lfi_detect,
}


async def execute_plan(plan, request_json=''):
    """No implicit authorization, condition evaluation, ticket creation or exploitation."""
    require_authorized_engagement()
    if not isinstance(plan, dict) or not isinstance(plan.get('steps'), list):
        return {'error': 'Invalid plan', 'executed': False}
    if len(plan['steps']) > 30:
        return {'error': 'At most 30 steps per execution', 'executed': False}
    # Preflight all supported explicit destinations before any traffic.
    for step in plan['steps']:
        if step.get('tool') in EXECUTORS:
            check_dispatch(step['tool'], step.get('params', {}))
    result = {'status': 'completed', 'executed': True, 'steps': [], 'findings': [],
              'coverage_complete': True, 'coverage': 'supported explicit plan steps; inspect skipped steps'}
    deadline = time.monotonic() + 180
    for step in plan['steps']:
        name = step.get('tool')
        args = dict(step.get('params', {}))
        entry = {'tool': name, 'status': 'not_executed'}
        result['steps'].append(entry)
        if name == 'engagement_gate' and args.get('action') in ('status', 'validate'):
            if args.get('target'):
                check_dispatch('vuln_scan', {'target': args['target']})
            entry['status'] = 'completed'
            continue
        if name not in EXECUTORS or step.get('condition') or step.get('unresolved_inputs'):
            entry.update(status='skipped', reason='unsupported step, unresolved inputs or caller-evaluated condition')
            result['coverage_complete'] = False
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            entry.update(status='skipped', reason='workflow deadline exhausted')
            result['coverage_complete'] = False
            continue
        if request_json and name in ('sqli_detect', 'xss_detect'):
            args['request_json'] = request_json
        check_dispatch(name, args)
        try:
            payload = await asyncio.wait_for(EXECUTORS[name](**args), timeout=min(remaining, 125))
            if isinstance(payload, str):
                payload = json.loads(payload)
            incomplete = bool(payload.get('error') or payload.get('errors')) or payload.get('coverage_complete') is False
            entry.update(status='partial' if incomplete else 'completed', result=payload)
            if incomplete:
                result['coverage_complete'] = False
            for finding in extract_findings_list(payload):
                finding = dict(finding)
                finding.setdefault('target', args.get('target', ''))
                finding.setdefault('coverage', payload.get('coverage', f'{name}; coverage not quantified'))
                finding.setdefault('confidence', payload.get('confidence', 'LOW'))
                result['findings'].append(normalize_finding(finding, require_quality=True, tool=name))
        except asyncio.TimeoutError:
            entry.update(status='error', error='step deadline exceeded')
            result['coverage_complete'] = False
        except Exception as exc:
            entry.update(status='error', error=type(exc).__name__)
            result['coverage_complete'] = False
    result['status'] = 'completed' if result['coverage_complete'] else 'partial'
    result['count'] = len(result['findings'])
    result['steps_completed'] = sum(s['status'] == 'completed' for s in result['steps'])
    return result
