import json
import shutil
from .cli_tools import _run_cli


async def cloud_iam_audit(provider: str = "aws") -> dict:
    """Report bounded IAM inventory or structured Prowler failures."""
    result = {'findings': [], 'count': 0, 'coverage_complete': False, 'audit_complete': False}
    if provider not in ('aws', 'gcp'):
        return dict(result, error='Unsupported provider', supported_providers=['aws', 'gcp'])
    result['provider'] = provider
    if provider == 'aws' and shutil.which('prowler'):
        tool, cmd, timeout = 'prowler', ['prowler', 'aws', '--services', 'iam', '-M', 'json'], 300
    elif provider == 'aws' and shutil.which('aws'):
        tool, cmd, timeout = 'aws-cli', ['aws', 'iam', 'list-roles', '--output', 'json'], 60
    elif provider == 'gcp' and shutil.which('gcloud'):
        tool, cmd, timeout = 'gcloud', ['gcloud', 'iam', 'roles', 'list', '--format=json'], 60
    else:
        return dict(result, error='Required cloud CLI not found', execution_status='not_started')
    result['tool'] = tool
    run = await _run_cli(cmd, timeout=timeout)
    if run.get('exit_code') != 0 or run.get('error_kind') or run.get('output_truncated'):
        return dict(result, error='Cloud command incomplete', execution_status='error', error_kind=run.get('error_kind'), exit_code=run.get('exit_code'))
    try:
        output = run.get('stdout', '')
        if tool == 'prowler':
            try:
                records = json.loads(output)
            except ValueError:
                records = [json.loads(line) for line in output.splitlines() if line.strip()]
            if isinstance(records, dict):
                records = [records]
            if not isinstance(records, list) or not records or any(not isinstance(r, dict) or r.get('Status') not in ('PASS', 'FAIL', 'MANUAL') for r in records):
                raise ValueError
            failures = [r for r in records if r['Status'] == 'FAIL']
            # Do not echo arbitrary resource metadata, logs or credential-bearing detail fields.
            result['findings'] = [{'severity': str(r.get('Severity', 'unknown')).lower() if str(r.get('Severity', '')).lower() in ('critical', 'high', 'medium', 'low', 'info') else 'unknown',
                                   'status': 'FAIL', 'evidence': 'Prowler reported failed check; not exploit confirmation',
                                   'confidence': 'MEDIUM', 'coverage': 'External Prowler report only; underlying check and exploitability not independently verified'} for r in failures[:100]]
            result['count'] = len(result['findings'])
            result['coverage'] = 'Structured Prowler IAM checks only'
            complete = len(failures) <= 100 and all(r['Status'] != 'MANUAL' for r in records)
        else:
            data = json.loads(output)
            records = data.get('Roles') if tool == 'aws-cli' and isinstance(data, dict) else data if tool == 'gcloud' else None
            if not isinstance(records, list) or any(not isinstance(r, dict) or not isinstance(r.get('RoleName' if tool == 'aws-cli' else 'name'), str) for r in records):
                raise ValueError
            key = 'RoleName' if tool == 'aws-cli' else 'name'
            result['roles'] = [{key: r[key][:256]} for r in records[:100]]
            result['count'] = len(result['roles'])
            result['coverage'] = 'Role inventory only; policies, trust and effective permissions not assessed'
            complete = len(records) <= 100 and not (isinstance(data, dict) and (data.get('IsTruncated') or data.get('Marker') or data.get('nextPageToken')))
    except (ValueError, TypeError, RecursionError):
        return dict(result, error='Malformed or unsupported cloud output', execution_status='error')
    result['coverage_complete'] = complete
    result['execution_status'] = 'completed' if complete else 'partial'
    if not complete:
        result['error'] = 'Cloud result incomplete or truncated'
    return result
