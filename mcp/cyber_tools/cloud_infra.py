import json
import shutil
from .cli_tools import _run_cli


async def cloud_infra(provider: str = "aws", service: str = "ec2") -> dict:
    """Bounded cloud configuration inventory; no exploit inference from logs."""
    result = {'count': 0, 'coverage_complete': False, 'audit_complete': False}
    if provider not in ('aws', 'azure') or (provider == 'aws' and service not in ('ec2', 's3')):
        return dict(result, error='Unsupported provider or service', supported_providers=['aws', 'azure'], supported_services=['ec2', 's3'])
    result.update(provider=provider, service='vm' if provider == 'azure' else service)
    if provider == 'aws' and service == 'ec2' and shutil.which('scoutsuite'):
        tool, cmd, timeout = 'scoutsuite', ['scoutsuite', 'aws', '--services', 'ec2'], 300
        key, fields = 'output', ()
    elif provider == 'aws' and shutil.which('aws'):
        tool, timeout = 'aws-cli', 60
        if service == 'ec2':
            cmd = ['aws', 'ec2', 'describe-security-groups', '--query', "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]", '--output', 'json']
            key, fields = 'open_security_groups', ('GroupId', 'GroupName')
        else:
            cmd = ['aws', 's3api', 'list-buckets', '--output', 'json']
            key, fields = 'buckets', ('Name',)
    elif provider == 'azure' and shutil.which('az'):
        tool, cmd, timeout = 'az', ['az', 'vm', 'list', '--output', 'json'], 120
        key, fields = 'virtual_machines', ('name', 'location')
    else:
        return dict(result, error='Required cloud CLI not found', execution_status='not_started')
    result['tool'] = tool
    run = await _run_cli(cmd, timeout=timeout)
    if run.get('exit_code') != 0 or run.get('error_kind') or run.get('output_truncated'):
        return dict(result, error='Cloud command incomplete', execution_status='error', exit_code=run.get('exit_code'), error_kind=run.get('error_kind'))
    if tool == 'scoutsuite':
        return dict(result, error='ScoutSuite console output is not a structured audit report', execution_status='partial', coverage='Report artifact not parsed')
    try:
        data = json.loads(run.get('stdout', ''))
        records = data.get('Buckets') if key == 'buckets' and isinstance(data, dict) else data
        if not isinstance(records, list) or any(not isinstance(r, dict) or not isinstance(r.get(fields[0]), str) for r in records):
            raise ValueError
        result[key] = [{k: r[k][:256] for k in fields if isinstance(r.get(k), str)} for r in records[:100]]
        result['count'] = len(result[key])
        complete = len(records) <= 100 and not (isinstance(data, dict) and (data.get('ContinuationToken') or data.get('NextToken') or data.get('IsTruncated')))
    except (ValueError, TypeError, RecursionError):
        return dict(result, error='Malformed or unsupported cloud output', execution_status='error')
    result['coverage_complete'] = complete
    result['execution_status'] = 'completed' if complete else 'partial'
    result['coverage'] = 'Configuration inventory only; public reachability, effective permissions and exploitation not assessed'
    if not complete:
        result['error'] = 'Cloud result incomplete or truncated'
    return result
