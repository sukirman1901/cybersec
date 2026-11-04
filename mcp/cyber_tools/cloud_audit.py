"""Bounded cloud HTTP observations; credential-dependent audits are explicit gaps."""
import json
import re
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from .http_guard import NoRedirectHandler


def guarded_urlopen(request, timeout=10, context=None):
    """Do not follow redirects: each budgeted attempt issues one HTTP request."""
    handlers = []
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(NoRedirectHandler, *handlers).open(request, timeout=timeout)


class _ObservationBudget:
    """Per-call cooperative budget, never shared between audit invocations."""
    def __init__(self):
        self.deadline = time.monotonic() + 30
        self.requests = 0
        self.skipped = 0
        self.outcome = 'not_started'

    def remaining(self):
        return max(0.0, min(8.0, self.deadline - time.monotonic()))

    def start(self):
        timeout = self.remaining()
        if self.requests >= 40 or timeout <= 0:
            self.skipped += 1
            self.outcome = 'skipped_budget'
            return 0.0
        self.requests += 1
        self.outcome = 'request_failed'
        return timeout


def cloud_audit(provider: str = "aws", targets: str = "", company: str = "", buckets: str = "", project: str = "") -> str:
    result = {'audits': [], 'summary': {s: 0 for s in ('critical', 'high', 'medium', 'low', 'info')},
              'total_findings': 0, 'coverage_complete': False}
    if provider not in ('aws', 'azure', 'gcp') or any(not isinstance(v, str) or len(v) > 8192 for v in (targets, company, buckets, project)):
        return json.dumps(dict(result, error='Invalid audit input'))
    target_list = [t.strip() for t in targets.split(',') if t.strip()]
    bucket_list = [b.strip() for b in buckets.split(',') if b.strip()]
    if len(target_list) > 20 or len(bucket_list) > 20:
        return json.dumps(dict(result, error='At most 20 targets and buckets per audit'))
    if any(_base(t) is None for t in target_list) or any(not _bucket(b) for b in bucket_list) or (company and not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', company)):
        return json.dumps(dict(result, error='Invalid target, bucket or company identifier'))
    result['provider'] = provider
    budget = _ObservationBudget()
    if company and provider == 'aws':
        result['audits'].append({'audit': 'cloud_enum', 'result': _cloud_enum(company, budget)})
    for bucket in bucket_list:
        result['audits'].append({'audit': 's3_public', 'bucket': bucket, 'result': _s3_check(bucket, budget)})
    for target in target_list:
        result['audits'].append({'audit': 'k8s', 'target': target, 'result': _k8s_check(target, budget)})
        result['audits'].append({'audit': 'docker', 'target': target, 'result': _docker_check(target, budget)})
    result['audits'].extend([{'audit': 'iam_audit', 'result': _iam_check(provider)},
                             {'audit': 'infra_audit', 'result': _infra_check(provider)}])
    for audit in result['audits']:
        for finding in audit['result'].get('findings', []):
            result['summary'][finding['severity']] += 1
            result['total_findings'] += 1
    result['overall'] = 'Cloud audit incomplete; findings reflect only validated HTTP observations'
    result['budget'] = {'request_limit': 40, 'seconds': 30, 'requests': budget.requests, 'skipped': budget.skipped,
                        'limitation': 'Cooperative deadline with remaining-time I/O timeouts; synchronous blocking I/O is not a hard interrupt'}
    return json.dumps(result, indent=2)


def _base(target):
    try:
        value = target if '://' in target else 'https://' + target
        parsed = urlsplit(value)
        if len(target) > 2048 or parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            return None
        parsed.port
        return value.rstrip('/')
    except (TypeError, ValueError):
        return None


def _bucket(name):
    return isinstance(name, str) and bool(re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', name))


def _read(url, method='GET', budget=None):
    budget = budget if budget is not None else _ObservationBudget()
    timeout = budget.start()
    if timeout <= 0:
        return None, None
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Cybersec-CloudAudit/1.0'}, method=method)
        with guarded_urlopen(req, timeout=timeout) as response:
            remaining = budget.remaining()
            if remaining <= 0:
                budget.outcome = 'deadline_exceeded'
                return None, None
            # urllib HTTPResponse has no public timeout setter. Clamp the owned
            # socket when available; synthetic/in-memory responses need none.
            sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(remaining)
            body = response.read(65537)
            if budget.remaining() <= 0:
                budget.outcome = 'deadline_exceeded'
                return None, None
            budget.outcome = 'response' if len(body) <= 65536 else 'body_limit'
            return response.status, body if len(body) <= 65536 else None
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if budget.remaining() <= 0:
            budget.outcome = 'deadline_exceeded'
            return None, None
        budget.outcome = 'response'
        return code, None
    except Exception:
        return None, None


def _cloud_enum(company, budget=None):
    budget = budget if budget is not None else _ObservationBudget()
    if not isinstance(company, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', company):
        return {'findings': [], 'total': 0, 'coverage_complete': False, 'error': 'Invalid company'}
    observations = []
    for suffix in ['', '-dev', '-prod', '-staging', '-test', '-backup', '-qa']:
        for tld in ['.s3.amazonaws.com', '.storage.googleapis.com', '.blob.core.windows.net']:
            url = f'https://{company}{suffix}{tld}'
            status, _ = _read(url, 'HEAD', budget)
            observations.append({'url': url, 'status': status, 'outcome': budget.outcome})
    return {'company': company, 'findings': [], 'total': 0, 'observations': observations, 'coverage_complete': False,
            'coverage': 'HEAD candidates only; status does not confirm resource existence or public data'}


def _s3_check(bucket_name, budget=None):
    budget = budget if budget is not None else _ObservationBudget()
    findings, observations = [], []
    if not _bucket(bucket_name):
        return {'findings': [], 'coverage_complete': False, 'error': 'Invalid bucket'}
    for region in ['us-east-1', 'eu-west-1', 'ap-southeast-1']:
        status, body = _read(f'https://{bucket_name}.s3.{region}.amazonaws.com/', budget=budget)
        matched = False
        if status == 200 and body is not None and b'<!DOCTYPE' not in body.upper():
            try:
                root = ET.fromstring(body)
                matched = root.tag.rsplit('}', 1)[-1] == 'ListBucketResult' and any(
                    child.tag.rsplit('}', 1)[-1] == 'Name' and child.text == bucket_name for child in root)
            except ET.ParseError:
                pass
        observations.append({'region': region, 'status': status, 'matched': matched, 'outcome': budget.outcome})
        if matched:
            findings.append({'type': 's3_public_listing', 'bucket': bucket_name, 'region': region, 'severity': 'high', 'evidence': 'Matching bucket listing XML; object access not tested',
                             'confidence': 'MEDIUM', 'coverage': 'HTTP listing structure candidate only; object access and ownership unverified'})
    return {'bucket': bucket_name, 'regions_checked': sum(o['outcome'] != 'skipped_budget' for o in observations), 'findings': findings, 'observations': observations,
            'is_public': bool(findings), 'coverage_complete': all(o['matched'] or o['status'] == 404 for o in observations)}


def _k8s_check(target, budget=None):
    budget = budget if budget is not None else _ObservationBudget()
    findings, observations = [], []
    base = _base(target)
    if base is None:
        return {'findings': [], 'coverage_complete': False, 'error': 'Invalid target'}
    for path, kind, field in [('/api/v1', 'APIResourceList', 'resources'),
                              ('/api/v1/namespaces/kube-system/secrets', 'SecretList', 'items')]:
        status, body = _read(base + path, budget=budget)
        try:
            data = json.loads(body) if body is not None else None
        except (ValueError, UnicodeError, RecursionError):
            data = None
        matched = status == 200 and isinstance(data, dict) and data.get('kind') == kind and isinstance(data.get(field), list)
        observations.append({'endpoint': path, 'status': status, 'matched': matched, 'outcome': budget.outcome})
        if matched:
            findings.append({'type': 'k8s_discovery_accessible' if field == 'resources' else 'k8s_secret_list_accessible',
                             'severity': 'info' if field == 'resources' or not data[field] else 'critical',
                             'confidence': 'MEDIUM', 'coverage': 'HTTP structure candidate for this endpoint only; broader permissions and exploitation untested',
                             'evidence': 'Expected Kubernetes response structure without authentication; no broader permissions inferred'})
    return {'target': target, 'findings': findings, 'observations': observations,
            'coverage_complete': all(o['matched'] or o['status'] == 404 for o in observations)}


def _docker_check(target, budget=None):
    budget = budget if budget is not None else _ObservationBudget()
    findings, observations = [], []
    base = _base(target)
    if base is None:
        return {'findings': [], 'coverage_complete': False, 'error': 'Invalid target'}
    host = urlsplit(base).hostname
    if ':' in host:
        host = '[' + host + ']'
    for addr in (f'http://{host}:2375', f'https://{host}:2376'):
        status, body = _read(addr + '/containers/json', budget=budget)
        try:
            data = json.loads(body) if body is not None else None
        except (ValueError, UnicodeError, RecursionError):
            data = None
        # An empty array or generic JSON alone cannot fingerprint a Docker API.
        matched = status == 200 and isinstance(data, list) and bool(data) and all(
            isinstance(item, dict) and isinstance(item.get('Id'), str) and bool(re.fullmatch(r'[0-9a-f]{64}', item['Id']))
            and isinstance(item.get('Image'), str) and isinstance(item.get('Names'), list) for item in data)
        observations.append({'address': addr, 'status': status, 'matched': matched, 'outcome': budget.outcome})
        if matched:
            findings.append({'type': 'docker_container_inventory_accessible', 'address': addr, 'severity': 'high',
                             'confidence': 'MEDIUM', 'coverage': 'HTTP inventory structure candidate only; write and execution permissions untested',
                             'evidence': 'Docker container inventory structure matched; no execution or write access tested'})
    return {'target': target, 'findings': findings, 'observations': observations,
            'coverage_complete': all(o['matched'] or o['status'] == 404 for o in observations)}


def _iam_check(provider):
    return {'provider': provider, 'findings': [], 'coverage_complete': False, 'coverage': 'skipped: credentials required for IAM audit'}


def _infra_check(provider):
    return {'provider': provider, 'findings': [], 'coverage_complete': False, 'coverage': 'skipped: credentials required for infrastructure audit'}
