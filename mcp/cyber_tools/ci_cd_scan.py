import httpx
import re
import asyncio
import time
from urllib.parse import urlsplit

GITHUB_ACTIONS_MISCONFIG = [
    ("pull_request_target", "branches: \\*", "critical", "PR target with wildcard — branch injection possible"),
    ("GITHUB_TOKEN", "write|contents: write|issues: write", "high", "Excessive token permissions"),
    ("pull_request", "ACTIONS_ALLOW_INSECURE", "high", "Insecure action execution"),
    ("env:", "secret|api_key|password", "critical", "Secrets in env block"),
]

GITLAB_CI_MISCONFIG = [
    ("script:", "curl|wget.*\\|\\s*bash", "high", "Piped curl to bash — supply chain risk"),
    ("env:", "CI_JOB_TOKEN|api_key|password", "critical", "Secrets in CI env"),
]

PATHS = [
    "/.github/workflows/",
    "/.github/workflows/main.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/.circleci/config.yml",
    "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml",
    "/Dockerfile",
    "/docker-compose.yml",
]

SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'sk-[a-zA-Z0-9]{20,}',
    r'xox[baprs]-[0-9a-zA-Z-]{10,}',
    r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
]


async def ci_cd_scan(target: str) -> dict:
    """Observe at most 12 paths/30 seconds; 256 KiB per body, 1 MiB total.

    Content patterns are candidates, not verified secrets or exploitability.
    Response bodies and matched values are never returned.
    """
    try:
        if not isinstance(target,str) or len(target)>8192:
            raise ValueError('Invalid target')
        parsed=urlsplit(target)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid target')
        parsed.port
    except (ValueError,TypeError):
        return {'error':'HTTP(S) target without credentials/query/fragment required','findings':[],'count':0,'coverage_complete':False}
    findings, requests = [], []
    base=target.rstrip('/')
    deadline=time.monotonic()+30
    total=0
    complete=True
    async with httpx.AsyncClient(timeout=10.0,verify=True,follow_redirects=False) as client:
        for path in ['']+PATHS[:11]:
            record={'path':path or '/','outcome':'pending'}
            requests.append(record)
            remaining=deadline-time.monotonic()
            if remaining<=0:
                record['outcome']='time_budget_exhausted'
                complete=False
                break
            try:
                async with asyncio.timeout(min(10,remaining)):
                    async with client.stream('GET',base+path) as response:
                        record['status']=response.status_code
                        if response.status_code==429:
                            record['outcome']='rate_limited'
                            complete=False
                            break
                        if response.status_code!=200:
                            record['outcome']='not_found' if response.status_code in (404,410) else 'not_assessed'
                            if response.status_code not in (404,410):
                                complete=False
                            continue
                        if response.headers.get('content-encoding','identity').lower() not in ('','identity'):
                            record['outcome']='encoded_content_not_assessed'
                            complete=False
                            continue
                        body=bytearray()
                        # Read raw bounded chunks; automatic decompression could
                        # allocate an unbounded decoded chunk before our check.
                        async for chunk in response.aiter_raw(chunk_size=8192):
                            total+=len(chunk)
                            if len(body)+len(chunk)>262144 or total>1048576:
                                raise ValueError('Response budget exceeded')
                            body.extend(chunk)
                content=body.decode('utf-8',errors='replace')
                if not path:
                    record['outcome']='root_observed'
                    continue
                if re.search(r'<(?:!doctype\s+html|html|body)\b',content,re.I):
                    record['outcome']='html_not_configuration'
                    complete=False
                    continue
                markers = (r'(?m)^\s*(?:name|on|jobs)\s*:' if '/.github/' in path else
                           r'(?m)^\s*(?:stages|script|image|services|version|steps|trigger|pipelines)\s*:')
                if path=='/Dockerfile':
                    markers=r'(?mi)^\s*FROM\s+\S+'
                elif path=='/Jenkinsfile':
                    markers=r'\b(?:pipeline|node)\s*\{'
                if not re.search(markers,content):
                    record['outcome']='unrecognized_content'
                    complete=False
                    continue
                record['outcome']='configuration_candidate'
                issues=[]
                for index,pattern in enumerate(SECRET_PATTERNS):
                    if re.search(pattern,content):
                        issues.append({'secret_type':f'pattern_{index+1}','match':'[REDACTED]','severity':'critical','status':'candidate'})
                signatures=GITHUB_ACTIONS_MISCONFIG if '/.github/' in path else GITLAB_CI_MISCONFIG if 'gitlab' in path else []
                for name,trigger,severity,note in signatures:
                    if name in content and re.search(trigger,content,re.I):
                        issues.append({'finding':note,'severity':severity,'status':'candidate'})
                if issues:
                    findings.append({'path':path,'issues':issues[:10],'status':'candidate'})
                else:
                    findings.append({'path':path,'status':'candidate','severity':'info','note':'Configuration-like content observed; validity and security not established'})
            except (httpx.HTTPError,TimeoutError):
                record['outcome']='request_failed'
                complete=False
                if not path:
                    break
            except ValueError:
                record['outcome']='response_budget_exhausted'
                complete=False
                break
    return {'target':target,'findings':findings,'count':len(findings),'requests':requests,
            'coverage_complete':complete,'confidence':'LOW',
            'limitations':'Bounded path/content inspection only; no secret validity, exploitation, or absence-of-vulnerabilities determination'}
