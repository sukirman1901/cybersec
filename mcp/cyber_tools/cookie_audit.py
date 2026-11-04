"""Inspect Set-Cookie attributes without retaining cookie values."""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie, CookieError
import httpx


async def cookie_audit(target: str) -> dict:
    result = {'target': target, 'cookies': [], 'cookie_count': 0, 'total_issues': 0,
              'coverage_complete': False, 'confidence': 'HIGH',
              'coverage': 'One anonymous GET; Set-Cookie headers only, authenticated cookies not assessed'}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(target)
    except httpx.HTTPError as exc:
        return {**result, 'error': type(exc).__name__}
    result['status_code'] = resp.status_code
    if not 200 <= resp.status_code < 300:
        return {**result, 'error': 'Non-success response; application cookies not assessed'}
    errors = []
    for header in resp.headers.get_list('set-cookie'):
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except CookieError:
            errors.append('Malformed Set-Cookie')
            continue
        if not parsed:
            errors.append('Unparsed Set-Cookie')
            continue
        for name, cookie in parsed.items():
            same_site = cookie['samesite'].lower()
            flags = {'httponly': bool(cookie['httponly']), 'secure': bool(cookie['secure']),
                     'samesite_lax': same_site == 'lax', 'samesite_strict': same_site == 'strict',
                     'samesite_none': same_site == 'none', 'path': cookie['path']}
            deleted = False
            valid_max_age = False
            if cookie['max-age']:
                flags['max_age'] = cookie['max-age']
                try:
                    deleted = int(cookie['max-age']) <= 0
                    valid_max_age = True
                except ValueError:
                    errors.append('Invalid Max-Age')
            if cookie['expires']:
                flags['expires'] = cookie['expires']
                try:
                    expires = parsedate_to_datetime(cookie['expires'])
                    if not valid_max_age:
                        deleted = expires.replace(tzinfo=expires.tzinfo or timezone.utc) <= datetime.now(timezone.utc)
                except (ValueError, TypeError, OverflowError):
                    errors.append('Invalid Expires')
            sensitive = any(word in name.lower() for word in ('session', 'token', 'auth', 'sid', 'jwt', 'login', 'api_key'))
            issues = []
            if not deleted:
                if not flags['secure']:
                    issues.append({'issue': 'Missing Secure attribute', 'severity': 'medium' if sensitive else 'low'})
                if not flags['httponly']:
                    issues.append({'issue': 'Missing HttpOnly; review whether JavaScript access is required',
                                   'severity': 'medium' if sensitive else 'info'})
                if same_site == 'none' and not flags['secure']:
                    issues.append({'issue': 'SameSite=None without Secure may be rejected by browsers', 'severity': 'low'})
                elif same_site not in ('lax', 'strict', 'none'):
                    issues.append({'issue': 'SameSite absent or invalid; browser default applies', 'severity': 'low'})
            result['cookies'].append({'name': name, 'flags': flags, 'deleted': deleted,
                                      'issues': issues, 'sensitive': sensitive, 'assessment': 'observed'})
    result.update(cookie_count=len(result['cookies']),
                  total_issues=sum(len(c['issues']) for c in result['cookies']),
                  coverage_complete=not errors)
    if errors:
        result.update(error='Some cookie attributes could not be assessed', errors=errors)
    return result
