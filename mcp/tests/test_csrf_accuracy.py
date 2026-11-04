"""Read-only CSRF indicators do not establish cross-site state changes."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools import csrf_detect as module


async def scan(body='', headers=None, status=200, offline=False):
    seen = []
    def handler(request):
        seen.append(request.method)
        if offline:
            raise httpx.ConnectError('private-value', request=request)
        return httpx.Response(status, text=body, headers=headers)
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with patch.object(module.httpx, 'AsyncClient', return_value=client):
        result = await module.csrf_detect('https://fixture.test/profile?token=private-value')
    return result, seen


class CsrfAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_default_get_comments_and_html_entities(self):
        result, _ = await scan('<!-- <form method=post></form> --><form><input name=email></form><form method=post><input value="ab&amp;cd" name=csrf_token></form>')
        self.assertEqual(len(result['forms']), 2)
        self.assertEqual(result['forms'][0]['method'], 'GET')
        self.assertEqual(result['forms'][1]['token_details']['length'], 5)
        self.assertEqual(result['candidate_forms'], [])

    async def test_cookie_expiry_comma_and_missing_value_do_not_merge(self):
        result, _ = await scan(headers=[('set-cookie','a=x; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Secure; HttpOnly; SameSite=Strict'),
                                       ('set-cookie','b=; Max-Age=0; Path=/')])
        self.assertEqual(len(result['cookie_analysis']['cookies']), 2)
        self.assertEqual(result['cookie_analysis']['cookies'][0]['flags_missing'], [])
        self.assertFalse(result['csrf_vulnerable'])

    async def test_form_budget_and_body_limit_report_partial(self):
        result, _ = await scan('<form method=post></form>' * 101)
        self.assertEqual(len(result['forms']), 100)
        self.assertEqual(result['forms_deferred'], 1)
        self.assertFalse(result['coverage_complete'])
        result, _ = await scan('x' * 262145)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['assessment'], 'inconclusive')

    async def test_public_get_and_missing_cookies_not_csrf(self):
        result, seen = await scan('<html>Welcome</html>')
        self.assertFalse(result['csrf_vulnerable'])
        self.assertEqual(result['total_findings'], 0)
        self.assertEqual(seen, ['GET'])
        self.assertEqual(result['cookie_analysis']['risk'], 'NOT_APPLICABLE')
        self.assertEqual(result['assessment'], 'not_exploit_tested')

    async def test_post_form_metadata_and_missing_token_candidate(self):
        result, _ = await scan('<form action="/change?key=private-value" method="POST"><input name="email"></form>')
        form = result['forms'][0]
        self.assertEqual(form['method'], 'POST')
        self.assertEqual(form['action'], 'same_origin')
        self.assertFalse(form['vulnerable'])
        self.assertEqual(form['assessment'], 'token_not_observed')
        self.assertEqual(result['candidate_forms'], [1])
        self.assertNotIn('private-value', json.dumps(result))

    async def test_token_attribute_order_encoding_and_double_submit_not_weakness(self):
        token = 'a4d8b0f2c6e193750123456789abcdef'
        for markup in (f'<input value="{token}" name="csrf_token">', f'<input name="csrf_token" value="{token}">'):
            with self.subTest(markup=markup):
                result, _ = await scan('<form method=post>'+markup+'</form>', [('set-cookie', f'csrf_token={token}; Secure; SameSite=Lax')])
                form = result['forms'][0]
                self.assertTrue(form['has_csrf_token'])
                self.assertEqual(form['token_details']['length'], len(token))
                self.assertEqual(form['token_details']['entropy'], 'unknown')
                self.assertFalse(form['token_details']['weaknesses'])
                self.assertFalse(result['csrf_vulnerable'])
                self.assertNotIn(token, json.dumps(result))

    async def test_token_value_not_taken_from_adjacent_input_or_meta(self):
        result, _ = await scan('<meta name="csrf-token" content="private-value"><form method=post><input name=csrf_token><input name=email value=private-value></form>')
        self.assertFalse(result['forms'][0]['has_csrf_token'])
        self.assertTrue(result['meta_token_observed'])
        self.assertEqual(result['candidate_forms'], [1])

    async def test_cookie_attributes_are_individual_not_value_substrings(self):
        result, _ = await scan(headers=[('set-cookie','a=SecureHttpOnlySameSite; Path=/'),
                                       ('set-cookie','b=private-value; HttpOnly; Secure; SameSite=Lax')])
        cookies = result['cookie_analysis']['cookies']
        self.assertEqual(cookies[0]['flags_missing'], ['httponly','secure','samesite'])
        self.assertEqual(cookies[1]['flags_missing'], [])
        self.assertNotIn('private-value', json.dumps(result))
        self.assertFalse(result['csrf_vulnerable'])

    async def test_failures_are_incomplete_not_clean(self):
        for kwargs in ({'status':403}, {'status':429}, {'status':503}, {'offline':True}):
            with self.subTest(kwargs=kwargs):
                result, seen = await scan(**kwargs)
                self.assertEqual(seen, ['GET'])
                self.assertFalse(result['coverage_complete'])
                self.assertEqual(result['assessment'], 'inconclusive')
                self.assertNotIn('private-value', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
