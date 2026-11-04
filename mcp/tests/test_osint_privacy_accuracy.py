"""Offline fixtures: fictional identifiers only; no provider access permitted."""
import asyncio
import importlib
import json
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

email = importlib.import_module('cyber_tools.email_osint')
social = importlib.import_module('cyber_tools.social_osint')
telegram = importlib.import_module('cyber_tools.telegram_osint')
people = importlib.import_module('cyber_tools.people_osint')
USER = 'fictional_fixture_42'
MAIL = 'fictional.fixture@example.invalid'
SECRET = 'fixture-secret-token'


class Response:
    def __init__(self, status=200, body=b''):
        self.status_code = self.status = status
        self.content = body
        self.text = body.decode()
        self.url = 'https://example.invalid/?token=' + SECRET
        self.read_sizes = []

    def json(self):
        return json.loads(self.content)

    def read(self, size=-1):
        self.read_sizes.append(size)
        return self.content if size < 0 else self.content[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def aiter_bytes(self, chunk_size=4096):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start:start + chunk_size]


class Client:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, *args, **kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def stream(self, *args, **kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class SlowResponse(Response):
    """A tiny body stalls without an HTTPX exception; cancellation must close it."""
    def __init__(self, headers=False):
        super().__init__(200)
        self.headers = headers
        self.started = asyncio.Event()
        self.closed = False

    async def __aenter__(self):
        if self.headers:
            self.started.set()
            await asyncio.Event().wait()
        return self

    async def aiter_bytes(self, chunk_size=4096):
        yield b'x'
        self.started.set()
        await asyncio.Event().wait()

    async def __aexit__(self, *args):
        self.closed = True


class PrivacyAccuracy(unittest.TestCase):
    def test_social_request_wall_timeout_closes_stream(self):
        async def run():
            response = SlowResponse()
            with patch.object(social.httpx, 'AsyncClient', return_value=Client(response)), patch.object(
                    social, '_MAX_REQUEST_SECONDS', .02, create=True), patch.object(
                    social, '_PLATFORMS', [('Fixture', 'https://example.invalid/{}', 'status', '')]):
                try:
                    result = await asyncio.wait_for(social.social_osint(USER), .3)
                except TimeoutError:
                    self.fail('request has no wall timeout')
            self.assertEqual(len(result['incomplete']), 1)
            self.assertTrue(response.closed)
        asyncio.run(run())

    def test_social_aggregate_timeout_preserves_completed_and_cleans_pending(self):
        async def run():
            response = SlowResponse()
            client = Client(response)
            def stream(method, url):
                return Response(404) if '/fast/' in url else response
            client.stream = stream
            platforms = [(name, f'https://example.invalid/{name}/{{}}', 'status', '')
                         for name in ('fast', 'slow', 'queued')]
            with patch.object(social.httpx, 'AsyncClient', return_value=client), patch.object(
                    social, '_MAX_TOTAL_SECONDS', .02, create=True), patch.object(social, '_PLATFORMS', platforms):
                try:
                    result = await asyncio.wait_for(social.social_osint(USER, concurrent=1), .3)
                except TimeoutError:
                    self.fail('aggregate has no wall timeout')
            self.assertEqual(len(result['not_found']), 1)
            self.assertEqual(len(result['incomplete']), 2)
            self.assertTrue(result['error'])
            self.assertTrue(response.closed)
            self.assertEqual(len(asyncio.all_tasks()), 1)
        asyncio.run(run())

    def test_social_caller_cancellation_cleans_workers(self):
        async def run():
            response = SlowResponse()
            with patch.object(social.httpx, 'AsyncClient', return_value=Client(response)), patch.object(
                    social, '_PLATFORMS', [('Fixture', 'https://example.invalid/{}', 'status', '')] * 3):
                task = asyncio.create_task(social.social_osint(USER, concurrent=1))
                await asyncio.wait_for(response.started.wait(), .3)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertTrue(response.closed)
                self.assertEqual(len(asyncio.all_tasks()), 1)
        asyncio.run(run())

    def test_telegram_wall_timeout_closes_stream(self):
        async def run():
            response = SlowResponse()
            with patch.object(telegram.httpx, 'AsyncClient', return_value=Client(response)), patch.object(
                    telegram, '_MAX_REQUEST_SECONDS', .02, create=True):
                try:
                    result = await asyncio.wait_for(telegram.telegram_osint(USER), .3)
                except TimeoutError:
                    self.fail('Telegram request has no wall timeout')
            self.assertEqual(result['status'], 'incomplete')
            self.assertIn('timed out', result['error'])
            self.assertTrue(response.closed)
        asyncio.run(run())

    def test_email_async_header_waits_have_wall_timeout(self):
        async def run():
            with patch.object(email.httpx, 'AsyncClient', return_value=Client(SlowResponse(headers=True))), patch.object(
                    email, 'GuardedAsyncClient', return_value=Client(SlowResponse(headers=True))), patch.object(
                    email, '_MAX_REQUEST_SECONDS', .02, create=True), patch.object(email, '_check_mx',
                    return_value={'mx_records': [], 'a_records': [], 'has_mx': None}):
                try:
                    result = await asyncio.wait_for(email.email_osint(MAIL), .3)
                except TimeoutError:
                    self.fail('email async requests have no wall timeout')
            self.assertEqual(result['gravatar']['status'], 'incomplete')
            self.assertEqual(result['domain_status']['status'], 'incomplete')
        asyncio.run(run())

    def setUp(self):
        # Fail closed even if a fixture forgets its local provider mock.
        for target in ('socket.getaddrinfo', 'socket.socket.connect', 'socket.socket.sendto',
                       'dns.resolver.Resolver.resolve', 'urllib.request.urlopen',
                       'httpx.AsyncClient', 'subprocess.run', 'subprocess.Popen'):
            mock = patch(target, side_effect=AssertionError('unmocked external access'))
            mock.start()
            self.addCleanup(mock.stop)

    def social_result(self, response, **kwargs):
        with patch.object(social.httpx, 'AsyncClient', return_value=Client(response)), patch.object(
                social, '_PLATFORMS', [('Fixture', 'https://example.invalid/{}', 'status', '')]):
            return asyncio.run(social.social_osint(USER, **kwargs))

    def telegram_result(self, response):
        with patch.object(telegram.httpx, 'AsyncClient', return_value=Client(response)):
            return asyncio.run(telegram.telegram_osint(USER))

    def test_social_blocking_and_timeout_are_incomplete(self):
        for response in (Response(403, USER.encode()), Response(429), httpx.ReadTimeout(SECRET)):
            with self.subTest(response=response):
                result = self.social_result(response)
                self.assertEqual(result['not_found'], [])
                self.assertEqual(result['found'], [])
                self.assertEqual(len(result.get('incomplete', [])), 1)
                self.assertNotIn(SECRET, json.dumps(result))

    def test_social_generic_200_is_not_profile_evidence(self):
        result = self.social_result(Response(200, b'Welcome to our profile followers page'))
        self.assertEqual(result['found'], [])
        self.assertEqual(len(result.get('incomplete', [])), 1)

    def test_social_match_is_candidate_not_identity(self):
        result = self.social_result(Response(200, USER.encode()))
        self.assertEqual(result['found_count'], 1)
        self.assertIs(result['found'][0].get('identity_confirmed'), False)
        self.assertIsNone(result['found'][0]['exists'])

    def test_social_absence_is_observation(self):
        result = self.social_result(Response(404))
        self.assertEqual(len(result['not_found']), 1)
        self.assertFalse(result['not_found'][0]['exists'])

    def test_social_oversize_is_incomplete(self):
        result = self.social_result(Response(200, USER.encode() + b'x' * 65537))
        self.assertEqual(result['found'], [])
        self.assertEqual(len(result.get('incomplete', [])), 1)

    def test_input_rejection_precedes_io(self):
        for module, function, value in ((social, social.social_osint, 'x' * 65),
                                        (telegram, telegram.telegram_osint, '../?token=' + SECRET),
                                        (email, email.email_osint, 'x' * 255 + '@example.invalid')):
            with self.subTest(module=module.__name__), patch.object(module.httpx, 'AsyncClient') as client:
                result = asyncio.run(function(value))
                self.assertTrue(result['error'])
                client.assert_not_called()
                self.assertNotIn(value, json.dumps(result))
        result = json.loads(people.people_osint('x' * 255))
        self.assertTrue(result.get('error'))

    def test_social_numeric_limits_rejected(self):
        for kwargs in ({'concurrent': 0}, {'concurrent': 51}, {'timeout': 61}, {'timeout': float('nan')}):
            with self.subTest(kwargs=kwargs):
                # Avoid old zero-semaphore deadlock by rejecting before client creation.
                with patch.object(social.httpx, 'AsyncClient', side_effect=ValueError('client reached')):
                    try:
                        result = asyncio.run(social.social_osint(USER, **kwargs))
                    except ValueError:
                        self.fail('invalid limits reached network client')
                    self.assertTrue(result['error'])

    def test_telegram_generic_200_not_confirmed(self):
        result = self.telegram_result(Response(200, b'If you have Telegram, you can contact someone'))
        self.assertIsNone(result['exists'])
        self.assertEqual(result.get('status'), 'incomplete')

    def test_telegram_failure_is_incomplete_and_redacted(self):
        for response in (Response(403), Response(429), httpx.ReadTimeout(SECRET), RuntimeError(MAIL + SECRET)):
            with self.subTest(response=response):
                result = self.telegram_result(response)
                self.assertIsNone(result['exists'])
                self.assertEqual(result.get('status'), 'incomplete')
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertNotIn(MAIL, json.dumps(result))

    def test_telegram_candidate_minimizes_metadata(self):
        body = (f'<div class="tgme_page_title">{USER}</div>'
                f'<meta property="og:description" content="{MAIL} token={SECRET}">'
                '<div data-user-id="123456789"></div>').encode()
        result = self.telegram_result(Response(200, body))
        self.assertIs(result.get('identity_confirmed'), False)
        self.assertNotIn(MAIL, json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn('123456789', json.dumps(result))
        self.assertTrue(all(link.get('observed') is False for link in result['search_links']))

    def test_gravatar_blocking_not_absence(self):
        for response in (Response(403), Response(429), httpx.ReadTimeout(SECRET)):
            with self.subTest(response=response), patch.object(email.httpx, 'AsyncClient', return_value=Client(response)):
                result = asyncio.run(email._check_gravatar(MAIL))
                self.assertIsNone(result['has_gravatar'])
                self.assertEqual(result.get('status'), 'incomplete')

    def test_email_links_are_generated_and_sensitive_values_omitted(self):
        with patch.object(email, '_check_mx', return_value={'mx_records': [], 'a_records': [], 'has_mx': None}), patch.object(
                email.httpx, 'AsyncClient', return_value=Client(Response(404))), patch.object(
                email, 'GuardedAsyncClient', return_value=Client(Response(403))):
            result = asyncio.run(email.email_osint(MAIL))
        self.assertNotIn(MAIL, json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIsNone(result['domain_status']['alive'])
        self.assertTrue(all(link.get('observed') is False for link in result['breach_check_urls'] + result['search_urls']))

    def test_people_status_is_not_identity_and_errors_retained(self):
        for status in (200, 403, 429):
            response = Response(status)
            with self.subTest(status=status), patch.object(people.urllib.request, 'urlopen', return_value=response):
                result = json.loads(people.people_osint(USER, 'search'))
                self.assertEqual(result['total_profiles'], 0)
                self.assertEqual(len(result.get('observations', [])), 12)
                self.assertFalse(any(row.get('identity_confirmed') for row in result['observations']))

    def test_people_github_mismatch_not_a_profile(self):
        body = json.dumps({'login': 'different_fictional_fixture', 'bio': MAIL + SECRET}).encode()
        response = Response(200, body)
        with patch.object(people.urllib.request, 'urlopen', return_value=response):
            result = json.loads(people.people_osint(USER, 'github'))
        self.assertEqual(result['total_profiles'], 0)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertTrue(response.read_sizes and all(0 < size <= 65537 for size in response.read_sizes))

    def test_people_github_match_has_no_personal_metadata(self):
        response = Response(200, json.dumps({'login': USER, 'name': MAIL, 'bio': SECRET}).encode())
        with patch.object(people.urllib.request, 'urlopen', return_value=response):
            result = json.loads(people.people_osint(USER, 'github'))
        self.assertEqual(result['total_profiles'], 1)
        self.assertIs(result['profiles'][0].get('identity_confirmed'), False)
        self.assertNotIn(MAIL, json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(result))

    def test_people_email_only_counts_mx_answers(self):
        response = Response(200, b'{"Status":0,"Answer":[{"type":5,"data":"alias.invalid"}]}')
        with patch.object(people.urllib.request, 'urlopen', return_value=response):
            result = json.loads(people.people_osint(MAIL, 'email'))
        self.assertFalse(result['email_analysis']['has_mx'])
        self.assertNotIn(MAIL, json.dumps(result))

    def test_email_dns_output_does_not_export_provider_strings(self):
        with patch.object(email, '_check_mx', return_value={
                'mx_records': [{'exchange': SECRET + MAIL, 'preference': 0}],
                'a_records': [SECRET], 'has_mx': True}), patch.object(
                email.httpx, 'AsyncClient', return_value=Client(Response(404))), patch.object(
                email, 'GuardedAsyncClient', return_value=Client(Response(200))):
            result = asyncio.run(email.email_osint(MAIL))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(MAIL, json.dumps(result))
        self.assertTrue(result['has_mx'])

    def test_telegram_oversize_and_absence(self):
        result = self.telegram_result(Response(200, b'x' * 65537))
        self.assertEqual(result['status'], 'incomplete')
        self.assertIsNone(result['exists'])
        self.assertTrue(result['error'])
        result = self.telegram_result(Response(404))
        self.assertFalse(result['exists'])
        self.assertEqual(result['status'], 'not_found')

    def test_people_oversize_and_failures_are_recorded(self):
        for response in (Response(200, b'x' * 65537), Response(403), Response(429)):
            with self.subTest(response=response), patch.object(people.urllib.request, 'urlopen', return_value=response):
                result = json.loads(people.people_osint(USER, 'github'))
                self.assertEqual(result['total_profiles'], 0)
                self.assertEqual(result['observations'][0]['status'], 'incomplete')
        with patch.object(people.urllib.request, 'urlopen', side_effect=TimeoutError(SECRET)):
            result = json.loads(people.people_osint(USER, 'search'))
            self.assertEqual(len(result['observations']), 12)
            self.assertNotIn(SECRET, json.dumps(result))

    def test_dns_timeout_and_null_mx_are_not_mailbox_proof(self):
        import dns.exception
        from types import SimpleNamespace
        with patch('dns.resolver.Resolver.resolve', side_effect=dns.exception.Timeout):
            self.assertIsNone(email._check_mx('example.invalid')['has_mx'])
        with patch('dns.resolver.Resolver.resolve', return_value=[SimpleNamespace(exchange='.', preference=0)]):
            self.assertFalse(email._check_mx('example.invalid')['has_mx'])

    def test_people_http_error_is_incomplete_not_not_found(self):
        from urllib.error import HTTPError
        for status in (403, 429):
            with self.subTest(status=status), patch.object(people.urllib.request, 'urlopen',
                    side_effect=HTTPError('https://example.invalid', status, SECRET, {}, None)):
                result = json.loads(people.people_osint(USER, 'github'))
                self.assertEqual(result['observations'][0]['status'], 'incomplete')
                self.assertNotIn(SECRET, json.dumps(result))


if __name__ == '__main__':
    unittest.main()
