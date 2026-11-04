"""Metrics fixtures distinguish numeric records from incidental prose."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_tools import metrics_check as module


async def scan(handler):
    seen = []
    def respond(request):
        seen.append(request.url.path)
        return handler(request)
    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    with patch.object(module.httpx, 'AsyncClient', return_value=client):
        result = await module.metrics_check('https://fixture.test')
    return result, seen


class MetricsAccuracy(unittest.IsolatedAsyncioTestCase):
    async def test_incidental_prose_and_dynamic_html_are_not_metrics(self):
        for body in ('Our uptime and go_tool documentation', '<html>process_cpu_seconds 1</html>', '# TYPE process_cpu_seconds counter\nnot a sample'):
            with self.subTest(body=body):
                result, _ = await scan(lambda r: httpx.Response(200, text=body + '\n' + r.url.path))
                self.assertEqual(result['total_exposed'], 0)

    async def test_real_samples_detected_without_labels_or_values(self):
        for body in ('# TYPE http_requests_total counter\nhttp_requests_total{user="private-value"} 12\n', 'custom_queue_size 12\ncustom_jobs_total 7\n'):
            with self.subTest(body=body):
                result, _ = await scan(lambda r: httpx.Response(200, text=body) if r.url.path == '/metrics' else httpx.Response(404))
                self.assertEqual(result['total_exposed'], 1)
                self.assertNotIn('private-value', json.dumps(result))
                self.assertNotIn('snippet', json.dumps(result))

    async def test_identical_catchall_not_metrics_endpoint(self):
        result, _ = await scan(lambda r: httpx.Response(200, text='http_requests_total 1\nprocess_cpu_seconds 2\n'))
        self.assertEqual(result['total_exposed'], 0)

    async def test_failures_inconclusive_and_bounded(self):
        for code in (403,429,503):
            with self.subTest(code=code):
                result, seen = await scan(lambda r: httpx.Response(code))
                self.assertEqual(len(seen), 1)
                self.assertEqual(result['risk'], 'INCONCLUSIVE')
                self.assertFalse(result['coverage_complete'])

    async def test_transport_failure_not_pass(self):
        def offline(request):
            raise httpx.ConnectError('private-value', request=request)
        result, seen = await scan(offline)
        self.assertEqual(result['risk'], 'INCONCLUSIVE')
        self.assertEqual(len(seen), 1)
        self.assertNotIn('private-value', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
