"""Bounded HTTP observations shared by shallow surface detectors."""
import asyncio
import time
import httpx


class SurfaceProbe:
    def __init__(self, client, seconds=15, max_requests=16, max_bytes=262144):
        self.client = client
        self.deadline = time.monotonic() + seconds
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.requests = 0
        self.errors = []
        self.stopped = False

    async def request(self, method, url, **kwargs):
        if self.stopped:
            return None
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= self.max_requests:
            self.errors.append('budget_exhausted')
            self.stopped = True
            return None
        self.requests += 1

        async def receive():
            async with self.client.stream(method, url, follow_redirects=False, **kwargs) as response:
                if response.status_code in (401, 403, 429) or response.status_code >= 500 or 300 <= response.status_code < 400:
                    self.errors.append('blocked_redirect_or_server_error:' + str(response.status_code))
                    self.stopped = True
                    return None
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > self.max_bytes:
                        self.errors.append('body_limit_exceeded')
                        self.stopped = True
                        return None
                    content.extend(chunk)
                headers = dict(response.headers)
                # aiter_bytes already decoded content encodings.
                headers.pop('content-encoding', None)
                headers.pop('content-length', None)
                return httpx.Response(response.status_code, headers=headers, content=bytes(content), request=response.request)
        try:
            return await asyncio.wait_for(receive(), timeout=remaining)
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            self.errors.append(type(exc).__name__)
            self.stopped = True
            return None

    def summary(self):
        return {'requests_attempted': self.requests, 'coverage_complete': not self.errors,
                'execution_status': 'partial' if self.errors else 'completed',
                **({'error': 'Probe incomplete', 'errors': self.errors} if self.errors else {})}
