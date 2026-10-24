"""Clamped HTTP transport for active probing.

An authorized target answering with a redirect must not move the request
(including headers and query parameters) to a host outside the authorized
engagement scope. This is dispatch-level egress containment, applied at the
transport layer: out-of-scope redirects raise a transport error instead of being
followed.
"""

import urllib.request
from urllib.error import HTTPError

import httpx

from .engagement_gate import validate_target

REASON = "redirect left authorized scope"
_REDIRECT = "cybersec_scoped_redirect"


def _check_redirect(request):
    if request.extensions.get(_REDIRECT) and not validate_target(str(request.url))["validated"]:
        raise httpx.RequestError(REASON, request=request)


def _mark_redirect(response):
    # HTTPX carries request extensions into next_request. Mark at the response
    # hook, before it constructs that request; check at the next request hook,
    # before transport egress. No private HTTPX methods or global patches.
    if response.has_redirect_location:
        response.request.extensions[_REDIRECT] = True


async def _async_check_redirect(request):
    _check_redirect(request)


async def _async_mark_redirect(response):
    _mark_redirect(response)


def GuardedClient(**kwargs):
    """Client factory retaining HTTPX behavior with scoped redirect hooks.

    Covers client/per-request follow overrides and sending next_request later.
    Initial-target authorization remains the dispatch middleware's responsibility.
    """
    hooks = {key: list(value) for key, value in kwargs.pop("event_hooks", {}).items()}
    hooks["request"] = [_check_redirect, *hooks.get("request", [])]
    hooks["response"] = [_mark_redirect, *hooks.get("response", [])]
    return httpx.Client(event_hooks=hooks, **kwargs)


def GuardedAsyncClient(**kwargs):
    """Async counterpart to GuardedClient; hooks are local to this client."""
    hooks = {key: list(value) for key, value in kwargs.pop("event_hooks", {}).items()}
    hooks["request"] = [_async_check_redirect, *hooks.get("request", [])]
    hooks["response"] = [_async_mark_redirect, *hooks.get("response", [])]
    return httpx.AsyncClient(event_hooks=hooks, **kwargs)


def guarded_httpx_get(url, **kwargs):
    """Scoped equivalent of httpx.get for synchronous one-shot callers."""
    client_options = {key: kwargs.pop(key) for key in ("verify", "trust_env", "proxy") if key in kwargs}
    with GuardedClient(**client_options) as client:
        return client.get(url, **kwargs)


class ScopeClampedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        location = newurl if isinstance(newurl, str) else str(newurl)
        if not validate_target(location)["validated"]:
            raise HTTPError(location, code, REASON, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Observe Location without following it, including outside an engagement."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(opener, request, timeout):
    """Single redirection seam for tests; build_opener runs before this."""
    return opener.open(request, timeout=timeout)


def guarded_urlopen(request, timeout=10, context=None):
    """Open a URL or Request, refusing redirects outside the authorized scope."""
    opener = urllib.request.build_opener(
        ScopeClampedRedirectHandler,
        *(_https_handlers(context)),
    )
    return _open(opener, request, timeout)


def _https_handlers(context):
    if context is None:
        return []
    handler = urllib.request.HTTPSHandler(context=context)
    return [handler]
