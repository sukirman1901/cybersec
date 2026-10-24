"""Clamped HTTP transport for active probing.

An authorized target answering with a redirect must not move the request
(including headers and query parameters) to a host outside the authorized
engagement scope. This is dispatch-level egress containment, applied at the
transport layer: out-of-scope redirects raise an HTTPError instead of being
followed.
"""

import urllib.request
from urllib.error import HTTPError

from .engagement_gate import validate_target

REASON = "redirect left authorized scope"


class ScopeClampedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        location = newurl if isinstance(newurl, str) else str(newurl)
        if not validate_target(location)["validated"]:
            raise HTTPError(location, code, REASON, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
