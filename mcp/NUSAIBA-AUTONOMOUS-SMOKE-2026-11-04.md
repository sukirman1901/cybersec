# Nusaiba bounded browser smoke — 2026-11-04

User renewed permission to continue testing their `nusaiba.dev` website during
autonomous tool remediation. Engagement initialized and authorized through the
connected gate at `2026-11-04T16:29:21.095008+00:00`. Actual requests stayed on the
exact `https://nusaiba.dev` origin; discovered subdomains were not tested.

Browser path: una MCP was unavailable (CDP connection failure), and the default
CLI profile was locked. Started an isolated persistent `cybersec-smoke` una daemon.
No existing browser process was terminated. Homepage navigation returned loaded,
title `Nusaiba — Motion-First Shadcn Sections`. Fresh snapshot and text check for
`Motion shadcn sections` passed. The first longer text assertion failed only because
the rendered heading contains a line break; the observed text was then checked.

Two explicit same-origin read-only fetches were dispatched through una eval, with
credentials omitted, redirects manual, 5-second abort per request, and a 256 KiB
response sampling limit. The first eval returned a function without invoking it;
it made no fetch. The subsequent invoked operation produced the following result:

| Request | HTTP | Sample bytes | Truncated | Next asset marker | Form tag |
|---|---|---:|---|---|---|
| `/` | 200 | 100428 | No | Yes | No |
| `/.__cybersec_missing_readonly_20261104` | 404 | 32437 | No | Yes | No |

Both responses exposed the **presence** of Content-Security-Policy,
Strict-Transport-Security, X-Content-Type-Options and X-Frame-Options. Their policies
were not semantically audited by this check. No cookie values or raw page bodies
were returned or saved. Browser response visibility cannot inspect Set-Cookie.

Traffic accounting: one deliberate document navigation plus two explicit fetches.
Browser performance entries showed 37 resource entries and one navigation entry
afterward, below the prior 100-request ceiling by that observable count. Performance
entries are not a complete wire-request log and may include cache hits; an exact
network count is not claimed. No repeated crawl, form submission, credential
attempts, destructive probes, exploit payloads or load tests were performed.

Confidence: HIGH for these HTTP/header-presence observations, MEDIUM for the
Next.js asset hint, no exploit verdict. Coverage: two public responses and rendered
homepage only; authentication, API authorization, CSRF validation, injection,
ports, cloud, AD and mobile behavior were not tested against this site.

The missing route returning 404 is a useful real-site negative observation. It is
not evidence that every route lacks a catch-all or that the site is vulnerability
free. Local synthetic detector tests remain separate from this live smoke.

## Cycle 2 repeat — 16:57:21 UTC

The existing engagement gate again returned `in_scope=true`, `authorized=true`,
no violations for `https://nusaiba.dev`. Una MCP remained unavailable; the persistent
isolated CLI browser was still on the homepage and produced a fresh snapshot.
Two explicit GET requests (same paths above) used credentials omitted, manual
redirects and a five-second abort; response streams were cancelled without reading
their bodies. No new navigation or resource crawl was requested.

Observed root **200**, missing-path control **404**, and presence of all four
previously listed security headers on both responses. These are fresh availability
and header-presence observations, not policy correctness or scanner exploit proof.
The browser and daemon were left running. No raw body, cookies or tokens saved.

## Cycle 3 repeat — 17:25:56 UTC

Engagement validation again confirmed the exact origin remained authorized. One
credential-free GET `/` through the existing una CLI browser returned **200**;
CSP, HSTS, X-Content-Type-Options and X-Frame-Options were present. Manual redirects,
five-second abort and immediate body cancellation were retained. No new navigation,
body read, scanner execution or negative-route request was made in this repeat.
This checks current availability/header presence only, not updated MCP runtime
behavior or vulnerability absence. The persistent browser remains open.

## Cycle 5 repeat — 18:01:02 UTC

Exact-origin engagement validation returned authorized/in-scope with no violations.
The persistent una CLI browser supplied a fresh homepage snapshot. One explicit
GET `/`, credentials omitted and redirects manual, returned **200** with CSP,
HSTS, X-Content-Type-Options and X-Frame-Options present. A five-second abort bound
was used and the body stream was cancelled unread. No navigation, credential
attempt, upload or cloud probe occurred. Header presence is not policy validation.
The browser/daemon remain running.
