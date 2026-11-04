# nusaiba.dev production smoke test

Authorization: user approved anonymous lightweight checks on https://nusaiba.dev,
maximum 100 requests / 5 minutes; no login brute force, uploads, writes or load tests.
Activity: approximately 15:24–15:25 UTC, 2026-11-04.

## Execution evidence

- una browser: homepage loaded, title `Nusaiba — Motion-First Shadcn Sections`.
  Snapshot and DOM inspection found no homepage input elements; public links include
  /blocks, /pricing, /docs, /login and /compose. These linked pages were not tested.
- Cybersec `http_probe_target(https://nusaiba.dev:443)`: one GET, HTTP 200,
  Cloudflare response, Next.js-related headers. Certificate validation is disabled
  in this tool, so this result does not certify TLS configuration.
- Cybersec `csp_analyze`: one homepage GET, CSP and protection headers returned.
- Cybersec `cookie_audit`: one homepage GET, no Set-Cookie observed. Authenticated
  session cookie security is untested.
- Browser resource timing listed 43 resource entries plus the navigation; three
  scanner GETs were issued. Resource entries are not an exact network-request log
  (cache, redirects and telemetry can differ). No further navigation or probes ran.

## Reviewed observations

1. LOW hardening observation, HIGH confidence in header content: CSP script-src
   includes 'unsafe-inline' without an observed nonce/hash. This weakens a layer
   of XSS mitigation but is not evidence of an injectable input or executed XSS.
   Consider tested nonce/hash-based policy compatible with Next.js.
2. Protections observed: HSTS max-age=63072000; includeSubDomains; preload,
   X-Frame-Options DENY, X-Content-Type-Options nosniff,
   Referrer-Policy strict-origin-when-cross-origin, CSP frame-ancestors 'none'.
3. No exploitable vulnerability confirmed by this smoke test.

## Scanner defects exposed by the live test

- CSP analyzer labels explicit https://host source expressions a broad `https:`
  scheme allowance because it checks a substring. Discard this false positive.
- HTTP probe returned Ruby alongside Cloudflare. Ruby is not substantiated by
  the response: its broad `rack` regex can match `tracking` in Permissions-Policy.
  Do not infer a Ruby backend from this result.
- generate_report ran, but its generic summary reports zero ports when no port
  inventory was supplied and counts the hardening observation as a vulnerability.
  Those labels do not establish a closed port or a confirmed exploit. This reviewed
  record is the authoritative interpretation of the smoke test.

Coverage: anonymous homepage only. SQLi/XSS injection, login/session verification,
API authorization, payment flows, authenticated pages and subdomains were not tested.
The result proves these three tool calls can run against the site; it does not
establish full detector accuracy or that the production application is secure.
