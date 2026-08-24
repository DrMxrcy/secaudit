---
name: better-auth-security
description: Audits Better Auth configurations and API misuse — the cookie-presence check sold as an auth gate, cookieCache delaying revocation and bans, disabled CSRF/origin checks and stale trustedOrigins, trusted proxy headers, organization/admin plugin permission checks that run only on the client, unscoped API keys, BETTER_AUTH_SECRET handling, account-linking takeover, memory-backed rate limits, and per-user data leaking into a shared Next.js cache. Use whenever the project depends on better-auth, has an auth.ts calling betterAuth(), or uses authClient/auth.api. For framework-agnostic auth issues see secaudit:auth.
license: MIT
---

# Better Auth Security

Better Auth is a configuration-first auth library: most of its security posture lives in the
options object passed to `betterAuth()` and in *which* of its two APIs you call. The server API
(`auth.api.*`) validates against the database; the client API (`authClient.*`) mostly does not, and
several of its helpers are pure UI convenience with zero server round-trip. AI assistants routinely
paste the fast helper into the place that needs the authoritative one.

This skill covers only Better-Auth-specific misuse. The framework-agnostic layer — middleware is
not a security boundary (CVE-2025-29927), Server Actions as public endpoints, JWT verification,
cookie flags, CSRF, session fixation, account enumeration — is in `secaudit:auth`. Roles trusted
from the client and the generic admin surface are in `secaudit:privilege-escalation`.

## When to Use

- `package.json` depends on `better-auth`, or a file calls `betterAuth({ ... })`.
- Reviewing `auth.ts` / `auth-client.ts`, `middleware.ts` / `proxy.ts`, or any `auth.api.*` call.
- The project uses the organization, admin, API-key, or two-factor plugins.
- Auditing whether a revoked session, banned user, or demoted admin actually loses access.

Review grep heuristics: `getSessionCookie`, `auth.api.getSession`, `cookieCache`, `freshAge`,
`disableCSRFCheck`, `disableOriginCheck`, `trustedOrigins`, `trustedProxyHeaders`,
`checkRolePermission`, `adminUserIds`, `verifyApiKey`, `accountLinking`, `BETTER_AUTH_SECRET`.

## 1. `getSessionCookie()` Is Not an Auth Gate

**What to look for:** `getSessionCookie(request)` (or `getCookieCache`) used as the decision that
lets a request through — in `middleware.ts` / `proxy.ts`, a layout, or a route handler.

**Why it's exploitable:** the helper checks that a cookie *exists*. It does not verify the
signature and does not touch the database. Better Auth's own docs put `// THIS IS NOT SECURE!` in
that snippet; assistants copy the code and drop the comment. Anyone can set a cookie named
`better-auth.session_token` to arbitrary junk with `curl` and pass the check. A revoked or expired
session passes too.

**Fix:** treat the cookie check as an optimistic redirect for UX only. The real gate is
`auth.api.getSession({ headers: await headers() })` inside the page, layout, or handler that
actually serves the data.

```typescript
// proxy.ts (Next.js 16; middleware.ts pre-16) — BAD: presence of a cookie is the whole gate
import { getSessionCookie } from "better-auth/cookies";
export function proxy(request: NextRequest) {
  const cookie = getSessionCookie(request);         // no signature check, no DB lookup
  if (!cookie) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();                        // forged cookie => allowed through
}

// GOOD: optimistic redirect here, authoritative check in the page/handler
// proxy.ts — UX only
export function proxy(request: NextRequest) {
  if (!getSessionCookie(request)) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}
// app/dashboard/page.tsx — the actual boundary
import { auth } from "@/lib/auth";
import { headers } from "next/headers";
export default async function Page() {
  const session = await auth.api.getSession({ headers: await headers() }); // validated server-side
  if (!session) redirect("/login");
  return <Dashboard userId={session.user.id} />;
}
```

**Next.js 16 note:** `middleware.ts` was renamed to `proxy.ts` and the named export `middleware`
to `proxy`; the edge runtime is not supported in `proxy` (Node.js only). The rename changes nothing
about the boundary — `proxy.ts` is still not a security boundary (`secaudit:auth`).

Detect: `grep -rn "getSessionCookie\|getCookieCache" --include=*.ts --include=*.tsx .`

## 2. Session Read in the Server Component, Not in the Action It Calls

**What to look for:** a Server Component or layout that calls `auth.api.getSession(...)`, renders a
form, and hands off to a `"use server"` action or `app/api/*` handler that has no session read of
its own. Also `auth.api.getSession()` called without `headers` — it silently returns `null`, and
`if (!session)` branches that "never fire" get deleted during debugging.

**Why it's exploitable:** the Server Action compiles to a public POST endpoint. The page-level
check protects the render, not the mutation. Any logged-in user (or any attacker with a stolen
cookie) can invoke the action directly with `curl` and skip every check the page performed.

**Fix:** re-read the session inside the action/handler and authorize there, forwarding `headers()`.

```typescript
// app/actions/delete-project.ts — BAD: relies on the page having checked
"use server";
export async function deleteProject(projectId: string) {
  await db.project.delete({ where: { id: projectId } }); // public POST, no session, no ownership
}

// GOOD: identity from the server-verified session, ownership in the same query
"use server";
import { auth } from "@/lib/auth";
import { headers } from "next/headers";
export async function deleteProject(projectId: string) {
  const session = await auth.api.getSession({ headers: await headers() }); // headers required
  if (!session) throw new Error("Unauthorized");
  await db.project.deleteMany({ where: { id: projectId, ownerId: session.user.id } });
}
```

Detect: `grep -rln "use server" app | xargs grep -Ln "auth.api.getSession"`

## 3. `cookieCache` Delays Revocation, Bans, and Role Changes

**What to look for:** `session: { cookieCache: { enabled: true, maxAge: ... } }` in `betterAuth()`,
especially with a long `maxAge`, combined with any destructive or privileged path that calls
`getSession` normally. Also `session: { freshAge: 0 }`.

**Why it's exploitable:** with the cookie cache on, `getSession` reads a signed cookie instead of
the session table. A session you revoked, a user you banned, and an admin you demoted all keep
working until `maxAge` expires — the DB no longer participates in the decision. Assistants enable
it because the docs frame it as a performance win. Separately, `freshAge` (default 1 day) is what
gates re-authentication before sensitive operations; `freshAge: 0` disables that check entirely.

**Fix:** keep `maxAge` short, and bypass the cache with `query: { disableCookieCache: true }` on
every privileged or destructive read. Tighten `freshAge` for destructive actions rather than
zeroing it.

```typescript
// lib/auth.ts — BAD: 30-minute stale window on bans, revocations, and role changes
export const auth = betterAuth({
  session: { cookieCache: { enabled: true, maxAge: 60 * 30 }, freshAge: 0 },
});

// GOOD: short cache, and the DB is authoritative wherever it matters
export const auth = betterAuth({
  session: { cookieCache: { enabled: true, maxAge: 60 }, freshAge: 60 * 15 },
});

// app/actions/delete-account.ts — force a DB-backed read before anything destructive
const session = await auth.api.getSession({
  headers: await headers(),
  query: { disableCookieCache: true },   // revoked/banned/demoted is caught here
});
if (!session) throw new Error("Unauthorized");
```

Detect: `grep -rn "cookieCache\|freshAge\|disableCookieCache" --include=*.ts .`

## 4. Disabled CSRF / Origin Checks and Stale `trustedOrigins`

**What to look for:** `advanced: { disableCSRFCheck: true }` or `advanced: { disableOriginCheck:
true }`; `trustedOrigins` containing `http://localhost:3000` in a production config; wildcard
entries like `https://*.example.com`; a `BETTER_AUTH_TRUSTED_ORIGINS` env var nobody reviewed.

**Why it's exploitable:** `disableOriginCheck` turns off trusted-origin validation for redirects
**and** callbacks, and for back-compat also disables the CSRF check — one flag, an open redirect
and a CSRF hole. It is commonly pasted in to silence an "Invalid origin" error during local
development and then shipped. A leftover `localhost` origin lets an attacker who can get a victim's
browser to a local listener receive callbacks; a subdomain wildcard means any subdomain — including
one dangling at a decommissioned CNAME and takeover-able — can receive OAuth callbacks and tokens.
`BETTER_AUTH_TRUSTED_ORIGINS` **appends** to the configured list, so the file you are reading is not
the whole list.

**Fix:** never disable the checks; enumerate exact production origins.

```typescript
// lib/auth.ts — BAD: origin/CSRF validation off, dev origin and a wildcard shipped
export const auth = betterAuth({
  advanced: { disableCSRFCheck: true, disableOriginCheck: true },
  trustedOrigins: ["http://localhost:3000", "https://*.example.com"],
});

// GOOD: exact origins, env-driven per environment, checks left on
export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL,     // https://app.example.com in production
  trustedOrigins: [process.env.APP_ORIGIN!],
});
```

Detect: `grep -rn "disableCSRFCheck\|disableOriginCheck\|trustedOrigins\|BETTER_AUTH_TRUSTED_ORIGINS" .`

## 5. `advanced.trustedProxyHeaders` Defaults to True

**What to look for:** no `baseURL` pinned, no explicit `advanced: { trustedProxyHeaders: false }`,
and an origin container/port reachable without going through the proxy. Also
`advanced: { ipAddressHeaders: ["x-forwarded-for"] }` on a platform that does not strip it.

**Why it's exploitable:** proxy headers are trusted **by default** so reverse-proxy deploys work
with no configuration. If a request can reach the app without traversing a proxy that overwrites
them, an attacker sends `X-Forwarded-Host: evil.com` and influences the resolved base URL used for
origin matching and callback URL construction. The same class of spoofing applies to
`ipAddressHeaders`: a forged `X-Forwarded-For` defeats per-IP rate limiting (see
`secaudit:rate-limiting`) and poisons any IP recorded on the session.

**Fix:** pin `baseURL`, turn proxy-header trust off unless a proxy you control is guaranteed to be
in front, and use the platform-specific IP header rather than the generic one.

```typescript
// lib/auth.ts — BAD: implicit trust of X-Forwarded-Host, spoofable client IP
export const auth = betterAuth({
  advanced: { ipAddressHeaders: ["x-forwarded-for"] }, // trustedProxyHeaders defaults to true
});

// GOOD: base URL is a constant, headers trusted only behind a controlled proxy
export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL,                  // never derived from a request header
  advanced: {
    trustedProxyHeaders: false,                          // true only behind your own proxy
    ipAddressHeaders: ["cf-connecting-ip"],              // platform header the edge overwrites
  },
});
```

Detect: `grep -rn "trustedProxyHeaders\|ipAddressHeaders\|baseURL" --include=*.ts .`

## 6. Organization Plugin: Tenant ID From the Request

**What to look for:** your own queries filtering on an `organizationId` that arrived in a request
body, param, or search param; `auth.api.hasPermission` treated as if it guarded your data layer.

**Why it's exploitable:** `hasPermission` authorizes Better Auth's **own** organization endpoints.
It has no view of `db.project.findMany`. If your handler takes `organizationId` from the client,
any member of any org reads any other org's rows — a cross-tenant IDOR wearing an auth library.

**Fix:** derive the tenant from the session (`session.session.activeOrganizationId`) and, for
role-gated operations, ask the server for the permission decision.

```typescript
// app/api/projects/route.ts — BAD: tenant chosen by the caller
const { organizationId } = await req.json();
return Response.json(await db.project.findMany({ where: { organizationId } }));

// GOOD: tenant from the session, permission checked server-side
const session = await auth.api.getSession({ headers: await headers() });
if (!session) return new Response("Unauthorized", { status: 401 });
const organizationId = session.session.activeOrganizationId;
if (!organizationId) return new Response("No active organization", { status: 400 });
const { success } = await auth.api.hasPermission({
  headers: await headers(),
  body: { permissions: { project: ["read"] } },   // evaluated against the member's real role
});
if (!success) return new Response("Forbidden", { status: 403 });
return Response.json(await db.project.findMany({ where: { organizationId } }));
```

Detect: `grep -rn "organizationId" app | grep -i "req.json\|params\|searchParams\|body\."`

## 7. `checkRolePermission` Is a Client-Side UI Helper

**What to look for:** `authClient.admin.checkRolePermission(...)` or
`authClient.organization.checkRolePermission(...)` used anywhere a decision is enforced; a
`role` string passed from the client into that call; `admin({ adminUserIds: [...] })` in the config.

**Why it's exploitable:** both `checkRolePermission` variants are client-only and **synchronous** —
zero server round-trip. They evaluate a role string against the access-control map bundled into the
client, and they do not see dynamically created roles. They are for hiding buttons. Anything they
"protect" is protected by the attacker's own browser. Separately, `adminUserIds` grants **full
admin regardless of the user's role field** — a hardcoded or stale entry is a standing backdoor
that no role audit will surface — and the `user: ["impersonate-admins"]` permission lets a holder
sign in as other admins, which should be treated as a break-glass capability, not a normal grant.

**Fix:** use the client helper only for rendering; re-check on the server with
`auth.api.userHasPermission` (admin plugin) or `auth.api.hasPermission` (organization plugin).
See `secaudit:privilege-escalation` for the general role-from-client rule.

```typescript
// components/DeleteUser.tsx — fine for UI only
const canDelete = authClient.admin.checkRolePermission({
  role: "admin", permissions: { user: ["delete"] },   // sync, local, decorative
});
return canDelete ? <DeleteButton /> : null;

// app/actions/delete-user.ts — BAD: the same helper as the authorization decision
"use server";
export async function deleteUser(id: string, role: string) {
  if (!authClient.admin.checkRolePermission({ role, permissions: { user: ["delete"] } })) return;
  await db.user.delete({ where: { id } });            // caller supplied `role`
}

// GOOD: the server decides, from the session
"use server";
export async function deleteUser(id: string) {
  const { success } = await auth.api.userHasPermission({
    headers: await headers(),
    body: { permissions: { user: ["delete"] } },
  });
  if (!success) throw new Error("Forbidden");
  await db.user.delete({ where: { id } });
}
```

Detect: `grep -rn "checkRolePermission\|adminUserIds\|impersonate-admins" --include=*.ts --include=*.tsx .`

## 8. API Key Plugin: Key Verified, Scope Ignored

**What to look for:** `auth.api.verifyApiKey({ body: { key } })` with no `permissions` argument;
`apiKey({ enableSessionForAPIKeys: true })` combined with unscoped keys.

**Why it's exploitable:** `verifyApiKey` returns `valid: true` for any live, unexpired key. Without
the `permissions` argument it answers "is this a real key", not "may this key do this" — so a key
minted for read-only telemetry performs writes and deletes. `enableSessionForAPIKeys: true`
compounds it: the key mints a full mock session, so an unscoped key inherits everything its owner
can do, including anything the owner's role permits.

**Fix:** pass the required permissions on every verification, and keep key scopes minimal.

```typescript
// app/api/ingest/route.ts — BAD: authenticated, not authorized
const { valid, key } = await auth.api.verifyApiKey({ body: { key: header } });
if (!valid) return new Response("Unauthorized", { status: 401 });
await db.event.create({ data: { ...payload, ownerId: key!.userId } });  // read-only key writes

// GOOD: the required scope is part of the check
const { valid, error } = await auth.api.verifyApiKey({
  body: { key: header, permissions: { events: ["write"] } },
});
if (!valid) return new Response(error?.message ?? "Forbidden", { status: 403 });
```

Detect: `grep -rn "verifyApiKey\|enableSessionForAPIKeys" --include=*.ts .`

## 9. `BETTER_AUTH_SECRET` Weak, Committed, or Shared Across Environments

**What to look for:** a literal secret in `auth.ts`; a real-looking value in `.env.example`; the
same secret in `.env`, CI, and preview deployments as in production; anything under 32 characters;
a default like `"secret"` or `"your-secret-key"`.

**Why it's exploitable:** the Better Auth session token is a **signed opaque cookie, not a JWT** —
the secret is what makes it unforgeable. The same secret also signs the OAuth state cookie and the
cookie cache. So a leaked secret means forgeable sessions; and because the cookie cache carries the
session and user payload, a forged cache payload means forged **roles** with no database row ever
written. Docs require at least 32 characters. Assistants write a plausible placeholder into
`.env.example` and it gets copied verbatim; preview environments reuse production values because
that is the path of least resistance. Rotating the secret invalidates every existing session — plan
the rotation, but rotate on any suspected exposure.

**Fix:** generate per-environment, keep it out of the repo, and keep preview separate from prod.

```typescript
// lib/auth.ts — BAD: committed literal, and a fallback that silently ships in CI
export const auth = betterAuth({ secret: process.env.BETTER_AUTH_SECRET ?? "dev-secret-123" });

// GOOD: required at boot, distinct per environment
const secret = process.env.BETTER_AUTH_SECRET;
if (!secret || secret.length < 32) throw new Error("BETTER_AUTH_SECRET missing or too short");
export const auth = betterAuth({ secret });
// .env.example holds a placeholder only: BETTER_AUTH_SECRET=
// generate with: openssl rand -base64 32
```

See `secaudit:secrets` for the general handling rules and `secaudit:deployment` for keeping preview
deployments off production credentials.

Detect: `grep -rn "BETTER_AUTH_SECRET\|secret:" --include=*.ts --include=.env* .`

## 10. Account Linking Configured for Takeover

**What to look for:** `account: { accountLinking: { trustedProviders: [...] } }`, especially with a
provider that does not verify email ownership; `allowDifferentEmails: true`;
`requireLocalEmailVerified: false`.

**Why it's exploitable:** a trusted provider links accounts **even when the provider has not
verified the email**. An attacker registers `victim@example.com` at a non-verifying provider, signs
in with it, and Better Auth links that identity into the victim's existing account — full takeover
with no password and no email access. `allowDifferentEmails: true` widens it further by dropping
the email-match requirement entirely.

**Fix:** trust only providers that verify email ownership, keep the local verification requirement
on, and consider disabling implicit linking altogether for high-value accounts.

```typescript
// lib/auth.ts — BAD: any of these providers can claim an existing account by email
export const auth = betterAuth({
  account: {
    accountLinking: {
      enabled: true,
      trustedProviders: ["google", "github", "some-oidc"], // does that OIDC verify email?
      allowDifferentEmails: true,
      requireLocalEmailVerified: false,
    },
  },
});

// GOOD: verified-email providers only; local verification still required
export const auth = betterAuth({
  account: {
    accountLinking: {
      enabled: true,
      trustedProviders: ["google"],        // verified-email providers only
      allowDifferentEmails: false,
      requireLocalEmailVerified: true,
      // disableImplicitLinking: true — require an explicit, authenticated link action
    },
  },
});
```

Detect: `grep -rn "accountLinking\|trustedProviders\|allowDifferentEmails\|requireLocalEmailVerified" .`

## 11. Rate Limiting Is Production-Only and Memory-Backed

**What to look for:** no `rateLimit` block in `betterAuth()`; `rateLimit: { storage: "memory" }` on
a serverless or multi-instance deployment; no `customRules` for the credential endpoints.

**Why it's exploitable:** the built-in limiter defaults to 100 requests per 10 seconds, is
**enabled only in production**, and stores counters in memory. On serverless every cold start gets
a fresh counter, and with multiple instances the effective limit is the default multiplied by the
instance count — so `/sign-in/email` brute-force protection is effectively absent, and it is absent
in development where you would have noticed. The generic default is also far too loose for
credential endpoints regardless of storage.

**Fix:** move counters to shared storage and tighten the sensitive endpoints explicitly.

```typescript
// lib/auth.ts — BAD: default limiter, memory storage, nothing tightened
export const auth = betterAuth({ rateLimit: { enabled: true } });

// GOOD: shared counters + per-endpoint rules on the brute-forceable paths
export const auth = betterAuth({
  rateLimit: {
    enabled: true,
    storage: "secondary-storage",                  // Redis; or "database"
    customRules: {
      "/sign-in/email":    { window: 60, max: 5 },
      "/forget-password":  { window: 60, max: 3 },
      "/two-factor/*":     { window: 60, max: 5 },
    },
  },
  secondaryStorage: redisStore,
});
```

Per-IP limits are only as good as the IP source — see section 5 and `secaudit:rate-limiting`.

Detect: `grep -rn "rateLimit\|customRules\|secondaryStorage" --include=*.ts .`

## 12. Per-User Data Pulled Into a Shared Next.js Cache

**What to look for:** `'use cache'` or `unstable_cache` wrapping a function that returns
user-scoped data; a session read hoisted *out* of a cached function so the cached function stops
throwing; a cached function whose arguments do not include anything user-specific.

**Why it's exploitable:** cache entries are keyed by **arguments**, not by session. `cookies()` and
`headers()` throw inside a `'use cache'` scope, so the natural "fix" is to read the session outside
and cache the result — which makes the first visitor's data the cached response for everyone. This
is a cross-user data leak with no auth bug anywhere in the auth config.

**Fix:** either key the cache on a session-derived identifier passed in as an argument, or use
`'use cache: private'`, which may read cookies and caches per viewer.

```typescript
// app/lib/data.ts — BAD: session hoisted out; one user's dashboard served to all
async function getDashboard() {
  "use cache";
  return db.widget.findMany({ where: { ownerId: currentUserId } }); // shared entry
}

// GOOD (a): the user id is part of the cache key, and the caller is authenticated
async function getDashboard(userId: string) {
  "use cache";
  return db.widget.findMany({ where: { ownerId: userId } });
}
export async function getMyDashboard() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) throw new Error("Unauthorized");
  return getDashboard(session.user.id);        // distinct cache entry per user
}

// GOOD (b): per-viewer cache that may read cookies
async function getMyDashboardPrivate() {
  "use cache: private";
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) throw new Error("Unauthorized");
  return db.widget.findMany({ where: { ownerId: session.user.id } });
}
```

Detect: `grep -rn "use cache\|unstable_cache" app | head -50`

## Checklist

- No `getSessionCookie` result used as an authorization decision — only as an optimistic redirect.
- Every Server Action and route handler calls `auth.api.getSession({ headers: await headers() })`
  itself and authorizes on the result.
- `cookieCache.maxAge` is short; destructive paths pass `query: { disableCookieCache: true }`;
  `freshAge` is tightened, not zeroed.
- `disableCSRFCheck` / `disableOriginCheck` absent; `trustedOrigins` holds exact production origins
  (no `localhost`, no wildcards) — check `BETTER_AUTH_TRUSTED_ORIGINS` too.
- `baseURL` pinned; `trustedProxyHeaders: false` unless behind a proxy you control; platform-
  specific IP header configured.
- Tenant scoping comes from `session.session.activeOrganizationId`, never from the request.
- `checkRolePermission` appears only in UI code; every server decision uses
  `auth.api.userHasPermission` / `auth.api.hasPermission`. `adminUserIds` is empty or justified.
- `verifyApiKey` always passes `permissions`; `enableSessionForAPIKeys` only with scoped keys.
- `BETTER_AUTH_SECRET` is >=32 chars, per-environment, absent from the repo and from
  `.env.example`.
- `accountLinking.trustedProviders` lists verified-email providers only;
  `allowDifferentEmails: false`; `requireLocalEmailVerified: true`.
- Rate limiting uses shared storage with `customRules` on `/sign-in/email`, `/forget-password`,
  and `/two-factor/*`.
- No user-scoped data inside a shared `'use cache'` / `unstable_cache` entry.

See also `secaudit:auth` (middleware boundary, Server Actions, cookies, CSRF, enumeration),
`secaudit:privilege-escalation` (roles from the client, admin surface), `secaudit:rate-limiting`,
`secaudit:secrets`, and `secaudit:web-vulns` (IDOR, open redirect).

## Sources

- https://better-auth.com/docs/integrations/next -- getSessionCookie is optimistic only; auth.api.getSession with headers
- https://better-auth.com/docs/reference/security -- secret requirements, CSRF/origin protection, trusted origins
- https://better-auth.com/docs/concepts/session-management -- cookieCache, freshAge, disableCookieCache, revocation
- https://better-auth.com/docs/concepts/cookies -- signed session cookie, cookie cache contents
- https://better-auth.com/docs/concepts/rate-limit -- production-only default, memory storage, customRules
- https://better-auth.com/docs/reference/options -- advanced.disableOriginCheck, trustedProxyHeaders, ipAddressHeaders
- https://better-auth.com/docs/concepts/users-accounts -- accountLinking, trustedProviders, allowDifferentEmails
- https://better-auth.com/docs/plugins/organization -- hasPermission, activeOrganizationId, client checkRolePermission
- https://better-auth.com/docs/plugins/admin -- adminUserIds, userHasPermission, impersonation permission
- https://better-auth.com/docs/plugins/api-key -- verifyApiKey permissions, enableSessionForAPIKeys
- https://better-auth.com/docs/installation -- BETTER_AUTH_SECRET generation and length
- https://nextjs.org/docs/app/guides/authentication -- verify sessions in the data access layer, not middleware
- https://nextjs.org/docs/app/api-reference/file-conventions/proxy -- middleware.ts renamed to proxy.ts; Node.js runtime only
- https://nextjs.org/docs/app/api-reference/directives/use-cache -- cache keyed by arguments; 'use cache: private'
