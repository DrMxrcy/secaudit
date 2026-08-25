---
name: auth
description: Audits authentication and authorization — JWT verification, why Next.js middleware is not a security boundary, Server Actions as public endpoints, session management, the auth-vs-authorization distinction, and Clerk specifics (where auth() and clerkMiddleware checks belong, unsafeMetadata as a client-writable role store, Svix webhook verification, Clerk with Convex). Use whenever writing or reviewing login, sessions, JWTs, protected routes, Server Actions, or access-control checks, when the project uses Clerk (@clerk/nextjs, clerkMiddleware, ClerkProvider), or when auditing whether the app can be accessed without proper authorization. For request throttling on these endpoints, see secaudit:rate-limiting.
license: MIT
---

# Authentication & Authorization

## When to Use

- Writing or reviewing login, registration, sessions, or JWT handling.
- Protecting routes, Server Actions, Route Handlers, or RPC endpoints.
- Auditing whether the app authenticates AND authorizes (verifies ownership, not just login).
- (For throttling auth endpoints, see `secaudit:rate-limiting`.)

## JWT Handling

- **Use `jwt.verify()`, never `jwt.decode()` alone.** `decode` reads the payload without checking
  the signature — an attacker can forge any payload.
- **Explicitly reject `"alg": "none"`.** Some JWT libraries accept unsigned tokens if the algorithm
  is set to `"none"`. Your verification must reject this.
- **Validate issuer, audience, and expiration** — not just the signature.

```typescript
// BAD: reads token without verifying signature
const payload = jwt.decode(token);

// GOOD: verifies signature, rejects tampered tokens
const payload = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'your-app',
});
```

## Next.js Middleware Is NOT a Security Boundary

**This is the #1 auth mistake in vibe-coded Next.js apps.**

Next.js middleware runs at the edge and is convenient for auth checks, but it is
**architecturally incapable of being a reliable sole auth layer**:

- **CVE-2025-29927 (CVSS 9.1):** Middleware completely bypassed via a spoofed
  `x-middleware-subrequest` header. Affected versions 11.1.4 through 15.2.2 (fixed in 12.3.5 /
  13.5.9 / 14.2.25 / 15.2.3). See `secaudit:framework-versions`.
- **CVE-2025-55182 (React2Shell, CVSS 10.0):** React Server Components RCE — unrelated to
  middleware, but reinforces that framework-level protections have limits.

Always verify auth again in **every** server-side entry point:
- Server Actions (they compile to public POST endpoints)
- Route Handlers (`app/api/`)
- Data access functions / database queries
- Database-level policies (RLS)

Middleware should direct traffic and do a first pass — like a building's front door. But every
room inside must have its own lock.

## Server Actions Are Public Endpoints

Server Actions compile into public POST endpoints. Anyone can call them with `curl`. AI assistants
frequently generate Server Actions that assume they're only called by the UI:

```typescript
// BAD: no auth check, no input validation
'use server';
export async function deleteItem(id: string) {
  await db.items.delete({ where: { id } });
}

// GOOD: validates input, authenticates, and authorizes
'use server';
export async function deleteItem(input: unknown) {
  const parsed = schema.safeParse(input);
  if (!parsed.success) return { error: 'Invalid input' };

  const session = await auth();
  if (!session?.user) redirect('/login');

  // Authorize: verify ownership, not just login
  await db.items.deleteMany({
    where: { id: parsed.data.id, userId: session.user.id }
  });
}
```

Every Server Action needs three things at the top:
1. **Input validation** (Zod or similar runtime schema — see `secaudit:data-access`)
2. **Authentication** (verify the user is logged in)
3. **Authorization** (verify the user owns the resource)

## Authentication vs Authorization

"Logged in" is not "allowed." Authentication confirms *who* the user is; authorization confirms
*what they may touch*. The most common vibe-coding bug is checking authentication and then acting
on a client-supplied ID without verifying ownership. Always scope mutations and reads to the
authenticated user's ID (derived from the session/token, never from the request body).

## Session Cookie Security

**What to look for:** session/auth tokens in `localStorage`/`sessionStorage` or set via client-side
`document.cookie`; `Set-Cookie` missing `httpOnly`, `secure`, or `sameSite`; broad `Domain=`;
long-lived or never-expiring sessions; in Next.js, `cookies().set('session', ...)` with no options.

**Why it's exploitable:** a token in `localStorage` is readable by any JavaScript on the page, so one
XSS (or a compromised dependency) exfiltrates it instantly. An `httpOnly` cookie is not reachable from
`document.cookie`. Without `Secure` the cookie rides plain HTTP (MITM); without `SameSite` it rides
cross-site requests (CSRF); without the `__Host-` prefix a sibling subdomain can inject/overwrite it.

```ts
// app/lib/session.ts — BEFORE: token in localStorage, readable by any XSS
localStorage.setItem("token", jwt);

// AFTER: httpOnly, host-scoped, short-lived cookie set server-side
import { cookies } from "next/headers";
export async function startSession(sessionId: string) {
  (await cookies()).set("__Host-session", sessionId, {
    httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 60 * 30,
  }); // __Host- requires Secure, no Domain, Path=/. Store the id server-side with idle+absolute expiry.
}
```

OWASP idle-timeout guidance: 2-5 min (high-value) / 15-30 min (low-risk), enforced server-side.

## CSRF (Cross-Site Request Forgery)

**What to look for:** state-changing endpoints (POST/PUT/DELETE) authenticated by cookie with no
anti-CSRF token and no custom-header requirement; Next.js Server Actions mutating data on the session
cookie alone; naive double-submit (cookie compared to a field with no signature).

**Why it's exploitable:** CSRF applies to cookie-based (ambient) auth - the browser auto-attaches the
session cookie to a forged cross-site request, and the server can't distinguish it. `SameSite` is
defense-in-depth, not a fix: default `Lax` still allows top-level cross-site POST for cookies set within
the prior 2 minutes, and a compromised sibling subdomain is "same site."

```ts
// app/actions/transfer.ts — AFTER: synchronizer token (primary) + SameSite (defense-in-depth)
"use server";
import { cookies } from "next/headers";
import { timingSafeEqual } from "node:crypto";
export async function transfer(formData: FormData) {
  const sent = String(formData.get("csrfToken") ?? "");
  const expected = (await cookies()).get("__Host-csrf")?.value ?? "";
  if (!expected || sent.length !== expected.length ||
      !timingSafeEqual(Buffer.from(sent), Buffer.from(expected))) throw new Error("CSRF failed");
  // ... mutate
}
// For fetch/AJAX APIs, require a custom header (e.g. X-CSRF-Token) - browsers can't send it cross-site
// without a CORS preflight you don't grant.
```

OWASP order: use the framework's built-in CSRF protection; else a synchronizer token; for stateless,
the signed/HMAC double-submit (never the naive one). Always pair with `SameSite`.

## Passkeys / WebAuthn

**What to look for:** password-only login, or "MFA" that is SMS/TOTP only (phishable via real-time
relay); no FIDO2/WebAuthn option for high-value accounts; hand-rolled WebAuthn ceremonies.

**Why it matters:** WebAuthn replaces the shared secret with a per-site public/private keypair; the
private key never leaves the authenticator and the server stores only the public key, so a DB leak
yields nothing reusable. It is phishing-resistant by construction - credentials are origin-bound, so a
key registered at `yourapp.com` cannot be used at `yourapp.evil.com`. Use a maintained library
(e.g. `@simplewebauthn/server`); both registration and authentication ceremonies must verify a
server-issued challenge plus the expected origin and RP ID. Offer passkeys as primary login or a
phishing-resistant second factor.

## Session Fixation

**What to look for:** a login flow that keeps the same session identifier from before login (no
regenerate / new cookie); accepting a session ID supplied by the client; no new session ID on privilege
change. Express: `req.session.userId = ...` without `req.session.regenerate()`.

**Why it's exploitable:** the attacker plants a known session ID, gets the victim to authenticate under
it, and - because the ID didn't change at login - inherits the authenticated session. OWASP requires
renewing the session ID after any privilege-level change, and only accepting IDs the app generated.

```ts
// server/auth.ts — AFTER: rotate the session identifier on login
async function login(req, res) {
  const user = await verifyCredentials(req.body);
  await new Promise((ok, err) => req.session.regenerate(e => (e ? err(e) : ok(null)))); // new id
  req.session.userId = user.id;
}
// DB-session equivalent: delete the anonymous session row and create a fresh id at login.
```

## Account Enumeration

**What to look for:** different messages for "no such user" vs "wrong password"; registration that says
"email already in use"; reset that says "no account with that email"; different status codes per case;
running the password hash only when the user exists (timing leak).

**Why it's exploitable:** any observable difference (message, status code, or response time) lets an
attacker confirm which emails are registered, building a target list for credential stuffing and
phishing. OWASP requires a generic response regardless of which part failed.

```ts
// app/api/login/route.ts — AFTER: uniform message, status, and timing
const user = await db.user.findByEmail(email);
const ok = await bcrypt.compare(password, user?.hash ?? DUMMY_BCRYPT_HASH); // hash even if absent
if (!user || !ok) return json({ error: "Invalid email or password." }, 401);
// Registration: "If that email is new, we've sent a verification link."
// Reset: always 200 with "If that email is in our database, we've sent a reset link."
```

## Clerk

Clerk makes an auth check look like one line, which is why the line so often lands in the wrong
file. `auth()` returns an object and nothing forces you to read it; `clerkMiddleware` plus a route
matcher feels like the authorization decision; and one of the three metadata fields is writable by
the client on purpose. Everything above still applies unchanged — this section covers only what is
specific to Clerk.

Review grep heuristics: `auth()`, `auth.protect`, `currentUser`, `clerkMiddleware`,
`createRouteMatcher`, `sessionClaims`, `publicMetadata`, `unsafeMetadata`, `verifyWebhook`,
`CLERK_SECRET_KEY`, `orgId`, `orgRole`, `has(`.

### 1. `auth()` Result Never Checked, or Checked Only in a Layout

**What to look for:** `const { userId } = await auth()` with no branch on the result; a layout or
page that calls `auth.protect()` while the Server Actions and route handlers it renders call
neither; `currentUser()` whose `null` return is unhandled.

**Why it's exploitable:** a layout check protects the render, not the mutation. The Server Actions
and `app/api/*` handlers beneath it compile to public POST endpoints reachable with `curl` — the
same lesson as the middleware section above, applied to Clerk's API. And on an unauthenticated
request `auth()` simply returns a `userId` of `null`; with no branch the handler runs anyway and
`null` flows into the query as an ownership filter that matches whatever `null` matches.

```typescript
// app/actions/delete-post.ts — BAD: the layout checked, so this one "doesn't need to"
'use server';
export async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } });   // public POST: no identity, no ownership
}

// GOOD: identity re-derived here, ownership enforced in the same query
'use server';
import { auth } from '@clerk/nextjs/server';
export async function deletePost(postId: string) {
  const { userId } = await auth();
  if (!userId) throw new Error('Unauthorized');
  await db.post.deleteMany({ where: { id: postId, authorId: userId } });
}
```

`auth.protect()` is the throwing variant — it redirects in a page and returns an error response in
an action or handler. It is a fine authentication half. It is not the authorization half: scoping
the query to the caller is still your job.

### 2. `clerkMiddleware` + `createRouteMatcher` as the Only Gate

**What to look for:** all protection expressed as `createRouteMatcher([...])` and
`await auth.protect()` inside `clerkMiddleware`, with the resources themselves unguarded; a
`config.matcher` export that skips paths; routes added after the matcher was written.

**Why it's exploitable:** two separate failures wearing one name. The matcher is a *pattern* —
`['/dashboard(.*)']` does not cover `/admin`, `/api/internal`, or the route someone adds next
sprint, and a route the matcher misses has no check at all. And a route the matcher *does* hit is
only **protected**, not **authorized**: the middleware proves someone is signed in, after which
every signed-in user reaches the handler with identical standing. Clerk's own migration guide moves
these checks off the matcher and onto each resource for exactly this reason. The middleware section
above applies verbatim, CVE-2025-29927 included — that bypass skips the matcher entirely.

```typescript
// middleware.ts — fine as a first pass; NOT the boundary
import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
const isProtected = createRouteMatcher(['/dashboard(.*)']);   // /admin is not in this list
export default clerkMiddleware(async (auth, req) => {
  if (isProtected(req)) await auth.protect();
});

// app/api/admin/users/route.ts — the real gate, in the code path that actually runs
import { auth } from '@clerk/nextjs/server';
export async function GET() {
  const { isAuthenticated, has } = await auth();
  if (!isAuthenticated) return new Response('Unauthorized', { status: 401 });
  if (!has({ permission: 'org:users:read' })) return new Response('Forbidden', { status: 403 });
  // ... and still scope the query to what this caller may see
}
```

### 3. Identity Taken From the Request Instead of the Session

**What to look for:** a `userId` in a JSON body, form field, path segment, or search param; a client
component that reads `useUser()` and posts `user.id` to your API; `clerkClient()` lookups keyed by
an id the caller supplied.

**Why it's exploitable:** this is the most common Clerk shape and it is plain A01:2025 Broken Access
Control. The session cookie proves who the caller is; a `userId` in the payload proves only what
they typed. Swapping one id for another reads or writes someone else's row.

```typescript
// app/api/profile/route.ts — BAD: the caller names the account
const { userId, bio } = await req.json();
await db.profile.update({ where: { userId }, data: { bio } });   // any userId works

// GOOD: the body carries data only; identity comes from the session
import { auth } from '@clerk/nextjs/server';
const { userId } = await auth();
if (!userId) return new Response('Unauthorized', { status: 401 });
const { bio } = schema.parse(await req.json());
await db.profile.update({ where: { userId }, data: { bio } });
```

### 4. `unsafeMetadata` / `publicMetadata` Used as the Permission Store

**What to look for:** `unsafeMetadata.role`, `unsafeMetadata.plan`, `publicMetadata.isAdmin`, or a
`sessionClaims.metadata` derived from either, read as the authorization decision; any
`user.update({ unsafeMetadata: ... })` writing a value that later gates access.

**Why it's exploitable:** Clerk's three metadata fields carry three different trust levels and the
names do not make that obvious. `unsafeMetadata` is **readable and writable from the frontend by
design** — the signed-in user sets it from their own browser — so a role, plan, or entitlement
stored there is attacker-controlled, and self-promotion is one client call. `publicMetadata` is
writable only through the Backend API, which makes it sound as *storage*, but it is exposed to the
client and it remains a claim your server evaluates, not a permission your server obeys.
`privateMetadata` is the backend-only one. The sharp end: an admin action gated on
`unsafeMetadata.role === 'admin'` is not gated at all.

```typescript
// app/actions/delete-user.ts — BAD: the attacker writes the value that authorizes them
'use server';
import { currentUser } from '@clerk/nextjs/server';
export async function deleteUser(id: string) {
  const user = await currentUser();
  if (user?.unsafeMetadata?.role !== 'admin') throw new Error('Forbidden');  // client-writable
  await db.user.delete({ where: { id } });
}
// The entire bypass, run from the victim app's own client bundle:
//   await user.update({ unsafeMetadata: { role: 'admin' } });

// GOOD: the decision comes from a source Clerk will not let the client write
'use server';
import { auth } from '@clerk/nextjs/server';
export async function deleteUser(id: string) {
  const { has } = await auth();
  if (!has({ permission: 'org:users:delete' })) throw new Error('Forbidden');
  await db.user.delete({ where: { id } });
}
```

If entitlements must live in `publicMetadata`, write them only from the backend (a verified webhook
handler, a billing callback) and treat the read as an input to your own check. The general
role-from-the-client rule is `secaudit:privilege-escalation`.

### 5. Session Claims and JWT Templates Trusted Without Verification

**What to look for:** `sessionClaims` destructured and used without the token ever being verified; a
hand-rolled `jwt.decode` of the `__session` cookie; a JWT template whose custom claim is built from
`{{user.unsafe_metadata...}}`; a backend service accepting Clerk tokens with no `authorizedParties`
allowlist.

**Why it matters:** two distinct mistakes. First, a signed claim is only as trustworthy as the value
it was built from — a template claim populated from unsafe metadata is client-controlled data
wearing a server signature. Copy only fields the client cannot write, and keep templates narrow
(`{{user.public_metadata.onboardingComplete}}`, not the whole metadata blob). Second, when you
verify a Clerk token yourself instead of letting the SDK do it, the generic JWT rules at the top of
this file apply, plus the `azp` (authorized party) claim: Clerk's `authorizedParties` option checks
`azp` against an allowlist of your origins and is documented as the defense against the subdomain
cookie-leaking attack.

```typescript
// BAD: claims read straight off an unverified token
const claims = jwt.decode(req.cookies['__session']);
if (claims.metadata.role === 'admin') { /* ... */ }

// GOOD: SDK verification with an explicit origin allowlist
import { verifyToken } from '@clerk/backend';
const payload = await verifyToken(token, {
  jwtKey: process.env.CLERK_JWT_KEY,
  authorizedParties: ['https://app.example.com'],      // rejects tokens minted for other origins
});
// authenticateRequest() on the backend client takes the same authorizedParties option.
```

### 6. Clerk + Convex: Identity Must Come From `ctx.auth`

**What to look for:** a Convex `query`/`mutation`/`action` taking `userId`, `clerkId`, or
`tokenIdentifier` as an argument; a public function with no `ctx.auth.getUserIdentity()` call; a
`convex/auth.config.ts` whose `domain` / `applicationID` do not match the Clerk JWT template.

**Why it's exploitable:** Convex has no row-level security. Every non-`internal` function is an
internet-facing endpoint anyone can call with your deployment URL and arguments of their choosing,
so wrapping your React tree in `ClerkProvider` protects nothing on the server. An argument named
`userId` is just a string the caller picked.

```typescript
// convex/messages.ts — BAD: the caller declares who they are
export const listForUser = query({
  args: { userId: v.string() },
  handler: async (ctx, args) =>
    ctx.db.query('messages').withIndex('by_author', q => q.eq('author', args.userId)).collect(),
});

// GOOD: identity from the Clerk token Convex verified for this call
export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (identity === null) throw new Error('Not authenticated');
    return ctx.db.query('messages')
      .withIndex('by_author', q => q.eq('author', identity.subject))   // Clerk user id
      .collect();
  },
});
```

Every public function needs its own check — there is no middleware layer to fall back on. See
`secaudit:convex-security` for internal vs public functions, argument validators, and HTTP actions.

### 7. Webhooks: Verify the Svix Signature Over the Raw Body

**What to look for:** a `/api/webhooks/clerk` route that calls `await req.json()` and trusts the
payload; `verifyWebhook` in a try/catch that logs and continues; a signing secret read with a
`?? ''` fallback or with no presence check at boot.

**Why it's exploitable:** the endpoint is public and its path is guessable. Unverified, anyone can
POST a `user.created` or `user.updated` body and write straight into the user table your app treats
as the source of truth — inventing accounts, rebinding an email to an attacker-controlled Clerk id,
or flipping a mirrored `role`/`plan` column. That is account takeover through a route with no
login on it. Clerk signs webhooks with Svix and the signature covers the **raw** body, so parsing
first both breaks the check and hands unverified data to your code. A missing or empty signing
secret must fail closed, never skip verification.

```typescript
// app/api/webhooks/clerk/route.ts — BAD: unverified payload writes the user table
export async function POST(req: Request) {
  const evt = await req.json();                        // anyone can send this
  await db.user.upsert({ where: { clerkId: evt.data.id }, /* ... */ });
  return new Response('ok');
}

// GOOD: signature verified over the raw body before anything is trusted
import { verifyWebhook } from '@clerk/nextjs/webhooks';
export async function POST(req: Request) {
  let evt;
  try {
    evt = await verifyWebhook(req);                    // throws on a bad or missing signature
  } catch {
    return new Response('Invalid signature', { status: 400 });   // fail closed
  }
  if (evt.type === 'user.created') { /* mirror the user */ }
  return new Response('ok', { status: 200 });
}
```

`verifyWebhook` reads `CLERK_WEBHOOK_SIGNING_SECRET` from the environment (other Clerk SDKs also
accept it as an option); if it is absent the call fails, which is the behaviour you want — do not
paper over it with a default. Hand the request object to the helper rather than reconstructing one,
so the Svix timestamp headers stay intact for replay protection.

### 8. The Publishable Key Is Public; the Secret Key Is Not

**What to look for:** `CLERK_SECRET_KEY` (an `sk_...` value) in client code, in a `NEXT_PUBLIC_` /
`VITE_` / `EXPO_PUBLIC_` variable, in `app.json`, or committed to the repo.

**A false positive worth naming:** `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` (`pk_test_...` /
`pk_live_...`) is **designed** to ship in the bundle — it identifies your Clerk instance to the
frontend and grants nothing on its own. Reporting it as a leaked credential burns the reader's
attention and teaches them to skim the next finding. The secret key is the one that acts as your
application against the Backend API: server-side only, and rotate it in the Clerk dashboard if it
ever reached a client. See `secaudit:secrets`. In Expo apps, keep Clerk's token cache in
`expo-secure-store` rather than AsyncStorage — `secaudit:expo-security` covers that and the
`EXPO_PUBLIC_` rules.

### 9. Organizations: Membership and Role Checked Server-Side, Per Operation

**What to look for:** an `orgId` / `organizationId` arriving in a body, param, or header and used to
scope a query; `useOrganization()` output posted to the server; a role string sent by the client;
`has({ role })` called only in the component that hides a button.

**Why it's exploitable:** an org id in a request is a claim, not proof of membership — accept one
and any signed-in user reads any tenant's rows, a cross-tenant IDOR. The active organization lives
in the session: `auth()` returns `orgId` and `orgRole` for it. Check the role or permission on the
server for each operation rather than once at sign-in, so a member demoted mid-session loses access
at the next call.

```typescript
// app/api/invoices/route.ts — BAD: the caller picks the tenant
const { orgId } = await req.json();
return Response.json(await db.invoice.findMany({ where: { orgId } }));

// GOOD: tenant and role both derived from the session
import { auth } from '@clerk/nextjs/server';
const { isAuthenticated, orgId, has } = await auth();
if (!isAuthenticated) return new Response('Unauthorized', { status: 401 });
if (!orgId) return new Response('No active organization', { status: 400 });
if (!has({ role: 'org:admin' })) return new Response('Forbidden', { status: 403 });
return Response.json(await db.invoice.findMany({ where: { orgId } }));
```

One wrinkle: server-side `has({ permission })` resolves custom permissions only — Clerk's system
permissions are not in the session token, so check the role for those.

## Sources

- https://nvd.nist.gov/vuln/detail/CVE-2025-29927 -- Next.js middleware authorization bypass
- https://vercel.com/blog/postmortem-on-next-js-middleware-bypass -- middleware bypass mechanism + fixed versions
- https://nextjs.org/blog/security-nextjs-server-components-actions -- treat Server Actions as public endpoints
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html -- cookies, timeouts, session fixation
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html -- CSRF defenses
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html -- auth, WebAuthn, generic error messages
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html -- enumeration-safe reset flow
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie -- cookie attributes (httpOnly/Secure/SameSite/__Host-)
- https://www.w3.org/TR/webauthn-2/ -- Web Authentication (passkeys)
- https://clerk.com/docs/reference/nextjs/app-router/auth -- auth() Auth object: isAuthenticated, userId, orgId, orgRole, has
- https://clerk.com/docs/guides/secure/authorization-checks -- where Clerk authorization checks belong; has()
- https://clerk.com/docs/guides/development/upgrading/upgrade-guides/migrate-from-create-route-matcher -- moving checks off the middleware matcher onto each resource
- https://clerk.com/docs/reference/types/metadata -- public vs private vs unsafe metadata trust levels
- https://clerk.com/docs/guides/users/extending -- unsafeMetadata is writable from the frontend
- https://clerk.com/docs/guides/sessions/session-tokens -- custom session claims; keep JWT templates narrow
- https://clerk.com/docs/guides/sessions/manual-jwt-verification -- verifying __session yourself; the azp claim
- https://clerk.com/docs/reference/backend/verify-token -- verifyToken with jwtKey and authorizedParties
- https://clerk.com/docs/guides/development/webhooks/overview -- webhooks are Svix-signed; verify the signature
- https://clerk.com/docs/guides/development/webhooks/syncing -- verifyWebhook() in a route handler; mirroring user data
- https://clerk.com/docs/guides/development/integrations/databases/convex -- Clerk + Convex; ctx.auth.getUserIdentity()
- https://clerk.com/docs/guides/organizations/control-access/roles-and-permissions -- org roles/permissions; system permissions are not in the token
- https://clerk.com/docs/guides/development/clerk-environment-variables -- publishable key ships to the client; secret key does not
