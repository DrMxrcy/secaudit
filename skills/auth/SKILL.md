---
name: auth
description: Audits authentication and authorization — JWT verification, why Next.js middleware is not a security boundary, Server Actions as public endpoints, session management, and the auth-vs-authorization distinction. Use whenever writing or reviewing login, sessions, JWTs, protected routes, Server Actions, or access-control checks, or when auditing whether the app can be accessed without proper authorization. For request throttling on these endpoints, see secaudit:rate-limiting.
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
