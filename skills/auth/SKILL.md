---
name: auth
description: Audits authentication and authorization — JWT verification, why Next.js middleware is not a security boundary, Server Actions as public endpoints, session management, the auth-vs-authorization distinction, Clerk specifics (where auth() and clerkMiddleware checks belong, unsafeMetadata as a client-writable role store, Svix webhook verification, Clerk with Convex), and Auth.js/NextAuth specifics (the July 2026 advisory set and its fixed versions, provider-unbound state/nonce/PKCE check cookies, the !!auth fail-open, allowDangerousEmailAccountLinking, trustHost, AUTH_SECRET, JWT-claim roles and callbacks leaking provider tokens, the Credentials provider, adapter Account tables), and multi-host apps (host-only __Host- cookies per host, single-use cross-host session handoff tokens bound to user, target host and browser, verified-host return-URL allowlists, logout across hosts, custom-domain TXT verification and dangling-domain takeover, hashed session tokens). Use whenever writing or reviewing login, sessions, JWTs, protected routes, Server Actions, or access-control checks, when one app serves several hosts or customer custom domains, when the project uses Clerk (@clerk/nextjs, clerkMiddleware, ClerkProvider) or Auth.js/NextAuth (next-auth, @auth/core, NextAuth(, AUTH_SECRET), or when auditing whether the app can be accessed without proper authorization. For request throttling on these endpoints, see secaudit:rate-limiting.
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

The framework parses the action request before any of that runs, so a parsing bug hits even a
fully guarded action — `GHSA-p3m5-59mp-jv5r` (2026-10-14, DoS by CPU exhaustion in App Router
Server Action parsing). The Next.js version is part of the Server Action check; see
`secaudit:framework-versions`.

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

If the app runs its own OAuth/OIDC flow ("Sign in with X" via `openid-client`, `arctic`/`lucia`
patterns, or a hand-written `/callback`), the login-CSRF defence is the `state` parameter bound
per flow rather than a form token, and it pairs with PKCE, ID-token validation and account-linking
rules — see `secaudit:oauth-oidc-security`.

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

## Multi-Host Sessions, Cross-Host Handoff, and Custom Domains

One app, several hosts: a portal on the main host, a host per community or tenant (a subdomain, or
a customer's own domain), and sign-in that happens on only one of them. Session Cookie Security,
CSRF and Session Fixation above still apply on every host. This section covers what crossing hosts
adds. The OAuth flow on the main host belongs to `secaudit:oauth-oidc-security`, and deciding which
`Host` header to believe belongs to `secaudit:proxy-trust` §3.

Review grep heuristics: `domain:` in cookie options, `Domain=`, `__Host-`, `handoff`, `transfer`,
`?token=`, `searchParams.get("token")`, `returnTo`, `endsWith(`, `resolveTxt`, `on_demand_tls`,
`customDomain`, `familyId`, `revokedAt`.

### 1. One Host-Only `__Host-` Cookie per Host, and Session Rows Bound to Their Host

**What to look for:** a session cookie set with `domain: ".example.com"` so that "every host
shares the login"; a session cookie without the `__Host-` prefix; a session lookup by token alone,
so a row issued on one host is accepted on any other; code that falls back to an unprefixed name
(`get("__Host-session") ?? get("session")`).

**Why it's exploitable:** RFC 6265bis §4.1.2.3 draws the line: "If the server omits the Domain
attribute, the user agent will return the cookie only to the origin server", while `Domain=
site.example` sends it to "site.example, www.site.example, and www.corp.site.example". §8.6 gives the
other half: "Cookies do not provide integrity guarantees for sibling domains (and their
subdomains)... The foo.site.example server can set a cookie with a Domain attribute of
"site.example"... In the worst case, bar.site.example will be unable to distinguish this cookie from
a cookie it set itself." On a community platform the sibling host belongs to somebody else. Any
subdomain that serves community-authored HTML or JS, and any subdomain taken over (§5), can toss a
cookie at the parent domain to fix the victim's session there. A parent-domain cookie also reaches
the server behind every one of those subdomains on every request. This is the reason GitHub moved
Pages to `github.io`, "mitigating phishing attacks and cross-domain cookie vulnerabilities", and its
post notes that "the Cookie header only contains the name and value" with no domain attached.

The `__Host-` prefix is the browser-enforced fix. §4.1.3.2: "If a cookie's name begins with a
case-sensitive match for the string __Host-, then the cookie will have been set with a Secure
attribute, a Path attribute with a value of /, and no Domain attribute... The lack of a Domain
attribute ensures that the cookie's host-only-flag is true, locking the cookie to a particular host,
rather than allowing it to span subdomains." 6265bis also requires that "UAs MUST match cookie
name prefixes case-insensitively", so a sibling cannot plant `__HOST-session; Domain=...` either. A tossed cookie therefore can never carry your session
cookie's name. That only protects you if the server reads nothing but the prefixed name.

Host-only cookies are not enough on their own. A customer who owns a custom domain controls its
DNS, so they can point it at their own server and get a valid certificate for it whenever they
like. Microsoft's takeover guidance says exactly that about hijacked subdomains: "a threat actor
can use the hijacked subdomain to apply for and receive a valid SSL certificate. Valid SSL
certificates grant them access to secure cookies". So a cookie issued on a custom domain must be
worthless on every other host. Store the issuing host on the session row and require it on every
lookup.

```ts
// BAD: one cookie for every host, and a session row that is valid anywhere
(await cookies()).set("session", token, { domain: ".example.com", httpOnly: true, secure: true });
const [s] = await db.select().from(sessions).where(eq(sessions.tokenHash, sha256(token)));

// GOOD: host-only cookie per host; the row only counts on the host that issued it
(await cookies()).set("__Host-session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
const host = await canonicalHost(req);  // Host matched against verified hosts, else 421 (proxy-trust §3)
const [s] = await db.select().from(sessions).where(and(
  eq(sessions.tokenHash, sha256(token)), eq(sessions.host, host),
  isNull(sessions.revokedAt), gt(sessions.expiresAt, sql`now()`))).limit(1);
```

If community subdomains sit under the portal's registrable domain, they are same-site with it, so
`SameSite` gives no protection between them (see CSRF above). Anything that serves community-authored
HTML or JS belongs on a separate registrable domain. The Public Suffix List's private section is not
a quick fix either: its guidelines say "Changes to the PSL may take time to percolate to clients",
and there is "no way to expedite."

### 2. The Cross-Host Handoff Token: Random, Hashed, Single-Use, Bound, POSTed

**What to look for:** a redirect to `https://<community>/auth/callback?token=...`; the main host's
session id copied to the target (`?sid=`); a handoff JWT valid for minutes and reusable; a raw token
in the table; a consume written as `SELECT` then `DELETE`; no `target_host` or browser binding on
the token row; a landing page that loads analytics or other third-party scripts.

**Why it's exploitable:** the handoff token is a bearer credential that buys a fresh session. Put it
in a query string and it leaks. OWASP's Session Management Cheat Sheet: an ID "included in the URL,
might disclose the session ID (in web links and logs, web browser history and bookmarks, the Referer
header or search engines)". RFC 9700 §4.2 and §4.3 say the same of authorization codes. A
`SELECT`-then-`DELETE` consume lets two concurrent redemptions both pass the `SELECT`. A token that
is not bound to its target host can be redeemed on another community or on the main host. A token
that is not bound to the browser can be redeemed by whoever reads it. It also works in reverse: an
attacker posts *their own* token into the victim's browser (login CSRF), so the victim then acts
inside the attacker's account, which is Session Fixation by another route. Copying the main
session's id puts one stolen value in force on two hosts and ends per-host revocation.

**Fix:**
- **Entropy and storage:** 32 bytes from `crypto.randomBytes`. Store only its SHA-256 (§6).
- **TTL in seconds:** e.g. 60 s, long enough to survive one redirect.
- **Bindings on the row:** user, session family (§4), target host, and the hash of a browser nonce.
- **Browser nonce:** before sending the browser to the main host, the target host sets a random
  `__Host-handoff` cookie and passes its hash along with the login request. The main host stores
  that hash on the token, and redemption compares it. A cross-site form POST does not carry `Lax`
  cookies, and RFC 6265bis §8.8.6 names this exact case: "the concluding step of a login flow may
  involve a cross-site top-level POST request to an endpoint; this endpoint expects a recently
  created cookie containing transactional state information... "Lax" enforcement is not
  appropriate". So this one cookie is `SameSite=None; Secure`, short-lived, and holds only the
  nonce. (`None` is needed only when the target is cross-site, i.e. a customer custom domain; for a
  subdomain of the main site the POST is same-site and `Lax` is enough.)
- **Atomic consume:** `DELETE FROM handoff_tokens WHERE token_hash=$1 AND target_host=$2 AND
  expires_at > now() RETURNING user_id, family_id, nonce_hash`. Under Read Committed, "If the first
  updater commits, the second updater will ignore the row if the first updater deleted it", so
  exactly one caller gets the row. `UPDATE ... SET used_at = now() WHERE ... AND used_at IS NULL
  RETURNING ...` is equivalent if you need an audit trail.
- **Delivery:** an auto-submitting `<form method="post">`, so the token travels in the body. The
  target's handler answers with a 303 to a clean path. A URL fragment is the fallback: it "is
  separated from the rest of the URI prior to a dereference" (RFC 3986), so it never reaches the
  server, and RFC 9110 says the Referer "MUST NOT include the fragment". But it does land in history
  and any script on the page can read it, so read it once, `history.replaceState` it away, and POST
  it same-origin.
- **Landing page:** `Referrer-Policy: no-referrer` (RFC 9700 §4.2.4: it "completely suppresses the
  Referer header in all requests originating from the resulting document"), `Cache-Control:
  no-store`, and no third-party resources.
- **Mint a new session on the target**, with its own token and `host` (Session Fixation above).

```ts
// main host, after its own OAuth callback: mint for a host that §3 already resolved
const raw = randomBytes(32).toString("base64url");
await db.insert(handoffTokens).values({ tokenHash: sha256(raw), userId: s.userId,
  familyId: s.familyId, targetHost: target.host, nonceHash: login.nonceHash,
  expiresAt: sql`now() + interval '60 seconds'` });
// respond with an auto-submitting POST form carrying `raw` to the target's /auth/handoff;
// headers: Referrer-Policy: no-referrer, Cache-Control: no-store

// app/auth/handoff/route.ts on the community host
export async function POST(req: NextRequest) {
  const host = await canonicalHost(req);                       // 421 for unverified hosts
  const raw = String((await req.formData()).get("token") ?? "");
  const nonce = req.cookies.get("__Host-handoff")?.value ?? "";
  const [t] = await db.delete(handoffTokens).where(and(
    eq(handoffTokens.tokenHash, sha256(raw)), eq(handoffTokens.targetHost, host),
    gt(handoffTokens.expiresAt, sql`now()`))).returning();     // single use: one winner
  const a = Buffer.from(sha256(nonce)), b = Buffer.from(t?.nonceHash ?? "");
  if (!t || !nonce || a.length !== b.length || !timingSafeEqual(a, b)) // timingSafeEqual throws on length mismatch
    return new Response("Sign-in link expired", { status: 400 }); // nonce cookie left to expire: a forged
                                                                   // cross-site POST can't clear it
  const token = randomBytes(32).toString("base64url");          // new session, never a copy
  await db.insert(sessions).values({ tokenHash: sha256(token), userId: t.userId,
    familyId: t.familyId, host, expiresAt: sql`now() + interval '12 hours'` });
  const res = NextResponse.redirect(new URL("/", "https://" + host), 303);
  res.cookies.set("__Host-session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
  res.cookies.delete("__Host-handoff");                         // only after a successful consume
  return res;
}
```

### 3. Target Host and Return URL: Parse, Then Exact-Match a Verified Row

**What to look for:** `host.endsWith("example.com")`, `.includes(`, a regex such as
`/example\.com$/`, `startsWith("https://example.com")`; a hard-coded or env-var host list instead
of the verified-domains table; a `returnTo` handed straight to `redirect()`.

**Why it's exploitable:** `evil-example.com` passes `endsWith("example.com")`, `example.com.evil.net`
passes `startsWith`/`includes`, and in `https://example.com@evil.net` the hostname is `evil.net`.
OWASP's redirect cheat sheet is direct: "Compare the parsed scheme, canonical host, and effective
port against an explicit allowlist... Reject userinfo and ambiguous input... Do not use raw prefix
or suffix matching". And the stakes here are higher than an open redirect. A login endpoint that
mints a handoff token for whatever host the link names will POST a live credential to the attacker.

```ts
// lib/target.ts: new URL() lowercases and punycodes the host and drops :443; it keeps a trailing dot
export async function resolveTarget(returnTo: string) {
  let u: URL;
  try { u = new URL(returnTo); } catch { return null; }
  if (u.protocol !== "https:" || u.username || u.password || u.port || u.hostname.endsWith("."))
    return null;
  const [d] = await db.select().from(domains)
    .where(and(eq(domains.hostname, u.hostname), eq(domains.status, "verified"))).limit(1);
  // re-parsing "//evil.net/x" against a base yields https://evil.net/x, so refuse protocol-relative paths
  if (!d || !/^\/(?![\/\\])/.test(u.pathname)) return null;
  const url = new URL("https://" + d.hostname);
  url.pathname = u.pathname; url.search = u.search;            // set fields; never concatenate and re-parse
  return { host: d.hostname, url };
}
```

Same-host `next`/`returnTo` handling is `secaudit:oauth-oidc-security` §2 and `secaudit:web-vulns`
Open Redirects.

### 4. Logout and Revocation Reach Every Host

**What to look for:** a logout that clears the cookie or deletes only the current row; no family id
linking the sessions one login spawned across hosts; a ban, role change or community-membership
removal that leaves sessions alive on other hosts; handoff tokens left outstanding after logout.

**Why it's exploitable:** host-only cookies mean the host handling the logout cannot clear the other
hosts' cookies. `Clear-Site-Data: "cookies"` reaches only "the entire registered domain, including
subdomains", never a customer's custom domain. OWASP: "deleting a cookie alone does not invalidate a
stolen copy of the session ID". Server-side revocation by family is the only lever that reaches
every host.

```ts
// logout on any host ends the whole login, on every host it reached
await db.update(sessions).set({ revokedAt: sql`now()` })
  .where(and(eq(sessions.familyId, current.familyId), isNull(sessions.revokedAt)));
await db.delete(handoffTokens).where(eq(handoffTokens.familyId, current.familyId));
// ban, role or permission change, removal from a community: the same, keyed by userId
await db.update(sessions).set({ revokedAt: sql`now()` }).where(eq(sessions.userId, userId));
```

Re-read roles at the point of use rather than caching them on the session
(`secaudit:privilege-escalation`). Keep account-level actions (linking, deletion, billing) on the
main host, so that a session on a community host authorizes only that community.

### 5. Custom-Domain Verification and the Dangling-Domain Lifecycle

**What to look for:** a domain marked verified because it resolves to you, or because an HTTP
challenge your own platform serves answered; a verification token that is static, derived from the
hostname or tenant id, or reused across claims; no unique constraint on the verified hostname;
verification done once and never repeated; community deletion that leaves the domain row or the
routing in place; on-demand TLS with no restriction; a worker that fetches `http://<customer
domain>` with plain `fetch`.

**Why it's exploitable:** a check that your own platform answers proves routing, not control. Once
a customer's CNAME points at you, the traffic arrives whoever claims the hostname on your side.
When a community is deleted and its domain still points at you, any new tenant can claim it. That
is subdomain takeover with you as the vendor. MDN describes takeover as a CNAME "but no host is
providing content for it" and tells hosting vendors to verify "that someone claiming a virtual host
actually has a legitimate claim to the domain name". The consequences Microsoft lists are cookie
harvesting, phishing, and a valid certificate in the attacker's hands. Two tenants verified for
one hostname make routing ambiguous: one tenant's content, cookies and handoffs land on the other's
host.

**Fix:** an ownership token in DNS, under a label that only the domain's controller can write.
Azure App Service uses an `asuid.{subdomain}` TXT record: "When such a TXT record exists, no other
Azure subscription can validate the custom domain or take it over". Cloudflare for SaaS uses a TXT
record at `_cf-custom-hostname.<hostname>` whose value comes from the API's `ownership_verification`
object.
- **Normalise before storing:** lowercase, punycode (`new URL()` / `url.domainToASCII`), strip one
  trailing dot, and reject IP literals, ports and wildcards, as well as your own apex and subdomains.
  Add a partial unique index, `CREATE UNIQUE INDEX ON domains (hostname) WHERE status = 'verified'`.
- **A fresh random token for every claim**, published at `_<yourapp>-challenge.<hostname>`. The
  token is public once published, so it needs to be unpredictable and unique per claim, not hashed.
- **Verify before** routing the host, issuing its certificate, or accepting handoffs for it. If you
  use Caddy's on-demand TLS, "On-demand TLS must be both enabled and restricted to prevent abuse".
  Caddy obtains a certificate when the `ask` endpoint returns a 2xx, so have it return 2xx only for
  verified rows.
- **Re-verify on a schedule and before certificate renewal.** Require the TXT record to stay in
  place (Cloudflare allows removing it after activation, and then you have nothing left to
  re-check). When verification lapses, because the domain changed hands or the records went, stop
  routing and issuing, and revoke `WHERE host = $1` (§1 makes that a one-liner).
- **On community deletion**, in one transaction: delete the domain rows, revoke the host's
  sessions, and purge its handoff tokens. Tell the customer to remove the CNAME. A later claim of
  that hostname must pass a new TXT check with a new token.

```ts
// worker/verify-domain.ts: DNS proves control; nothing here asks your own edge
import { resolveTxt } from "node:dns/promises";
export async function ownsDomain(d: { hostname: string; token: string }) {
  let records: string[][];
  try { records = await resolveTxt(`_portal-challenge.${d.hostname}`); } catch { return false; }
  return records.map((chunks) => chunks.join("")).includes(`portal-verify=${d.token}`);
}
```

Any HTTP request the worker makes to a customer-controlled hostname (a reachability probe, an HTTP
challenge) is SSRF: the customer controls the DNS, so the name can resolve to `169.254.169.254` or
to an internal address, or rebind between your check and your fetch. Use the resolve-then-pin,
no-redirect fetcher in `secaudit:web-vulns` §2, with egress isolated from internal services.

### 6. Session and Handoff Tokens at Rest: SHA-256 of a Random Token Is the Right Hash

**What to look for:** raw session or handoff tokens in the table; bcrypt or argon2 run on a random
session token; the opposite mistake, a fast hash over a low-entropy value (a 6-digit code, a
`Math.random()` string); raw tokens in logs.

**Why it matters:** OWASP's Session Management Cheat Sheet: "anyone who can read it can reuse
unexpired tokens... If read-only disclosure of the store is in your threat model, store a one-way
verifier instead... A fast hash is sufficient for these random verifiers; password hashing
algorithms are unnecessary." Generate them "using a CSPRNG with at least 128 bits of entropy; prefer
160 bits or more". The hash's limits are spelled out too: it "does not protect against stolen
cookies, modification of session records, or compromise of the application." OWASP also documents a
split design for stores where the lookup must not use the secret: the server looks up a public id,
hashes the supplied verifier, and must "compare it with the stored hash using a constant-time
comparison". Keep tokens out of logs ("log a
salted-hash of the session ID instead"). Randomness sources are covered in `secaudit:cryptography`
§2.

**Detection:**

```bash
# Session cookies scoped to a parent domain (should be host-only and __Host- prefixed)
grep -rnE "domain:\s*['\"]\.?[a-z0-9-]+\.|Domain=\.?[a-z0-9-]+\." --include='*.ts' --include='*.tsx' --include='*.js' .
# Unprefixed fallbacks that let a tossed cookie win
grep -rnE "\.get\(['\"](session|sid|token)['\"]\)" --include='*.ts' --include='*.tsx' .
# Handoff tokens in a query string
grep -rnE "searchParams\.get\(['\"](token|handoff|ticket|sid)['\"]\)|[?&](handoff|ticket|sid)=" --include='*.ts' --include='*.tsx' .
# Host allowlists built from string tricks
grep -rnE "(host|hostname|domain)[A-Za-z]*\.(endsWith|startsWith|includes)\(" --include='*.ts' --include='*.js' .
# Two-step consume instead of DELETE ... RETURNING
grep -rnE "handoff|transferToken|loginToken" --include='*.ts' --include='*.sql' . | grep -iE "select|findFirst|findUnique"
# Domain verification and on-demand TLS gates
grep -rnE "resolveTxt|resolveCname|on_demand_tls" --include='*.ts' --include='*.js' --include='Caddyfile' .
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

## Auth.js / NextAuth

Auth.js is the library formerly called NextAuth.js: `next-auth` v4, `next-auth` v5 (still shipping
as `5.0.0-beta.x`), both on `@auth/core`. Its docs now banner "The Auth.js project is now part of
Better Auth", and its security policy is narrow — "Security updates are only released for the
current latest version. Old releases are not maintained and do not receive updates." A
`5.0.0-beta.x` pinned months ago is a standing exposure, not a safe pin. Generic OAuth mechanics
live in `secaudit:oauth-oidc-security`; this section covers what Auth.js decides on your behalf,
and where its own defaults and documented examples are the finding.

Review grep heuristics: `next-auth`, `@auth/core`, `NextAuth(`, `auth()`, `!!auth`, `authorized:`,
`allowDangerousEmailAccountLinking`, `trustHost`, `AUTH_TRUST_HOST`, `AUTH_URL`, `AUTH_SECRET`,
`NEXTAUTH_SECRET`, `strategy: "jwt"`, `callbacks:`, `Credentials(`, `getToken(`,
`normalizeIdentifier`, `PrismaAdapter`, `SupabaseAdapter`.

### 1. The July 2026 Advisory Set: Check the Installed Version First

**What to look for:** in `package.json` or the lock file, `next-auth` below `4.24.15`, any
`next-auth` `5.0.0-beta.0` through `5.0.0-beta.31`, or `@auth/core` below `0.41.3` — four
advisories published together on 2026-08-12, two of them critical.

- **`CVE-2026-73419`** (`GHSA-x445-f3h2-j279`, moderate) — the OAuth `state`, `nonce` and PKCE
  check cookies are global and "not bound to the provider that created them", so "a check value
  minted during a sign-in started with one provider can satisfy the callback for a different
  provider"; fixed 4.24.15 / 5.0.0-beta.32, and 0.41.3 on `@auth/core`. See §2.
- **`CVE-2026-73421`** (`GHSA-8fpg-xm3f-6cx3`, critical) — a server configuration error makes
  existence checks on the `auth()` result fail open; `next-auth` 5.0.0-beta.0 through beta.31 only
  (v4 and `@auth/core` are not in range); fixed 5.0.0-beta.32. See §3.
- **`CVE-2026-73420`** (`GHSA-7rqj-j65f-68wh`, critical) — the built-in `defaultNormalizer`
  "validates an address before applying Unicode normalization", so `U+FF20` FULLWIDTH COMMERCIAL AT
  survives validation and then "canonicalizes to an ASCII at-sign under NFKC or NFKD", which can
  "deliver the passwordless sign-in link to an attacker-controlled recipient"; fixed 4.24.15 /
  5.0.0-beta.32, and 0.41.3 on `@auth/core`. Only where the built-in normalizer is used instead of a
  custom `normalizeIdentifier` *and* the sender normalizes — treat the version as the fix.
- **`CVE-2026-73418`** (`GHSA-xmf8-cvqr-rfgj`, high) — `getToken()` URL-decodes the bearer value
  before validating it, so "a single unauthenticated request" with malformed percent-encoding makes
  `decodeURIComponent()` throw: "per-request denial of service without exposing tokens"; fixed
  4.24.15 / 5.0.0-beta.32, and 0.41.3 on `@auth/core`.

Clean floors: **`next-auth@4.24.15`** or **`next-auth@5.0.0-beta.32`**, with **`@auth/core@0.41.3`**
underneath — adapters pull it transitively, so check the lock file, not just `package.json`.
`secaudit:framework-versions` carries the same floors.

### 2. Multi-Provider Account Linking on Unbound Check Cookies

**What to look for:** two or more OAuth providers in the `providers` array; a "connect another
account" / "link GitHub" flow that a signed-in user can start; any provider config with
`checks: ["none"]` or an OIDC provider whose `checks` no longer include `"pkce"`/`"nonce"`; a
version in the CVE-2026-73419 range from §1.

**Why it's exploitable:** the anti-CSRF values are meant to be transaction-specific — RFC 9700
requires the challenge or nonce to be bound "to the client and the user agent in which the
transaction was started" — and the binding to *which provider* was missing. The advisory's own
exploit conditions: "In a multi-provider
application that permits account linking while logged in, when one provider's authorization request
is observable and a target provider callback can be satisfied without a PKCE verifier, an attacker
can lure a victim into starting a legitimate same-origin flow and link the attacker's
target-provider account to the victim's Auth.js user. The linked provider grants the attacker
persistent sign-in to the victim's account, while cross-site request forgery alone is
insufficient." The result is a permanent second front door on someone else's account.

```typescript
// auth.ts — BAD: checks disabled to "fix" a callback error, on a version in range
providers: [GitHub({ ...creds, checks: ["none"] }), Google({ ...creds })]  // no state, no PKCE

// GOOD: on 4.24.15 / 5.0.0-beta.32, with the defaults left alone
providers: [GitHub({ ...creds }), Google({ ...creds })]
// Default is checks: ["pkce"] (plus "nonce" on OIDC, "state" when redirectProxyUrl is set). A
// callback that only works with checks: ["none"] is a wrong redirect_uri, not a checks bug.
```

Hand-rolled parts of the flow: `secaudit:oauth-oidc-security` §1 (per-flow binding), §4 (linking).

### 3. `!!auth` and `if (session)` Fail Open on a Config Error

**What to look for:** the documented `authorized` callback shape
`authorized: async ({ auth }) => !!auth`, `if (req.auth)`, `if (session)` — any gate that tests
only that the object *exists*; `next-auth` 5.0.0-beta.0 through beta.31.

**Why it's exploitable:** per CVE-2026-73421, "a non-OK session response is parsed into a truthy
error object instead of null, so checks such as `!!auth` and `if (req.auth)` evaluate to true for
unauthenticated requests." The trigger is not an attack — it is your own misconfiguration: "A
provider missing both the issuer and authorization endpoint triggers InvalidEndpoints, and an unset
`AUTH_SECRET` or another server configuration error can produce the same behavior." So a deploy that
forgets one environment variable does not break login loudly; it opens every gate quietly, and the
pattern that opens is the one the official protecting-routes page tells you to write.

```typescript
// auth.ts — BAD: the documented shape and the fail-open shape are the same line
export const { auth } = NextAuth({ providers: [GitHub],
  callbacks: { authorized: async ({ auth }) => !!auth } });   // truthy error object === "signed in"

// GOOD: upgrade, then assert on a field only a real session has
export const { auth } = NextAuth({ providers: [GitHub],
  callbacks: { authorized: async ({ auth }) => Boolean(auth?.user?.id) } });

// app/api/projects/route.ts — the same rule where the data actually moves
const session = await auth();
if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });
```

Fail closed on the config error too: validate `AUTH_SECRET` and every provider's credentials at
boot and refuse to start without them, rather than degrading into a truthy error object.

### 4. `allowDangerousEmailAccountLinking: true`

**What to look for:** the flag on any provider; a `signIn` callback that looks up an existing user
by `profile.email` and links; a provider with the flag whose `email_verified` claim is never read.

**Why it's exploitable:** the name is the warning, and the docs spell it out — "Automatic account
linking on sign in is not secure between arbitrary providers and is disabled by default ... it may
be desirable to allow automatic account linking if you trust that the provider involved has securely
verified the email address associated with the account." Some providers let a user edit their own
email claim without re-verification (nOAuth): the attacker sets their profile email to the
victim's, signs in, and lands inside the victim's account.

```typescript
// BAD: linking on an email the provider may never have verified
providers: [Google({ allowDangerousEmailAccountLinking: true })]

// GOOD: off; link only behind an explicit signed-in confirmation, and read the claim
providers: [Google({})]
callbacks: { async signIn({ profile }) { return profile?.email_verified === true; } }
```

Identity keys on `(issuer, sub)`, never on the email string — `secaudit:oauth-oidc-security` §4.

### 5. `trustHost` / `AUTH_TRUST_HOST` / `AUTH_URL`

**What to look for:** `trustHost: true` in the config, or `AUTH_TRUST_HOST=true` in the
environment, on a deployment that is not actually behind a proxy you control; `AUTH_URL` unset on a
non-Vercel host; v4's `NEXTAUTH_URL` missing in production.

**Why it matters:** "Auth.js relies on the incoming request's host header to function correctly",
and `AUTH_TRUST_HOST` "tells Auth.js to trust the `X-Forwarded-Host` header from the reverse proxy"
(only `VERCEL` and `CF_PAGES` are auto-detected). If that header can reach the app from anywhere but
a proxy that overwrites it, the attacker picks the host Auth.js thinks it is running on — the host
callback URLs and email links are built against. Set it only where a proxy strips and re-sets the
forwarded headers, and pin `AUTH_URL` to the canonical origin so the value never comes from the
request. The proxy side — which hops to trust, header stripping, forward-auth identity headers — is
`secaudit:proxy-trust`.

### 6. `AUTH_SECRET` Strength and Rotation

**What to look for:** a short, guessable, or committed `AUTH_SECRET` / `NEXTAUTH_SECRET`; the same
secret shared across preview and production; no secret at all in a v4 dev deployment.

**Why it matters:** the secret "is used to encrypt cookies and tokens. It should be a
cryptographically secure random string of at least 32 characters" (`npx auth secret`, or
`openssl rand -base64 33`). Under a JWT session strategy it is the *only* thing between an attacker
and a forged session cookie; in v4 the development fallback is a hash of the options object —
deterministic, derivable from config. Rotate through the array form rather than swapping the value:
`secret: [NEW, OLD]` — "the first secret that successfully decrypts the JWT will be used ... The
newer secret should be added to the start of the array" — then drop the old one once your session
lifetime has elapsed. Preview deployments get their own secret (`secaudit:deployment`).

### 7. JWT Claims as Roles, and Callbacks That Ship Provider Tokens to the Browser

**What to look for:** `session: { strategy: "jwt" }` plus a `role`, `plan` or `isAdmin` read off
`session.user` as the authorization decision; a `jwt` callback copying `account.access_token` into
the token and a `session` callback copying it onward; the `update` trigger writing client `session`
data into the token.

**Why it's exploitable:** a JWT session is a snapshot — the role in it was true when the token was
minted, so a user demoted, banned or downgraded mid-session keeps the old claim until it expires:
fine as a UI hint, wrong as the gate on a destructive action. And the `session` callback's return
value "will be exposed to the client, so be careful what you return here!", while the official
example for passing provider data through is literally `session.accessToken = token.accessToken` —
a live provider credential handed to the browser. Data from `useSession().update()` lands in the
`jwt` callback's `session` parameter, where the docs are explicit: "you should validate this data
before using it."

```typescript
// auth.ts — BAD: provider token forwarded to the browser, role trusted from the token
callbacks: {
  async jwt({ token, account }) { if (account) token.accessToken = account.access_token; return token; },
  async session({ session, token }) { session.accessToken = token.accessToken; return session; },
}                                        // ^ the doc's own example: "exposed to the client"
// app/actions/delete-org.ts
if (session.user.role !== "admin") throw new Error("Forbidden");   // stale claim, minted at login

// GOOD: token stays server-side; authority re-read at the point of use
callbacks: {
  async jwt({ token, account, user }) {
    if (account?.access_token && user) await vault.put(user.id, account.provider, account.access_token);
    return token;                              // no provider credential in the cookie
  },
  async session({ session, token }) { session.user.id = token.sub!; return session; },
}
// app/actions/delete-org.ts — current authority, read server-side
const member = await db.member.findUnique({ where: { userId: session.user.id, orgId } });
if (member?.role !== "admin") throw new Error("Forbidden");
```

Encrypting a stored provider token and binding it to its row: `secaudit:oauth-oidc-security` §5.

### 8. Credentials Provider: The Security Parts Are Yours

**What to look for:** a `Credentials` provider whose `authorize()` compares passwords with `===`
or a plain string compare; no throttling in front of `signIn("credentials", ...)`; `authorize()`
returning a user object on a lookup miss; a distinct error for "no such user".

**Why it matters:** Auth.js says so directly — "By default, the Credentials provider does not
persist data in the database. However, you can still create and save any data in your database, you
just have to provide the necessary logic, eg. to encrypt passwords, add rate-limiting, add password
reset functionality, etc." Nothing in the library hashes, throttles or locks out, and the provider
is JWT-sessions-only, so a weak `AUTH_SECRET` (§6) compounds with it. The account-enumeration and
session-fixation sections above apply verbatim.

```typescript
// auth.ts — BAD: plaintext compare, unlimited attempts
Credentials({
  async authorize(c) {
    const user = await db.user.findUnique({ where: { email: c.email as string } });
    return user && user.password === c.password ? user : null;      // plaintext + timing oracle
  },
})
// GOOD: throttled, constant-work verification, one failure shape
Credentials({
  async authorize(c, req) {
    const parsed = credentialsSchema.safeParse(c);
    if (!parsed.success) return null;
    if (!(await limiter.allow(`login:${ipOf(req)}:${parsed.data.email}`))) return null; // IP + user
    const user = await db.user.findUnique({ where: { email: parsed.data.email } });
    const ok = await argon2.verify(user?.hash ?? DUMMY_ARGON2_HASH, parsed.data.password);
    return user && ok ? { id: user.id, email: user.email } : null;
  },
})
```

Hash parameters: `secaudit:cryptography`; limiter placement: `secaudit:rate-limiting`.

### 9. `auth()` in Middleware (or `proxy.ts`) Is Still Not the Boundary

**What to look for:** `export { auth as middleware } from "@/auth"` (Next.js 16: `proxy.ts`,
`export { auth as proxy }`) with a `config.matcher`, and route handlers, Server Actions and data
functions underneath that never call `auth()` again.

**Why it matters:** this is the middleware section at the top of this file wearing Auth.js's API.
Auth.js's own protecting-routes page: "You should not rely on the proxy exclusively for
authorization. Always ensure that the session is verified as close to your data fetching as
possible." Next.js agrees: "it should not be your only line of defense in protecting your data."
CVE-2025-29927 bypassed Next.js middleware outright with a spoofed header, and on an affected v5
beta the `authorized` callback it runs is the §3 fail-open shape. Keep it for redirects; put the
real check in every Server Action, route handler and data function, scoped to `session.user.id`.

### 10. Adapter Tables Hold Provider Tokens, and Sit in Your Database

**What to look for:** an adapter (`PrismaAdapter`, `SupabaseAdapter`, Drizzle) with the default
schema; an `Account` table reachable through a client-side Supabase key or a PostgREST-exposed
schema; no RLS on `accounts` / `sessions` / `users` / `verification_tokens`.

**Why it's exploitable:** the default `Account` row stores "`access_token`, `expires_at`,
`refresh_token`, `id_token`, `token_type`, `scope` and `session_state`" — live provider credentials,
as returned, with no encryption anywhere in the library. One over-broad Supabase policy, one SQL
injection, or one leaked read-only database URL therefore yields every user's Google or GitHub
token, not just session rows. The adapter also links accounts "automatically, only when they have
the same e-mail address, and the user is currently signed in" — the flow §2 and §4 describe.

Two fixes, in order: don't store what you don't use (trim the columns in the provider's `account()`
callback), and encrypt what remains before it reaches the table, bound to its row — AEAD with the
user id and provider as associated data. Then treat the adapter tables like any other sensitive
table: service-role access only, RLS denying the anonymous and authenticated roles, never reachable
through a client-side key. `secaudit:database` covers the policy side, and
`secaudit:oauth-oidc-security` §5 the token vault.

## Sources

- https://nvd.nist.gov/vuln/detail/cve-2025-29927 -- Next.js middleware authorization bypass
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
- https://github.com/advisories/GHSA-x445-f3h2-j279 -- CVE-2026-73419 Auth.js OAuth state/nonce/PKCE check cookies not bound to their provider; the account-linking exploit conditions
- https://github.com/advisories/GHSA-8fpg-xm3f-6cx3 -- CVE-2026-73421 config errors make existence checks on the auth() result fail open (next-auth 5 betas)
- https://github.com/advisories/GHSA-7rqj-j65f-68wh -- CVE-2026-73420 email normalizer validates before Unicode normalization (fullwidth @ magic-link hijack)
- https://github.com/advisories/GHSA-xmf8-cvqr-rfgj -- CVE-2026-73418 getToken() throws on a malformed Bearer header (per-request DoS)
- https://authjs.dev/security -- security updates only for the current latest version
- https://authjs.dev/reference/core/providers -- allowDangerousEmailAccountLinking; the default checks array
- https://authjs.dev/reference/core -- trustHost; secret as an array for rotation; jwt/session callback semantics
- https://authjs.dev/getting-started/deployment -- AUTH_SECRET length, AUTH_TRUST_HOST trusts X-Forwarded-Host, AUTH_URL
- https://authjs.dev/concepts/session-strategies -- JWT vs database sessions
- https://authjs.dev/concepts/database-models -- the Account row stores access_token / refresh_token / id_token; automatic linking by email
- https://authjs.dev/guides/extending-the-session -- what the session object does and does not persist
- https://authjs.dev/getting-started/authentication/credentials -- password hashing and rate limiting are the app's job
- https://authjs.dev/getting-started/session-management/protecting -- the authorized: !!auth pattern; do not rely on the proxy exclusively
- https://next-auth.js.org/configuration/options -- v4 NEXTAUTH_SECRET / NEXTAUTH_URL and the development secret fallback
- https://nextjs.org/docs/app/guides/authentication -- proxy/middleware should not be your only line of defense
- https://www.rfc-editor.org/rfc/rfc6265.html -- Domain attribute; host-only when omitted; §8.6 weak integrity for sibling domains
- https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/ -- RFC 6265bis (draft 22): __Host-/__Secure- prefixes, case-insensitive prefix matching, Lax vs cross-site top-level POST (§8.8.6), Public Suffix List
- https://publicsuffix.org/ -- Public Suffix List: cookie boundaries between registrable domains
- https://github.com/publicsuffix/list/wiki/Guidelines -- PSL private-section submissions are slow and cannot be expedited
- https://github.blog/engineering/yummy-cookies-across-domains/ -- GitHub Pages moved to github.io over cookie tossing from subdomains
- https://www.rfc-editor.org/rfc/rfc9700.html -- OAuth 2.0 Security BCP: credential leakage via Referer (§4.2) and browser history (§4.3); Referrer-Policy: no-referrer; form post
- https://www.rfc-editor.org/rfc/rfc9110.html -- §10.1.3 Referer must not include the fragment
- https://www.rfc-editor.org/rfc/rfc3986.html -- §3.5 the fragment is separated before dereference (never sent to the server)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy -- Referrer-Policy values; strict-origin-when-cross-origin default
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data -- "cookies" clears the registered domain only
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html -- parsed-URL allowlist; no prefix/suffix matching; reject userinfo
- https://www.postgresql.org/docs/current/transaction-iso.html -- Read Committed: a concurrent second DELETE ignores the already-deleted row
- https://orm.drizzle.team/docs/delete -- Drizzle delete().where().returning() on PostgreSQL
- https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover -- dangling DNS, cookie harvesting with a valid certificate, asuid TXT domain verification
- https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Subdomain_takeover -- subdomain takeover and vendor-side verification of domain claims
- https://github.com/EdOverflow/can-i-take-over-xyz -- which hosting services allow dangling-CNAME takeover
- https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/domain-support/hostname-validation/pre-validation/ -- _cf-custom-hostname TXT ownership verification
- https://caddyserver.com/docs/automatic-https -- on-demand TLS must be restricted; the ask endpoint
- https://caddyserver.com/docs/caddyfile/options -- on_demand_tls ask: 2xx authorizes issuance
- https://nodejs.org/api/dns.html -- dns.promises.resolveTxt returns TXT records as arrays of chunks
