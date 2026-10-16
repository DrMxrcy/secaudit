---
name: oauth-oidc-security
description: Audits OAuth 2.0 / OpenID Connect code the project writes itself — "Sign in with Google/GitHub/Discord/Apple/Microsoft" flows built with `openid-client`, with the deprecated `arctic` / `lucia` packages or their hand-rolled replacements, or with a hand-written `/callback` route that exchanges a `code`. Covers per-flow `state` and PKCE S256 binding, exact-match `redirect_uri` and open redirectors on `returnTo`/`next`, ID-token validation (`iss`, `aud`, `exp`, `nonce`, `alg` allow-list, JWKS by `kid`) and mix-up defence across multiple providers, account linking on unverified email (nOAuth), provider access/refresh tokens stored in plaintext or shipped to the client, and refresh-token rotation with reuse detection. Also covers the provider side — `oidc-provider` or a hand-rolled IdP: PKCE required for every client, hashed `client_secret`, single-use codes with family revocation, pairwise subjects, JWKS rotation, back-channel logout. Use whenever the project builds or reviews an OAuth/OIDC flow itself. For Auth.js/NextAuth, Clerk and Better Auth specifics see secaudit:auth.
license: MIT
---

# OAuth / OIDC Security (Sign in with X, and Running Your Own Provider)

OAuth is the protocol AI assistants generate confidently and wrongly, because the happy path is
short: build an authorize URL, take the `code` at your callback, POST it for a token, look up the
email, create a session. Every line of that works, and every security-relevant parameter in it is
optional as far as the compiler is concerned — `state`, `code_challenge`, `nonce`, the `iss` check,
the signature verification. A flow missing all five still logs you in, in development and in
production, until someone else logs in as you.

The ecosystem shifted under this code recently, which matters for what an assistant reaches for.
**Arctic was deprecated in July 2026** and **Lucia was deprecated in March 2025**; both sites now
publish single-file, copy-in replacement code instead of a package. `arctic` or `lucia` in a
`package.json` is therefore a stale-dependency finding *and* a signal that the flow is about to
become hand-rolled — exactly when the five optional parameters go missing. The replacement code is
the pattern to audit against: 32 random bytes hex-encoded as the PKCE verifier, its SHA-256 digest
base64url-encoded as an `S256` challenge, verifier and state in `HttpOnly; Secure; SameSite=Lax;
Max-Age=600` cookies scoped to that provider's callback path, both compared on the callback before
the code is redeemed.

Findings map to OWASP **A07:2025** (Authentication Failures) — a flow that authenticates the wrong
person — and **A01:2025** (Broken Access Control) — tokens and accounts reachable by someone who
should not reach them. `secaudit:auth` covers Auth.js/NextAuth, Clerk and the session layer;
`secaudit:better-auth-security` covers Better Auth; `secaudit:react-native-security` covers PKCE in
a mobile app with a custom URL scheme.

## When to Use

- `openid-client`, `oidc-provider`, `arctic`, `lucia`, `jose`, or `@oslojs/*` in `package.json`.
- A hand-written `/callback`, `/auth/*/callback` or `/api/auth/callback/*` route that receives a
  `code` and exchanges it at a token endpoint.
- A "Sign in with Google / GitHub / Discord / Apple / Microsoft" button whose flow the project owns.
- Anything that stores a provider `access_token` / `refresh_token`, or refreshes one on a schedule.
- The project *is* the identity provider: it issues codes, ID tokens or refresh tokens to clients.

Review grep heuristics: `client_secret`, `redirect_uri`, `code_challenge`, `grant_type=`,
`response_type`, `id_token`, `email_verified`, `jwt.decode`, `authorizationCodeGrant`,
`new Provider(`, and any `searchParams.get("code")`.

## 1. `state` and PKCE S256 on Every Flow, Bound Per Flow

**What to look for:** an authorize URL with no `state`, or a `state` generated and never compared on
the callback; no `code_challenge`; `code_challenge_method` omitted (it **defaults to `plain`** per
RFC 7636 §4.3); a verifier or state held in a module-level variable, an in-memory `Map`, or one
global cookie shared by every provider; a check cookie with no `Max-Age`, no `HttpOnly`, or
`SameSite=None`; and a callback that reads `state` from the URL twice instead of comparing it to
something the server stored.

**Why it's exploitable:** these are two different controls that AI-generated code drops together.

- **No `state` (or an uncompared one)** is login CSRF: the attacker starts a flow with their own
  provider account, harvests the callback URL and lures a victim to it. The victim's browser
  completes *the attacker's* flow and lands in the attacker's account — everything saved afterwards
  goes somewhere the attacker controls. RFC 9700 §2.1: "Clients MUST prevent Cross-Site Request
  Forgery (CSRF)."
- **No PKCE** leaves the code redeemable by whoever grabs it. RFC 9700 §2.1.1: "Public clients MUST
  use PKCE" (RECOMMENDED for confidential ones), and §4.5.3.1: "PKCE ensures that an attacker cannot
  redeem a stolen" code. A code leaked in a Referer header, a proxy log, browser history or an open
  redirector (§2) is a full account takeover without it.
- **A check value not bound to its flow** defeats both even when present. RFC 9700 §2.1.1 requires
  the challenge or nonce to be "transaction-specific and securely bound to the client and the user
  agent in which the transaction was started." Cookies shared across providers let a value minted in
  one provider's flow satisfy another provider's callback — the shape behind real multi-provider
  account-linking advisories, including one in Auth.js (see `secaudit:auth`).

**Fix:** mint `state` and a PKCE verifier per flow, store them in short-lived cookies scoped to
*that provider's* callback path, and compare both server-side before redeeming the code. Always send
`code_challenge_method=S256` — RFC 7636 §4.2: "If the client is capable of using `S256`, it MUST use
`S256`", and §7.2 forbids downgrading to `plain`. Send a `nonce` too on OIDC flows (§3).

```ts
// app/login/google/route.ts — BAD: no state, no PKCE, and the method defaults to "plain"
const url = new URL(AUTHORIZE_ENDPOINT);
url.search = new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID!,
  redirect_uri: `${origin}/login/google/callback`, response_type: "code",
  scope: "openid email profile" }).toString();
redirect(url.toString());          // nothing about this flow is remembered server-side
```

```ts
// app/login/google/route.ts — GOOD: per-flow state, nonce and S256 verifier in scoped cookies
import { createHash, randomBytes } from "node:crypto";
const b64url = (b: Buffer) => b.toString("base64url");
export async function GET() {
  const [state, nonce] = [b64url(randomBytes(32)), b64url(randomBytes(32))];
  const codeVerifier = randomBytes(32).toString("hex");            // 32 bytes, hex — 64 chars
  const challenge = b64url(createHash("sha256").update(codeVerifier).digest());

  const url = new URL(AUTHORIZE_ENDPOINT);
  url.search = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID!, response_type: "code",
    redirect_uri: "https://app.example.com/login/google/callback",
    scope: "openid email profile", state, nonce, code_challenge: challenge,
    code_challenge_method: "S256",                                 // never omit: default is plain
  }).toString();

  // Path-scoped per provider: a Discord flow's cookies are not visible to /login/google.
  const attrs = "Path=/login/google; HttpOnly; Secure; SameSite=Lax; Max-Age=600";
  const headers = new Headers({ Location: url.toString() });
  for (const [n, v] of [["state", state], ["nonce", nonce], ["verifier", codeVerifier]]) {
    headers.append("Set-Cookie", `google_oauth_${n}=${v}; ${attrs}`);
  }
  return new Response(null, { status: 302, headers });
}
// app/login/google/callback/route.ts — GOOD: compare before you redeem, and clear either way
const jar = await cookies();
const [storedState, storedVerifier] =
  [jar.get("google_oauth_state")?.value, jar.get("google_oauth_verifier")?.value];
const { searchParams } = new URL(req.url);
const [code, state] = [searchParams.get("code"), searchParams.get("state")];
if (!code || !storedVerifier || !state || state !== storedState) return bad(400);
jar.delete("google_oauth_state");                    // one-time use: a replayed callback fails
jar.delete("google_oauth_verifier");
const tokens = await exchangeCode(code, storedVerifier);
```

**Detection:**

```bash
# Authorize URLs with no challenge, and callbacks that read state but never compare it
grep -rlE 'response_type["\x27:=[:space:]]+code' --include='*.ts' . \
  | xargs grep -LE 'code_challenge_method' 2>/dev/null
grep -rlE 'searchParams\.get\(["\x27]code' --include='*.ts' --include='*.js' . \
  | xargs grep -LE 'storedState|cookies\(\)|getRequestCookie|session\.(state|oauth)' 2>/dev/null
# Per-flow secrets parked in process memory — not user-bound, and gone on the next instance
grep -rnE '^(const|let)[[:space:]]+(states?|verifiers?|nonces?)[[:space:]]*=[[:space:]]*(new Map|\{\})' \
  --include='*.ts' --include='*.js' .
```

## 2. Exact-Match `redirect_uri`, and No Open Redirector on `returnTo`

**What to look for:** a `redirect_uri` assembled from `req.headers.host`, `x-forwarded-host` or
`new URL(req.url).origin`; a wildcard or path prefix registered in the provider dashboard; and — the
more common half — a callback that finishes by redirecting to a `next` / `returnTo` / `callbackUrl`
parameter unvalidated, or guarded by a `startsWith("https://app.example.com")` check that
`https://app.example.com.evil.test` satisfies.

**Why it's exploitable:** RFC 9700 §4.1.3 requires the authorization server to compare the two URIs
with "Simple String Comparison" — "the authorization server MUST ensure that the two URIs are
equal", the only exception being a native app's localhost port. The client half fails first and more
often: §4.11.1 states "Clients MUST NOT expose open redirectors. Attackers may use open redirectors
to produce URLs pointing to the client and utilize them to exfiltrate authorization codes and access
tokens." A redirect chain through your own registered callback turns an exactly matched
`redirect_uri` into an attacker-chosen destination with the code riding along in the URL. A
host-derived `redirect_uri` is the same bug from the other side: whoever can set
`Host`/`X-Forwarded-Host` makes your server hand the provider a callback URL on their domain.

**Fix:** take the `redirect_uri` from per-environment configuration, never from the request. Treat
every post-login destination as untrusted: accept only a path (a single leading `/`, rejecting `//`
and `/\`) resolved against your own origin, or best, an allow-list of known destinations.

```ts
// BAD: the provider is told whatever the request claims, then the user is sent wherever the URL says
const redirectUri = `${req.headers.get("x-forwarded-host")}/callback`;
return Response.redirect(searchParams.get("next") ?? "/");   // open redirector; codes leak here
```

```ts
// GOOD: redirect_uri comes from config; the destination is proven same-origin
const REDIRECT_URI = process.env.OAUTH_REDIRECT_URI!;   // exactly what is registered, per env
function safeNext(next: string | null): string {
  // Reject protocol-relative ("//evil.test") and backslash tricks before resolving.
  if (!next?.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  const resolved = new URL(next, SELF_ORIGIN);
  return resolved.origin === SELF_ORIGIN ? resolved.pathname + resolved.search : "/";
}
```

**Detection:**

```bash
# redirect_uri derived from the request instead of configuration
grep -rnE 'redirect_uri[^\n]*(headers|host|origin|req\.|request\.)' \
  --include='*.ts' --include='*.js' --include='*.py' .
# Redirect targets from the query string, and origin checks done with startsWith (a prefix is not
# an origin)
grep -rnE '(redirect|Response\.redirect|res\.redirect)\(.*\b(next|returnTo|redirectTo|callbackUrl)\b' \
  --include='*.ts' --include='*.js' .
grep -rnE 'startsWith\(["\x27]https?://' --include='*.ts' --include='*.js' .
```

## 3. ID Token Validation, and Mix-Up Defence With `iss`

**What to look for:** `jwt.decode(id_token)` / `jose.decodeJwt()` with no verification; `verify()`
with no `algorithms` allow-list; a JWKS fetched once at boot, or key selection that ignores the
`kid` header; missing `aud` or `exp` checks; a `nonce` sent and never compared; and, with more than
one provider, a callback that decides which provider it is talking to from a query parameter rather
than from the flow it started.

**Why it's exploitable:** OIDC Core §3.1.3.7 makes each of these a client MUST. The issuer "MUST
exactly match the value of the `iss` (issuer) Claim"; the client "MUST validate that the `aud`
(audience) Claim contains its `client_id` value" and reject a token listing "additional audiences
not trusted by the Client"; "the current time MUST be before the time represented by the `exp`
Claim"; and if a nonce was sent, "a `nonce` Claim MUST be present and its value checked". Skip the
signature and an ID token is a JSON blob anyone can author, with the `sub` and `email` of their
choice. Accept any `alg` and you invite algorithm confusion (`secaudit:cryptography`); accept any
`aud` and you accept tokens minted for a different application entirely.

Mix-up is the multi-provider variant. With more than one authorization server RFC 9700 §2.1 makes a
defence **REQUIRED**: clients "SHOULD use the `iss` parameter as a countermeasure according to
[RFC9207], or ... the `iss` claim in the ID Token". §4.4.2 requires clients to "store, for each
authorization request, the issuer they sent the authorization request to and bind this information
to the user agent", and §4.4.2.1: "the client MUST compare the received issuer identifier to the
stored issuer identifier. If there is a mismatch, the client MUST abort." Without it, an attacker
operating (or compromising) one of your providers gets a code issued by *their* server redeemed at
*your* trusted provider's token endpoint, with your client credentials.

**Fix:** verify against a remote JWKS keyed by `kid`, pinning `issuer`, `audience` and an
`algorithms` allow-list; compare the `nonce` to the cookie from §1 and the issuer to the one stored
when the flow started.

```ts
// BAD: three claims trusted, zero verified
const claims = jwt.decode(tokens.id_token);            // no signature check at all
const user = await db.user.upsert({ where: { email: claims.email }, ... });
```

```ts
// GOOD: jose verifies the signature against the issuer's JWKS, selected by `kid`
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL(discovery.jwks_uri));   // caches, refetches on a new kid

const { payload } = await jwtVerify(tokens.id_token, JWKS, {
  issuer: ISSUER,                            // must equal the issuer identifier, exactly
  audience: process.env.GOOGLE_CLIENT_ID!,   // rejects tokens minted for another client
  algorithms: ["RS256"],                     // allow-list; never accept alg from the token
  clockTolerance: 30, maxTokenAge: "10 minutes",      // exp/iat checked by jwtVerify
});

// nonce and issuer are compared to what *this* flow stored (§1), not to what the token claims
if (payload.nonce !== storedNonce) throw new Error("nonce mismatch");
if (payload.iss !== storedIssuer) throw new Error("issuer mismatch — possible mix-up attack");
if (Array.isArray(payload.aud) && payload.aud.some(a => a !== process.env.GOOGLE_CLIENT_ID)) {
  throw new Error("untrusted additional audience");
}
```

**Detection:**

```bash
# Decoding instead of verifying
grep -rnE '(jwt|jsonwebtoken)\.decode\(|decodeJwt\(' --include='*.ts' --include='*.js' .
# Verification with no algorithm allow-list, and ID-token code with no issuer comparison anywhere
grep -rlE 'jwtVerify\(|jwt\.verify\(' --include='*.ts' . | xargs grep -LE 'algorithms' 2>/dev/null
grep -rlE 'id_token' --include='*.ts' --include='*.js' . | xargs grep -LE '\biss\b|issuer' 2>/dev/null
```

## 4. Account Linking Only on a Provider-Verified Email

**What to look for:** `db.user.findUnique({ where: { email } })` on the callback path followed by an
unconditional link or session issue; `email_verified` never read; a user table keyed on `email` with
no `(provider, providerAccountId)` pair; "link my other login" flows that take the new provider's
email as proof of ownership.

**Why it's exploitable:** this is nOAuth. An email in an ID token is an attribute, not an identity,
and some providers let the account holder set it freely — per Descope's write-up, "In Microsoft
Azure AD, the email claim is both mutable and unverified so it should never be trusted or used as an
identifier. A bad actor can change the Email attribute under 'Contact Information' in the Azure AD
account to control the 'email' claim in the returned identity JWT ... resulting in a complete
account takeover." The NextAuth FAQ gives the general rule: "Automatic account linking on sign in is
not secure between arbitrary providers ... this can be exploited by bad actors to hijack accounts by
creating an OAuth account associated with the email address of another user." The attacker never
touches your password reset, rate limits or MFA — they sign in through a provider you trust and land
in someone else's account.

Mind the standing of the rule: OIDC Core §5.1 defines what `email_verified` *means* ("the OP took
affirmative steps to ensure that this e-mail address was controlled by the End-User"), but does not
itself say you must require it before linking. That comes from the implementation guidance above —
treat it as the industry rule it is, not as a spec citation.

**Fix:** identity is `(issuer, sub)`. Store that pair per linked account and look up by it; use email
only as a *hint*, and auto-link on it only when the provider returned `email_verified === true` *and*
that provider is on a trust list you maintain. Otherwise make the user sign in with the existing
method first and link deliberately. Okta's linking guide has the same shape: match on the email,
then key the user on "the required, static `sub` claim".

```ts
// BAD: whoever can put an email in a claim owns that account
const user = await db.user.upsert({ where: { email: claims.email },
  create: { email: claims.email, name: claims.name }, update: {} });
await createSession(user.id);
```

```ts
// GOOD: look up by (issuer, sub); auto-link only on a verified email from a trusted issuer
const TRUSTED_VERIFIERS = new Set([GOOGLE_ISSUER]);          // issuers you have actually vetted
const [iss, sub] = [payload.iss as string, payload.sub as string];

const linked = await db.account.findUnique({ include: { user: true },
  where: { issuer_subject: { issuer: iss, subject: sub } } });
if (linked) return createSession(linked.user.id);

const existing = claims.email ? await db.user.findUnique({ where: { email: claims.email } }) : null;
if (existing) {
  if (claims.email_verified !== true || !TRUSTED_VERIFIERS.has(iss)) {
    // Do not link, do not sign in: make the user prove the existing account is theirs.
    return redirect("/login?link=confirm&provider=google");
  }
  await db.account.create({ data: { userId: existing.id, issuer: iss, subject: sub } });
  return createSession(existing.id);
}
// New user: still record the (issuer, sub) pair, not just the email.
```

**Detection:**

```bash
# Callback paths that resolve a user by email
grep -rnE '(findUnique|findFirst|upsert|where)[^\n]*email[^\n]*(claims|payload|profile|userinfo)' \
  --include='*.ts' --include='*.js' .
# email_verified never read anywhere in an app that consumes ID tokens
grep -rlE 'id_token|userinfo' --include='*.ts' --include='*.js' . \
  | xargs grep -LE 'email_verified' 2>/dev/null
# Account tables with no provider-subject pair
grep -rnE 'model Account|CREATE TABLE.*account' -A 12 --include='*.prisma' --include='*.sql' . \
  | grep -icE 'provider|subject|sub\b'
```

## 5. Provider Tokens at Rest: Encrypted, Bound to Their Row, Never Client-Side

**What to look for:** an `Account` / `oauth_tokens` table with `access_token` and `refresh_token` as
plain `text` columns; provider tokens copied into the session JWT or cookie, or returned to the
browser "so the frontend can call the API"; one `ENCRYPTION_KEY` for tokens, cookies and everything
else; AES-GCM used without AAD.

**Why it's exploitable:** a provider refresh token is a long-lived credential to a *third party* on
behalf of your user — Gmail, a Drive, a repo, a calendar, a Discord guild. Plaintext columns turn any
read-only leak (a logged query, a backup, an analytics sync, a read-only SQL injection) into standing
access to accounts you do not own and cannot revoke on the user's behalf. Shipping the token to the
client is worse: it lands in `localStorage`, devtools and error reports, and the provider's scope
becomes the browser's. Encrypting without binding is the subtle one — ciphertext with no associated
data can be copied between rows, so anyone with a write path swaps their token into your row, or
yours into theirs, and the decrypt succeeds.

**Fix:** AES-256-GCM per value, a fresh 12-byte IV each time, and the row's identity as AAD so the
ciphertext is only valid where it was written — Node's docs note `setAAD()` supplies "the additional
authenticated data (AAD) input parameter" for authenticated modes and that `getAuthTag()` "should
only be called after encryption has been completed using the `cipher.final()` method", so store IV,
tag and ciphertext together. Derive the token key with HKDF (RFC 5869), a purpose string in `info`,
so the token key is not the cookie key even though both come from one master secret. The plaintext
stays server-side: the browser gets your session, never the provider's token.

```ts
// BAD: a third-party credential in a text column, and then handed to the browser
await db.account.create({ data: { userId, access_token: tokens.access_token,
                                  refresh_token: tokens.refresh_token } });
session.accessToken = token.accessToken;     // now in every client bundle that reads the session
```

```ts
// lib/tokenVault.ts — GOOD: purpose-separated key, per-row AAD, IV+tag stored with the ciphertext
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
const MASTER = Buffer.from(process.env.TOKEN_MASTER_KEY_B64!, "base64");   // 32+ bytes, from KMS/env
// `info` is the purpose label: a different label yields a different, unrelated key (RFC 5869)
const KEY = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(0), "oauth-token-enc-v1", 32));
type Kind = "access" | "refresh";
const aad = (userId: string, provider: string, kind: Kind) =>
  Buffer.from(`${userId}:${provider}:${kind}`, "utf8");

export function sealToken(plain: string, userId: string, provider: string, kind: Kind) {
  const iv = randomBytes(12);                                   // never reuse an IV with a key
  const c = createCipheriv("aes-256-gcm", KEY, iv);
  c.setAAD(aad(userId, provider, kind));                        // binds ciphertext to this row
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return { iv, tag: c.getAuthTag(), ct, keyVersion: 1 };        // keyVersion makes rotation possible
}

// openToken() mirrors it: createDecipheriv, the same setAAD(...), setAuthTag(row.tag) before
// final() — and final() throws if the ciphertext was moved to another row.
```

**Detection:**

```bash
# Plaintext token columns in the schema
grep -rnE '(access_token|refresh_token|id_token)[[:space:]]+(String|Text|text|varchar)' \
  --include='*.prisma' --include='*.sql' --include='*.ts' .
# Provider tokens crossing to the client, and AES-GCM used without AAD
grep -rnE '(session|res|json)[^\n]*\.(access_?[Tt]oken|refresh_?[Tt]oken)[[:space:]]*=' --include='*.ts' .
grep -rlE 'aes-256-gcm' --include='*.ts' --include='*.js' . | xargs grep -LE 'setAAD' 2>/dev/null
```

## 6. Refresh-Token Rotation and Reuse Detection

**What to look for:** a stored refresh token read, used, and never replaced with the one the token
response returned; two paths (a request handler and a cron) refreshing the same row without a lock;
your own refresh tokens issued long-lived, never rotated, and revoked only by deleting the one
presented; an `invalid_grant` handled by retrying rather than by re-consenting.

**Why it's exploitable:** RFC 9700 §2.2.2 requires refresh tokens for public clients to "be
sender-constrained or use refresh token rotation", and §4.14.2 explains why rotation is a *detector*,
not hygiene: "If a refresh token is compromised and subsequently used by both the attacker and the
legitimate client, one of them will present an invalidated refresh token, which will inform the
authorization server of the breach" — and it then "will revoke the active refresh token". As the
client, dropping the rotated token or letting two workers race means you present an invalidated
token yourself: a self-inflicted outage indistinguishable from the attack. As the issuer, deleting
only the presented token throws the signal away — detection requires revoking the whole family.

**Fix:** persist whatever the token endpoint returns in the same transaction that consumed the old
value, and serialise refreshes per row (a conditional update on the stored value is enough). For
tokens your app issues, give every chain a family id and, on reuse of a consumed token, revoke the
family and force re-authentication.

```ts
// BAD: the rotated refresh_token is dropped, so the next refresh presents an invalidated one
await db.account.update({ where: { id: row.id }, data: { access_token: tokens.access_token } });
```

```ts
// GOOD: compare-and-set, so a concurrent refresh loses cleanly instead of corrupting the chain
const rotated = tokens.refresh_token ?? presented;
const updated = await db.account.updateMany({
  where: { id: row.id, refreshTokenFingerprint: row.refreshTokenFingerprint },   // CAS guard
  data: { ...sealToken(tokens.access_token, rotated),                               // §5
          refreshTokenFingerprint: sha256(rotated),
          expiresAt: new Date(Date.now() + tokens.expires_in * 1000) },
});
if (updated.count === 0) return readFreshRow(row.id);   // someone else rotated; use theirs
```

```ts
// GOOD: your own refresh tokens — rotation with family revocation on reuse
const stored = await db.refreshToken.findUnique({ where: { hash: sha256(presented) } });
if (!stored) return deny();
if (stored.consumedAt) {           // a consumed token came back: attacker or clone — kill the chain
  await db.refreshToken.updateMany({ where: { familyId: stored.familyId, revokedAt: null },
                                     data: { revokedAt: new Date() } });
  await auditLog("refresh_token_reuse", { userId: stored.userId, familyId: stored.familyId });
  return deny();
}
await db.$transaction([          // rotate: consume this one, issue its successor in the family
  db.refreshToken.update({ where: { id: stored.id }, data: { consumedAt: new Date() } }),
  db.refreshToken.create({ data: { familyId: stored.familyId, userId: stored.userId,
                                   hash: sha256(newToken), expiresAt: in30Days() } }),
]);
```

**Detection:**

```bash
# Refresh flows that never write the returned refresh_token back
grep -rlE 'grant_type[^\n]*refresh_token' --include='*.ts' --include='*.js' . \
  | xargs grep -LE 'refresh_token:.*tokens?\.|refreshToken:.*tokens?\.' 2>/dev/null
# Refresh-token tables with no family/rotation columns (no hits is the finding)
grep -rnE 'model RefreshToken|CREATE TABLE[^\n]*refresh_token' -A 12 \
  --include='*.prisma' --include='*.sql' . | grep -icE 'family|rotat|consumed|replaced'
```

## 7. `openid-client`: the `checks` Argument *Is* the Validation

**What to look for:** `authorizationCodeGrant(config, currentUrl)` called with two arguments;
`skipStateCheck: true`; `expectedNonce` omitted on an OIDC flow; the verifier, state or nonce read
from anywhere but server-side storage tied to this user agent.

**Why it's exploitable:** `authorizationCodeGrant(config, currentUrl, checks?,
tokenEndpointParameters?, options?)` takes the anti-CSRF checks — "CSRF Protection checks like PKCE,
expected state, or expected nonce" — as an *optional* parameter, and the docs are precise about what
absence means: `expectedState` "must match exactly. When undefined the expectation is that there is
no state in the authorization response", and `expectedNonce` likewise "When undefined the
expectation is that there is no nonce in the ID Token". Omitting them does not fail loudly — it
changes what the library expects, and the call succeeds, so a flow that looks fully library-managed
can have every control in §1 and §3 silently switched off.

**Fix:** persist state, nonce and verifier when you build the authorization URL (cookies as in §1,
or a server-side flow record) and pass all three back on the callback. The library already does the
§3 validation — give it the values to check against.

```ts
// BAD: two arguments; no state comparison, no PKCE verifier, no nonce expectation
const tokens = await client.authorizationCodeGrant(config, new URL(req.url));
```

```ts
// GOOD: every per-flow secret comes from the server-side record for this user agent
import * as client from "openid-client";

const flow = await consumeFlowCookie(req);          // state, nonce, verifier — one-time use
if (!flow) return new Response("Bad request", { status: 400 });
const tokens = await client.authorizationCodeGrant(config, new URL(req.url), {
  pkceCodeVerifier: flow.codeVerifier, expectedState: flow.state,
  expectedNonce: flow.nonce, idTokenExpected: true,
});
const claims = tokens.claims()!;                    // already signature-, iss-, aud- and exp-checked
```

**Detection:**

```bash
grep -rnE 'authorizationCodeGrant\([^,]+,[^,)]+\)|skipStateCheck' --include='*.ts' --include='*.js' .
grep -rlE 'authorizationCodeGrant' --include='*.ts' . | xargs grep -LE 'pkceCodeVerifier' 2>/dev/null
```

## 8. The Provider Side: `oidc-provider` or a Hand-Rolled IdP

**What to look for:** `new Provider(issuer, { ... })` with the defaults left alone; `client_secret`
stored as given and compared with `===`; no `pkce` block while confidential clients are registered;
`rotateRefreshToken` unset; authorization codes deleted only after a successful exchange;
`subjectTypes` left at `['public']`; a single signing key with no successor; no back-channel logout
endpoint, or one that accepts a logout token without validating it.

**Why it's exploitable:** each default is a reasonable library choice and a bad deployment choice.

- **PKCE.** `oidc-provider`'s `pkce.required` default returns `true` only when
  `client.clientAuthMethod === 'none'`, `false` otherwise — so a confidential client whose secret
  leaks (a mobile build, a front-end bundle, a committed `.env`) has nothing between a stolen code
  and a token. RFC 9700 §2.1.1 also requires the AS to "mitigate PKCE downgrade attacks": a code
  issued with a challenge must only be redeemable with a verifier.
- **Client secrets.** Stored in the clear, the client table is a credential dump; compared with
  `===`, it leaks length and prefix to a timing oracle. `clientAuthMethods` also ships `'none'`
  enabled — keep it only if you register public clients.
- **Codes.** A code redeemable twice is an account takeover for whoever replays it; single use must
  be enforced by the database, not by a `delete` after the exchange.
- **Refresh tokens.** `rotateRefreshToken: true` rotates "when used, with the current token marked
  as consumed", and "when a consumed refresh token is encountered an error shall be returned and
  the whole token chain (grant) is revoked" — the reuse detection RFC 9700 §4.14.2 asks for.
- **Subjects.** With public subjects every relying party sees the same `sub`, so two of them can
  correlate a user across products without consent. OIDC Core §8.1: pairwise means "the OpenID
  Provider MUST calculate a unique `sub` (subject) value for each Sector Identifier. The Subject
  Identifier value MUST NOT be reversible by any party other than the OpenID Provider."
  `oidc-provider` ships `subjectTypes: ['public']` and warns its `pairwiseIdentifier` "default helper
  implementation is a placeholder and MUST be replaced by a deployment before use".
- **Keys.** Swapping the signing key in place invalidates in-flight tokens and breaks every RP
  holding a cached JWKS. Overlap in the documented order instead: push the new key to the *end* of
  `keys`, reload all processes, move it to the *front*, reload again.
- **Logout.** A provider that never sends a back-channel logout leaves RP sessions alive after the
  user signs out at the IdP. Where your app is the RP, Back-Channel Logout §2.6 requires validating
  the logout token's signature, `alg` (never `none`), `iss`, `aud`, `iat` and `exp` as for an ID
  token, requiring a `sub` or `sid` and an `events` claim containing the back-channel logout member,
  and **rejecting any logout token that carries a `nonce`**.

**Fix:**

```ts
// BAD: every security-relevant default left as shipped — no pkce, no rotation, public subjects
const provider = new Provider(ISSUER, { clients: [{ client_id: "web",
  client_secret: "s3cret", redirect_uris: ["https://app.example.com/cb"] }] });
// GOOD: PKCE for everyone, rotation on, pairwise subjects, overlapping keys
import Provider from "oidc-provider";

const provider = new Provider("https://idp.example.com", {
  clients: [{
    client_id: "web",
    client_secret: process.env.WEB_CLIENT_SECRET!,      // store hashed in your own client table
    redirect_uris: ["https://app.example.com/cb"],      // exact strings, no wildcards (§2)
    backchannel_logout_uri: "https://app.example.com/backchannel-logout",
    backchannel_logout_session_required: true,
  }],
  clientAuthMethods: ["client_secret_basic", "private_key_jwt"],   // drop "none" if no public clients
  pkce: { required: () => true },                       // not just for clientAuthMethod === "none"
  rotateRefreshToken: true,                             // consumed-token reuse revokes the grant
  subjectTypes: ["public", "pairwise"],                 // the shipped default is ["public"] only
  pairwiseIdentifier: async (ctx, accountId, client) => // per-sector, salted: not RP-reversible
    createHash("sha256").update(client.sectorIdentifier).update(accountId)
      .update(process.env.PAIRWISE_SALT!).digest("base64url"),
  jwks: { keys: [currentSigningKey, nextSigningKey] },  // rotate by position, reload between steps
  ttl: { AuthorizationCode: 60, RefreshToken: 14 * 24 * 60 * 60 },
});
```

```ts
// GOOD (hand-rolled): single-use codes enforced by the database, reuse revokes the family
const [row] = await db.$queryRaw`
  UPDATE auth_codes SET consumed_at = now()
  WHERE code_hash = ${sha256(code)} AND consumed_at IS NULL AND expires_at > now()
  RETURNING client_id, user_id, family_id, code_challenge`;
if (!row) {   // expired, unknown, or a replay of a redeemed code — treat replay as compromise
  await revokeGrantFamilyByCodeHash(sha256(code));
  return tokenError("invalid_grant");
}
const challenge = createHash("sha256").update(verifier).digest("base64url");
if (challenge !== row.code_challenge) return tokenError("invalid_grant");   // no downgrade to plain
```

**Detection:**

```bash
# Provider constructed with no explicit security config (no hits for these keys is the finding)
grep -rnE 'new Provider\(' -A 15 --include='*.ts' --include='*.js' . \
  | grep -icE 'pkce|rotateRefreshToken|subjectTypes|clientAuthMethods'
# Client secrets compared directly, codes deleted rather than conditionally consumed, no logout
grep -rnE 'client_secret[[:space:]]*(===|==|!=|!==)' --include='*.ts' --include='*.js' --include='*.py' .
grep -rnE '(delete|DELETE FROM)[^\n]*(auth_code|authorization_code)' --include='*.ts' --include='*.sql' .
grep -rnE 'backchannel[-_]?logout' --include='*.ts' --include='*.js' .
```

## OAuth / OIDC Footgun Checklist

- `arctic` or `lucia` in `package.json` — both deprecated (July 2026, March 2025); the flow is stale
  or about to be hand-rolled. Audit it as hand-rolled.
- No `state`, or a `state` generated and never compared server-side; `code_challenge_method` omitted
  (RFC 7636 defaults it to `plain`, which protects nothing); one global cookie holding `state` /
  `nonce` / verifier for every provider instead of one scoped per provider, per flow, short-lived.
- `redirect_uri` built from `Host` / `X-Forwarded-Host` / `req.url`, or registered with a wildcard;
  a post-login redirect to `next` / `returnTo` / `callbackUrl` without same-origin proof — an open
  redirector is a code-exfiltration primitive, not a UX bug.
- `jwt.decode()` on an ID token; `verify()` with no `algorithms` allow-list; JWKS not selected by
  `kid`; `aud`, `exp` or `nonce` unchecked; two or more providers and no stored-issuer (`iss`)
  comparison on the callback — mix-up defence is REQUIRED once there are two.
- A user looked up by `email` from a claim; `email_verified` never read; no `(issuer, sub)` stored.
- `access_token` / `refresh_token` in plaintext columns, in the session cookie or JWT, or returned
  to the browser; AES-GCM with no AAD binding ciphertext to its row; one key for every purpose.
- A rotated refresh token not persisted, two refreshers racing with no CAS/lock, or reuse handled by
  deleting the presented token instead of revoking the family.
- `authorizationCodeGrant(config, url)` with no third argument, or `skipStateCheck: true` — the
  checks are optional parameters, and absent means "expect none", not "fail".
- Provider side: `pkce.required` left at the default, `rotateRefreshToken` unset, secrets in clear
  text, codes not single-use in the database, `subjectTypes: ['public']` with the placeholder
  `pairwiseIdentifier`, a single signing key, no back-channel logout.

## Cross-References

- `secaudit:auth` — Auth.js/NextAuth and Clerk specifics (provider-scoped check cookies, session
  strategy, `auth()` fail-open), CSRF, session cookies and session fixation; not repeated here.
- `secaudit:better-auth-security` — Better Auth's own account-linking and session model.
- `secaudit:cryptography` — password hashing, JWT algorithm confusion, and the key-management side
  of the §5 token vault (envelope encryption, key IDs, rotation procedure).
- `secaudit:secrets` — `client_secret` in the repo or behind a client-exposed env prefix.
- `secaudit:react-native-security` — PKCE with custom URL schemes; why an embedded WebView must not
  host the authorization request (RFC 8252 §8.12).
- `secaudit:web-vulns` — open redirect and SSRF as general classes; §2 is the OAuth-specific case.

## Sources

- https://www.rfc-editor.org/rfc/rfc9700.txt -- OAuth 2.0 Security BCP: §2.1.1 PKCE and transaction-bound challenges, §4.1.3 exact redirect matching, §4.4.2 mix-up, §4.5 code injection, §4.7.1 CSRF/state, §4.11.1 open redirectors, §4.14.2 refresh rotation and reuse detection
- https://www.rfc-editor.org/rfc/rfc7636.txt -- PKCE: §4.2 S256 is mandatory to implement, §4.3 `code_challenge_method` defaults to `plain`, §7.2 no downgrade
- https://www.rfc-editor.org/rfc/rfc9207.txt -- the `iss` authorization response parameter (mix-up countermeasure)
- https://www.rfc-editor.org/rfc/rfc8252.txt -- OAuth for native apps: §6 PKCE required, §8.12 no embedded user-agents
- https://openid.net/specs/openid-connect-core-1_0.html -- OIDC Core: §3.1.3.7 ID token validation, §5.1 `email_verified` semantics, §8.1 pairwise subject identifiers
- https://openid.net/specs/openid-connect-backchannel-1_0.html -- Back-Channel Logout §2.6 logout token validation rules
- https://www.descope.com/blog/post/noauth -- nOAuth: mutable, unverified `email` claims and account takeover by email linking
- https://next-auth.js.org/faq -- why automatic account linking between arbitrary providers is unsafe
- https://developer.okta.com/docs/guides/add-an-external-idp/openidconnect/main/ -- match on email if you must, but key the user on the static `sub` claim
- https://arctic.pilcrowonpaper.com/ -- Arctic deprecated July 2026; replacement code published in the repository
- https://pilcrowonpaper.com/blog/18 -- the deprecation announcement for Arctic and most Oslo packages
- https://raw.githubusercontent.com/pilcrowonpaper/arctic/refs/heads/main/code/authorization_request-pkce.ts -- the hand-rolled authorization request: 32-byte hex verifier, S256 challenge, scoped `HttpOnly; Secure; SameSite=Lax; Max-Age=600` cookie
- https://raw.githubusercontent.com/pilcrowonpaper/arctic/refs/heads/main/code/authorization_code_exchange-pkce.ts -- reading the stored verifier back and aborting when it is missing
- https://lucia-auth.com/ -- Lucia deprecated March 2025; the site now hosts single-file replacement code
- https://raw.githubusercontent.com/panva/openid-client/main/docs/functions/authorizationCodeGrant.md -- `authorizationCodeGrant(config, currentUrl, checks?, ...)`; the checks argument is optional
- https://raw.githubusercontent.com/panva/openid-client/main/docs/interfaces/AuthorizationCodeGrantChecks.md -- `expectedState` / `expectedNonce` semantics when undefined; `skipStateCheck`
- https://raw.githubusercontent.com/panva/node-oidc-provider/main/docs/README.md -- `pkce.required` default, `clientAuthMethods`, `rotateRefreshToken` chain revocation, `subjectTypes` / `pairwiseIdentifier` placeholder, the four-step JWKS rotation
- https://nodejs.org/api/crypto.html -- `createCipheriv`, `setAAD`, `getAuthTag` after `final()`, `hkdfSync`
- https://www.rfc-editor.org/rfc/rfc5869.txt -- HKDF extract-then-expand; `info` for purpose separation
- https://csrc.nist.gov/pubs/sp/800/38/d/final -- NIST SP 800-38D, GCM authenticated encryption with associated data
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025, where §1, §3, §4 and §7 land
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where §2, §5, §6 and §8 land
