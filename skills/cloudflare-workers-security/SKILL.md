---
name: cloudflare-workers-security
description: Audits applications running on Cloudflare Workers and Pages Functions, usually with Hono. Covers plaintext `[vars]` in `wrangler.toml` / `wrangler.jsonc` versus `wrangler secret`, `.dev.vars` hygiene and per-environment non-inheritance, binding blast radius (D1, KV, R2, Durable Objects, Queues, Workers AI) where every route reaches every binding, Hono middleware ordering and auth placement, `c.env` leaking into responses, CORS/CSRF/secure-header middleware defaults, static-file serving and path handling, trusting `cf-connecting-ip` rather than `x-forwarded-for`, D1 prepared statements, KV's eventual consistency as a rate-limit store, and verifying the Cloudflare Access JWT instead of trusting its header. Use whenever the project has a `wrangler.toml`, `wrangler.jsonc`, `.dev.vars`, a `functions/` directory, or a `hono` dependency. For R2 presigned URLs and bucket configuration see secaudit:object-storage-security.
license: MIT
---

# Cloudflare Workers Security (Workers, Pages Functions, Hono)

A Worker has no server, no network perimeter, and no framework doing anything implicit on your
behalf. What it has instead is `env`: one object, handed to every request, holding a live handle to
your database, your object store, your queues, your AI account, and every secret you configured.
There is no connection string to steal because there is nothing to steal — Cloudflare's own words
are that "the underlying secret is never exposed to your Worker's code." The flip side is that
reaching the resource needs no credential either: any line of code that runs inside the Worker
already has the permission.

The recurring AI-codegen failure mode is a Worker that deploys on the first try. The config that
deploys has the API key in `[vars]`, because that is the block the docs show first and it needs no
extra CLI step. The Hono app that works has `app.use('*', cors())` at the top and
`app.get('/admin/:id', …)` above the auth middleware, because that is the order the routes were
written in. The D1 query that returns rows is a template literal. Each is the documented wrong
choice, and none of them produces an error. Findings map to OWASP **A01:2025** (Broken Access
Control — §2, §3, §7), **A02:2025** (Security Misconfiguration — §1, §3, §4, §5) and **A05:2025**
(Injection — §6).

## When to Use

- The repo contains `wrangler.toml`, `wrangler.jsonc`, `wrangler.json`, `.dev.vars`, or a
  `functions/` directory (Pages Functions), or depends on `hono` / `wrangler`.
- Any code reads `c.env`, `context.env`, or an `env` handler argument, or imports from
  `cloudflare:workers`.
- Reviewing a D1 query, a KV read/write, an R2 `get`/`put`, a Durable Object stub, or `env.AI.run`.
- The app sits behind Cloudflare Access / Zero Trust and reads a `Cf-Access-*` header.

Review grep heuristics: `[vars]`, `.dev.vars`, `c.env`, `DB.prepare`, `KV.put`, `env.BUCKET`,
`serveStatic`, `x-forwarded-for`, `Cf-Access-Jwt-Assertion`, `nodejs_compat`, and `app.use(`
relative to the first `app.get(`.

## 1. `[vars]` Is Plaintext Config, Not a Secret Store

**What to look for:** anything key-shaped inside a `[vars]` table (or a `"vars"` object in
`wrangler.jsonc`) — `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, `JWT_SECRET`, `DATABASE_URL`; a
`.dev.vars` or `.env` that is not in `.gitignore`; a real production value in `.dev.vars.example`;
and the mirror-image mistake — a secret set with `wrangler secret put` and then *also* pasted into
`[env.production.vars]` because "production couldn't see it".

**Why it's exploitable:** the Wrangler config is a committed file. Cloudflare states plainly that
text and JSON vars "are not encrypted and are useful for storing application configuration" and
"Do not use plaintext environment variables to store sensitive information." A key in `[vars]` is
in the repository, in every fork, in every CI log that prints the config, and in the dashboard for
anyone with account read access. Secrets differ in the way that matters: "secret values are not
visible within Wrangler or Cloudflare dashboard after you define them." Non-inheritance is what
makes the mistake recurring — Wrangler is explicit that "Non-inheritable keys are configurable at
the top-level, but cannot be inherited by environments and must be specified for each environment",
and that "bindings and environment variables are non-inheritable." Secrets behave the same way, so
a developer who runs `wrangler secret put API_KEY` without `--env`, deploys `--env production` and
finds `env.API_KEY` undefined has one correct fix and one tempting one; the tempting one is pasting
the value into `[env.production.vars]`, where it is plaintext forever.

**Fix:** every value that would matter if a stranger read it goes in via `wrangler secret put`,
once per environment. `[vars]` keeps only what you would happily print. Add `.dev.vars*` and
`.env*` to `.gitignore` before the first commit, and treat anything already committed as burned:
rotate at the provider rather than deleting the file.

```toml
# wrangler.toml — BAD: credentials in a committed file, and production inherits none of them
name = "api"
compatibility_date = "2026-09-01"

[vars]
OPENAI_API_KEY = "sk-proj-REDACTED"          # plaintext, in git, in every fork
JWT_SECRET = "super-secret-value"            # rotating this is a code change

[env.production.vars]
OPENAI_API_KEY = "sk-proj-REDACTED"          # duplicated because envs do not inherit
```

```toml
# wrangler.toml — GOOD: vars hold public config only; secrets are set out of band, per env
[vars]
ENVIRONMENT = "development"
PUBLIC_APP_URL = "https://app.example.com"

[env.production.vars]
ENVIRONMENT = "production"                   # restated: vars are non-inheritable
PUBLIC_APP_URL = "https://app.example.com"

# Secrets never appear here — per environment, out of band:
#   wrangler secret put OPENAI_API_KEY --env production
# Local values live in .dev.vars (gitignored); selecting an environment locally loads
# .dev.vars.<environment-name> ahead of the generic .dev.vars.
```

Bindings are non-inheritable too, which `wrangler.jsonc` makes easy to get wrong: without a
per-environment block production has no database — or somebody points production at the dev one.

```jsonc
{
  "d1_databases": [{ "binding": "DB", "database_name": "api-dev", "database_id": "DEV_ID" }],
  "env": { "production": {
    "d1_databases": [{ "binding": "DB", "database_name": "api-prod", "database_id": "PROD_ID" }]
  } }
}
```

**One extra exposure path:** with `nodejs_compat` and the `nodejs_compat_populate_process_env` flag
— "enabled by default for compatibility dates on or after 2025-04-01" — `process.env` "will contain
any environment variables, secrets, or version metadata that has been configured on your Worker."
Without it, "By default `env` is an empty object." That is why a Node-shaped debug route or an
error reporter serializing `process.env` now exfiltrates your Workers secrets instead of nothing.

**Detection:**

```bash
# Key-shaped names inside a vars block (toml `KEY = ...` and jsonc `"KEY": ...` forms)
grep -rnE '[A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD|DSN)[A-Z0-9_]*"?[[:space:]]*[=:]' \
  --include='wrangler.toml' --include='wrangler.json' --include='wrangler.jsonc' .
# Local secret files tracked by git, or missing from .gitignore
git ls-files | grep -E '(^|/)\.dev\.vars|(^|/)\.env($|\.)'
grep -qE '^\.dev\.vars\*?$' .gitignore || echo 'MISSING: .dev.vars* not in .gitignore'
# Anything dumping the whole environment bag
grep -rnE 'stringify\((process\.env|c\.env)\)|\.\.\.(process\.env|c\.env)\b' --include='*.ts' .
```

## 2. Every Route Reaches Every Binding

**What to look for:** a route that takes a key, id, or path from the request and hands it to a
binding — `env.BUCKET.get(c.req.param('key'))`, `env.KV.get(searchParams.get('k'))`, a D1 query
with no owner predicate; an unauthenticated route that calls `env.AI`; an AI Gateway token or
provider key shipped to the browser.

**Why it's exploitable:** bindings attach to the *Worker*, not to a route. The same `env` is passed
to every handler, so a health check, a public marketing route and an admin mutation all carry
identical, unauthenticated authority over D1, KV, R2, Durable Objects and Queues. The convenience
Cloudflare advertises — "you never have to add secret keys or tokens to your Worker in order to
access resources on your Cloudflare account" — cuts both ways: there is no credential to omit in
order to *reduce* a route's authority. Cloudflare's Workers-with-R2 walkthrough says it outright:
an unguarded Worker means "your bucket is publicly exposed and its contents can be accessed and
modified by undesired actors", and "You must now define authorization logic to determine who can
perform what actions to your bucket. This logic lives within your Worker's code." An R2 binding is
read/write over the whole bucket with no per-object ACLs, so knowing a key *is* the access check
unless you add one. Workers AI is the same shape with a billing tail — `env.AI` needs no key, so
any reachable route can spend — and an AI Gateway token is worse if it escapes: "Any token with
`AI Gateway Run` can send requests through every gateway in the account, including any configured
with stored provider keys through Bring Your Own Keys (BYOK), consuming those credentials."

**Fix:** treat every handler as internet-facing. Derive identity from a server-verified session
(§3, §7), look the object up *by owner*, and let your database — never the URL — produce the
storage key. Keep the `cf-aig-authorization` token server-side. If one Worker needs a binding
another must never touch, that is a second Worker: the binding set is the isolation unit.

```ts
// src/index.ts — BAD: the URL names the object, the binding does the rest
app.get('/files/:key', async (c) => {
  const obj = await c.env.BUCKET.get(c.req.param('key'));   // any key, any user, no session
  return obj ? new Response(obj.body) : c.notFound();
});
app.post('/ai/summarize', async (c) =>                      // unauthenticated and unmetered:
  c.json(await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct',   // a stranger's bill, paid by you
    { prompt: (await c.req.json()).text })));
```

```ts
// src/index.ts — GOOD: the session decides, the database owns the key
app.get('/files/:id', async (c) => {
  const user = c.get('user');                       // set by auth middleware (§3)
  const row = await c.env.DB
    .prepare('SELECT r2_key FROM files WHERE id = ?1 AND owner_id = ?2')
    .bind(c.req.param('id'), user.id)               // ownership is part of the query
    .first<{ r2_key: string }>();
  if (!row) return c.notFound();                    // 404, not 403: do not confirm existence
  const obj = await c.env.BUCKET.get(row.r2_key);   // key from our row, never from the URL
  if (!obj) return c.notFound();
  return new Response(obj.body, { headers: { 'X-Content-Type-Options': 'nosniff',
    'Content-Type': obj.httpMetadata?.contentType ?? 'application/octet-stream' } });
});
```

**Detection:**

```bash
# Request-derived values flowing straight into a binding call
grep -rnE '(c\.)?env\.[A-Z_]+\.(get|put|delete)\([^)]*(req\.|param\(|query\(|searchParams)' \
  --include='*.ts' --include='*.js' .
# Files that touch a binding but never look at a session/user; gateway tokens in client code
grep -rlE '(c\.)?env\.(BUCKET|KV|DB|AI)\b' --include='*.ts' src functions 2>/dev/null \
  | xargs grep -LiE 'session|getUser|jwtPayload|c\.get\(.user.\)' 2>/dev/null
grep -rniE 'cf-aig-authorization|CLOUDFLARE_API_TOKEN' --include='*.tsx' --include='*.jsx' .
```

## 3. Middleware Order *Is* the Authorization Model

**What to look for:** `app.use('*', auth)` registered *below* the routes it should protect; auth
scoped to `'/api/*'` while a sub-app is mounted at `/admin`; `cors()` with no arguments in front of
a cookie-authenticated API; `c.json(c.env)` or `c.env` spread into a response or log;
`secureHeaders()` assumed to have set a CSP.

**Why it's exploitable:** Hono's guide states the rule without ambiguity — "The order in which
Middleware is executed is determined by the order in which it is registered." A handler registered
before the auth middleware is matched and served before that middleware is ever in the chain. The
route works, the tests pass (they call it logged in), and the endpoint is public. Path scoping
fails as quietly: `app.use('/api/*', auth)` does nothing for `/admin/users`, and
`app.route('/admin', adminApp)` inherits only middleware registered on the parent *before* the
mount. `c.env` is §2's whole binding-and-secret bag, so returning or logging it leaks everything at
once. Three middleware defaults deserve their own lines:

- **`cors()`** — the origin option's "default is `*`", so an unconfigured `cors()` invites every
  site on the internet to call an authenticated API. Older Hono removed the browser's last safety
  net: `CVE-2026-54290` (HIGH) — "With `credentials: true` and no explicit `origin` (the default
  wildcard), the CORS Middleware reflects the request's `Origin` and sends
  `Access-Control-Allow-Credentials: true`" — fixed 4.12.25. That is a same-origin bypass for
  every route behind it.
- **`csrf()`** — it "protects against CSRF attacks by checking both the `Origin` header and the
  `Sec-Fetch-Site` header", and only for unsafe methods carrying form-submittable content types
  (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`) — not a token scheme,
  no cover for a JSON body, and it misbehaves where proxies strip `Origin`.
- **`secureHeaders()`** — a useful default pack (HSTS, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, COOP/CORP), but `Content-Security-Policy` is "No Setting" by default.

**Fix:** register global middleware at the top of the file, before any route or sub-app mount;
mount protected routers under a prefix that already carries auth; pin `cors()` to an explicit
origin allowlist whenever credentials are involved; never let `c.env` reach a response or a log.

```ts
// src/index.ts — BAD: the admin route is registered before auth exists, and CORS is open
const app = new Hono<{ Bindings: Env }>();

app.use('*', cors());                          // origin defaults to '*'
app.get('/admin/users', (c) => c.json(listUsers(c.env)));   // matched with no auth in the chain
app.get('/debug/env', (c) => c.json(c.env));   // every secret and binding name, one GET
app.use('/api/*', auth);                       // registered last: protects nothing above
```

```ts
// src/index.ts — GOOD: policy first, routes second, origins explicit
const app = new Hono<{ Bindings: Env; Variables: { user: User } }>();

app.use('*', secureHeaders({                   // CSP is not set by default — set it
  contentSecurityPolicy: { defaultSrc: ["'self'"], objectSrc: ["'none'"],
                           frameAncestors: ["'none'"] },
}));
app.use('*', cors({
  origin: ['https://app.example.com'],         // never '*' alongside credentials
  credentials: true, allowMethods: ['GET', 'POST'],
}));
app.use('*', csrf({ origin: ['https://app.example.com'] }));   // defence in depth, not the gate
app.use('/api/*', auth);                       // registered BEFORE the routes below
app.use('/admin/*', auth, requireRole('admin'));

app.get('/api/me', (c) => c.json({ id: c.get('user').id }));
app.route('/admin', adminApp);                 // mounted after '/admin/*' middleware exists
```

**Detection:**

```bash
# Auth middleware registered after the first route on the same app
grep -nE "app\.(get|post|put|patch|delete)\(|app\.use\(" src/index.ts \
  | awk -F: '/app\.use\(.*(auth|jwt|bearerAuth|basicAuth)/ {u=$1} \
             /app\.(get|post|put|patch|delete)\(/ && !r {r=$1} \
             END {if (u && r && u+0 > r+0) print "ORDER BUG: first route " r ", auth at " u}'
# The environment bag in a response or a log; unconfigured or wildcard CORS
grep -rnE '(c\.json|c\.body|console\.(log|error))\(\s*c\.env\b|\.\.\.c\.env' --include='*.ts' .
grep -rn 'cors()' --include='*.ts' . ; grep -rnE "origin:\s*'\*'" --include='*.ts' .
```

## 4. Static Serving and Path Handling

**What to look for:** `serveStatic` from a Hono Cloudflare adapter, especially on a pinned older
version; a route that resolves a request path segment against asset storage; `toSSG()` in a build
script; any handler treating `c.req.param('path')` as a filesystem path.

**Why it's exploitable:** this is where Hono's Workers adapter has actually been bitten, repeatedly,
and the bug is always the same — a user-controlled path is resolved before it is constrained.
`CVE-2026-24473` (MODERATE): `serveStatic` in the Cloudflare Workers adapter "may allow attackers
to read arbitrary keys from the Workers environment", because the requested path is not restricted
before being resolved against asset storage; fixed 4.11.7. On Workers that is not a directory
listing — it is §2's binding-and-secret bag, read over HTTP unauthenticated. The same middleware
carried `CVE-2026-29045` (HIGH, arbitrary file access), fixed 4.12.4, and `CVE-2026-39407`
(middleware bypass via repeated slashes), fixed 4.12.12. Static generation has its own instance:
`CVE-2026-84365` — `toSSG()` still writes files outside the output directory, an incomplete fix for
an earlier advisory in the same function; fixed 4.13.5.

**Fix:** upgrade first — §8's floor is the only complete answer. Then remove the pattern that makes
the class possible: never accept a path from the request and resolve it against storage. Serve
assets from a fixed manifest instead.

```ts
// src/index.ts — BAD: the request names the path, the adapter resolves it
import { serveStatic } from 'hono/cloudflare-workers';
app.get('/assets/*', serveStatic({ root: './' }));        // on an unpatched version, §4's CVEs
app.get('/download/:path{.+}', async (c) =>
  new Response((await c.env.ASSETS.get(c.req.param('path')))?.body));  // "../", absolute keys
```

```ts
// src/index.ts — GOOD: a fixed allowlist; the request selects, it does not construct
const PUBLIC_ASSETS = new Map([
  ['logo', { key: 'brand/logo.svg', type: 'image/svg+xml' }],
  ['terms', { key: 'legal/terms-2026-09.pdf', type: 'application/pdf' }],
]);

app.get('/assets/:name', async (c) => {
  const asset = PUBLIC_ASSETS.get(c.req.param('name'));   // no path arithmetic anywhere
  const obj = asset && await c.env.BUCKET.get(asset.key);
  if (!obj) return c.notFound();
  return new Response(obj.body, { headers: {
    'Content-Type': asset.type, 'X-Content-Type-Options': 'nosniff' } });
});
```

**Detection:**

```bash
# serveStatic / toSSG usage (compare the installed version against §8's floor)
grep -rn 'serveStatic\|toSSG(' --include='*.ts' --include='*.js' .
# Wildcard path params resolved against storage
grep -rnE "param\('[a-z]+'\)" --include='*.ts' . | grep -E '\{\.\+\}|ASSETS|BUCKET|KV'
```

## 5. Which Client-IP Header You Can Trust

**What to look for:** `c.req.header('x-forwarded-for')` used for rate limiting, allowlisting, audit
logs or geo decisions; `x-real-ip` treated as authoritative; `ipRestriction` on an old Hono version;
`request.cf.country` read without a null check; and the one people forget — a Worker that proxies
to an origin server reachable on its own IP.

**Why it's exploitable:** at the edge the two headers are not equivalent. `CF-Connecting-IP`
"provides the client IP address connecting to Cloudflare to the origin web server" and has "a
consistent format containing only one IP address". `X-Forwarded-For` "maintains proxy server and
original visitor IP addresses" — Cloudflare *appends* to it when the client already sent one, so an
attacker-supplied value survives in the list. Parsing the first XFF element lets the caller pick
their own identity: one attacker becomes unlimited rate-limit buckets, and an IP allowlist becomes a
header you can type. Hono's `getConnInfo` for the Workers adapter reads `cf-connecting-ip`, right on
Workers and only there. `ipRestriction` has had parser-level bypasses of its own: `CVE-2026-24398`
— the IPv4 regex accepts octets above 255 (`999.1.1.1`) with no range check, so a crafted address
slips past a deny rule; fixed 4.11.7. Two IPv6 siblings followed: `CVE-2026-39409` fixed 4.12.12
and `CVE-2026-47674` fixed 4.12.21.

Origin bypass silently undoes all of it. If a server with a public IP sits behind you, Cloudflare
warns that someone who "discovers your origin server's IP address — for example, through historical
DNS records or mail server configuration — they could send traffic directly to your server,
bypassing Cloudflare's security protections entirely", and that origin then sees whatever headers
the attacker chose to send, including `CF-Connecting-IP` and any `Cf-Access-*` header (§7).

**Fix:** on Workers read `cf-connecting-ip` (directly or via `getConnInfo`) and never parse
`x-forwarded-for` for a security decision. Null-check `request.cf`, which "is not available in the
Cloudflare Workers dashboard or Playground preview editor". If a separate origin exists, block
everything that is not a Cloudflare IP address and turn on Authenticated Origin Pulls, which "helps
ensure requests to your origin server come from the Cloudflare network."

```ts
// src/middleware/limit.ts — BAD: the caller chooses their own rate-limit key
const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
await bump(c.env, `rl:${ip}`);           // a new XFF value per request = a fresh bucket each time
```

```ts
// src/middleware/limit.ts — GOOD: the edge-set header, with no client-controlled fallback
import { getConnInfo } from 'hono/cloudflare-workers';

export const clientIp = (c: Context): string | null =>
  // Set by Cloudflare on the way in (Cloudflare documents this as the header to use for the client IP).
  c.req.header('cf-connecting-ip') ?? getConnInfo(c).remote.address ?? null;

export const rateLimit = async (c: Context, next: Next) => {
  const ip = clientIp(c);
  if (!ip) return c.text('Bad Request', 400);      // fail closed; never bucket as 'unknown'
  const country = c.req.raw.cf?.country ?? 'XX';   // cf is undefined in dashboard/local previews
  if (!(await allow(c.env.LIMITER, ip, country))) return c.text('Too Many Requests', 429);
  await next();
};
```

**Detection:**

```bash
# XFF or x-real-ip used for a security decision; ipRestriction in use (check §8's floor)
grep -rnE "header\(['\"](x-forwarded-for|x-real-ip)['\"]\)|ipRestriction" --include='*.ts' .
# request.cf dereferenced without a guard; any origin that could be reached directly
grep -rnE '\bcf\.(country|colo|asn|tlsVersion)' --include='*.ts' . | grep -v 'cf?\.'
grep -rn 'fetch(' --include='*.ts' . | grep 'https://' | grep -v 'workers\.dev'
```

## 6. D1 Query Construction, and KV Is Not a Counter

**What to look for:** a template literal or `+` concatenation inside `env.DB.prepare(...)` or
`env.DB.exec(...)`; `.bind()` never called; and separately, KV holding a rate-limit counter, an
OTP/nonce, a one-time token, a session revocation list, or an idempotency key.

**Why it's exploitable, part one (A05:2025):** D1 speaks SQL, so it has SQL injection, and nothing
about the serverless framing prevents it. Cloudflare's guidance is direct — "The recommended
approach is to use prepared statements to run the SQL and bind parameters to them", and "Binding
parameters using `bind()` to prepared statements … prevents SQL injection attacks." A Worker that
interpolates a search term into a `WHERE` clause hands over the whole database, and because the
binding carries full authority (§2) there is no per-connection privilege to limit the damage.

**Part two:** KV is the wrong shape for anything that must be counted or revoked. It "achieves high
performance by being eventually-consistent", where "Changes may take up to 60 seconds or more to be
visible in other global network locations", and it is explicitly unsuited to a "write-heavy workload
where you are updating the same key tens or hundreds of times per second." Read-modify-write on a KV
key has no atomicity and no compare-and-swap, so parallel requests all read the same count and all
write `n+1`: a five-per-hour limit becomes five per *concurrent batch*, from any colo, for up to a
minute, and a revoked session stays valid elsewhere in the world after you delete it. Cloudflare's
own pointer is the fix — "If you need stronger consistency guarantees, consider using Durable
Objects" — which provide "durable, transactional, and strongly consistent storage" and are
"single-threaded and cooperatively multi-tasked", so increments serialize by construction.

**Fix:** `prepare()` with `?`/`?1` placeholders plus `.bind()`, always; sort directions and other
identifiers come from an allowlist, never from a parameter. Keep KV for read-heavy, cacheable data
and move counters, nonces, locks and revocation into a Durable Object keyed by the subject.

```ts
// src/routes/search.ts — BAD: injection, plus a counter that does not count
const q = c.req.query('q') ?? '';
const rows = await c.env.DB.prepare(
  `SELECT * FROM notes WHERE owner_id = '${user.id}' AND title LIKE '%${q}%'`   // injectable
).all();
const n = Number((await c.env.KV.get(`rl:${ip}`)) ?? 0);                 // stale by up to 60s
await c.env.KV.put(`rl:${ip}`, String(n + 1), { expirationTtl: 3600 });  // lost updates
```

```ts
// src/routes/search.ts + src/limiter.ts — GOOD: bound parameters, and a DO that serializes
const dir = c.req.query('dir') === 'asc' ? 'ASC' : 'DESC';    // never interpolate raw input
const rows = await c.env.DB
  .prepare(`SELECT id, title FROM notes
            WHERE owner_id = ?1 AND title LIKE ?2 ORDER BY created_at ${dir} LIMIT ?3`)
  .bind(user.id, `%${c.req.query('q') ?? ''}%`, 50)
  .all();

export class RateLimiter extends DurableObject {
  async hit(limit: number, windowMs: number): Promise<boolean> {
    const now = Date.now();
    type W = { n: number; start: number };
    const w = (await this.ctx.storage.get<W>('w')) ?? { n: 0, start: now };
    if (now - w.start > windowMs) { w.n = 0; w.start = now; }
    await this.ctx.storage.put('w', { ...w, n: ++w.n });   // transactional, single-threaded
    return w.n <= limit;
  }
}
// One object per subject, so contention is per-user rather than global:
const stub = c.env.LIMITER.get(c.env.LIMITER.idFromName(`login:${ip}`));
if (!(await stub.hit(5, 60_000))) return c.text('Too Many Requests', 429);
```

**Detection:**

```bash
# SQL built by interpolation, and prepare() with no bind() in the file
grep -rnE '(prepare|exec)\(\s*`[^`]*\$\{' --include='*.ts' --include='*.js' .
grep -rl '\.prepare(' --include='*.ts' . | xargs grep -L '\.bind(' 2>/dev/null
# KV standing in for a counter, nonce, lock, or revocation list
grep -rniE "KV\.(get|put)\(\s*[\`'\"](rl:|rate|limit|nonce|otp|lock|revoked|attempts)" --include='*.ts' .
```

## 7. Cloudflare Access: The Header Is Not the Authorization

**What to look for:** code that reads `Cf-Access-Authenticated-User-Email` or
`Cf-Access-Jwt-Assertion` and uses it unverified; a JWT "decoded" with a base64 split; `jwtVerify`
with no `audience`; and the assumption that "it is behind Access" makes the code unreachable any
other way.

**Why it's exploitable:** Access forwards "an application token as a `Cf-Access-Jwt-Assertion`
request header" — and a header is a string the caller can also type. Cloudflare's instruction is
explicit: "You should validate the token with your public key to ensure that the request came from
Access and not a malicious third party." Two checks matter beyond the signature: the issuer, and
the `aud` claim, which "specifies which application the JWT is valid for". Skip `aud` and a valid
token minted for *any* application in your Access organization — including a low-sensitivity
internal tool a contractor can reach — authenticates to this one. Skip verification and the gate is
a header name. Whether an attacker can reach the code at all is §5's question.

**Fix:** verify the JWT on every request against your team's JWKS at
`https://<your-team-name>.cloudflareaccess.com/cdn-cgi/access/certs`, pinning both `issuer` (your
team domain) and `audience` (this application's AUD tag). Cache the key set, fail closed on any
error, and treat the verified claims — not a convenience `Cf-Access-*` header — as the identity.

```ts
// src/middleware/access.ts — BAD: the header is the auth
const email = c.req.header('cf-access-authenticated-user-email');
if (!email) return c.text('Unauthorized', 401);
c.set('user', { email });               // spoofable on any path that does not traverse Access
// Equally bad: decoding without verifying.
const claims = JSON.parse(atob(c.req.header('cf-access-jwt-assertion')!.split('.')[1]));
```

```ts
// src/middleware/access.ts — GOOD: signature, issuer and audience, all checked
import { createRemoteJWKSet, jwtVerify } from 'jose';

let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

export const accessAuth = async (c: Context, next: Next) => {
  const token = c.req.header('cf-access-jwt-assertion');
  if (!token) return c.text('Unauthorized', 401);
  // TEAM_DOMAIN and POLICY_AUD are config, not secrets; the AUD tag identifies THIS app.
  jwks ??= createRemoteJWKSet(new URL(`${c.env.TEAM_DOMAIN}/cdn-cgi/access/certs`));
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: c.env.TEAM_DOMAIN,
      audience: c.env.POLICY_AUD,       // without this, any app's token is accepted
    });
    c.set('user', { email: payload.email as string, sub: payload.sub! });
  } catch {
    return c.text('Unauthorized', 401); // fail closed: never fall back to the header
  }
  await next();
};
```

If you verify with Hono's own JWK middleware instead, note it had an algorithm-confusion bug:
`CVE-2026-22817` (HIGH) — when a JWK carries no `alg`, verification fell back to the unverified
`alg` in the token header, permitting forged tokens; fixed 4.11.4. Two more JWT-middleware defects
matter when auditing a pinned version: `CVE-2026-47673` (any `Authorization` scheme accepted, not
only `Bearer`) fixed 4.12.21, and `CVE-2026-44459` (improper `exp`/`nbf`/`iat` validation) fixed
4.12.18.

**Detection:**

```bash
# Access headers consumed without a verify call in the same file
grep -rlniE 'cf-access-(jwt-assertion|authenticated-user-email)' --include='*.ts' . \
  | xargs grep -LiE 'jwtVerify|createRemoteJWKSet|verify\(' 2>/dev/null
# Hand-rolled JWT decoding; and whether any jwtVerify call pins an audience
grep -rnE "atob\([^)]*split\('\.'\)|JSON\.parse\(atob" --include='*.ts' .
grep -rn -A4 'jwtVerify(' --include='*.ts' . | grep -c 'audience'
```

## 8. Version Floor

Hono moves fast and carries a large advisory surface, so this section is a starting point, not an
answer. Re-derive the floor from OSV at audit time exactly as `secaudit:framework-versions` does:
query the `hono` package for the installed version and read the result, rather than trusting a
number written here weeks ago. As verified on 2026-09-15, `hono@4.13.5` is the current clean floor
— OSV reports zero open advisories for it, and it is the highest fixed version in the package's
advisory feed. The Workers-relevant advisories behind that number:

- `CVE-2026-24473` — `serveStatic` on the Workers adapter reads arbitrary keys from the Workers
  environment (§4); fixed 4.11.7.
- `CVE-2026-84365` — `toSSG()` writes outside the output directory (§4); fixed 4.13.5.
- `CVE-2026-54290` — `cors()` with credentials and the default wildcard origin reflects the request
  `Origin` (§3); fixed 4.12.25.
- `CVE-2026-71850` — `hono/jsx` `memo()` retains a server-rendered result and reuses it, so "a
  response can contain HTML rendered for another user's request"; request-scoped values from
  `useContext` / `useRequestContext` are ignored by its comparator; fixed 4.12.34. On a shared edge
  runtime that is a cross-user data leak, not a caching nit.
- `CVE-2026-22817` — JWK/JWKS algorithm confusion (§7); fixed 4.11.4.
- `CVE-2026-44457` — the cache middleware ignores `Vary: Authorization` / `Cookie`, serving one
  user's cached response to another; fixed 4.12.18.

Note what that list says about "upgrade to the fix": each release answered its own advisory and was
superseded within weeks. 4.11.7 is the version that fixed the serve-static disclosure, and
it is still exposed to dozens of later advisories — a version cited as a CVE fix is not a version
that is safe today. Go to the current clean floor, then re-check it.

```bash
# Installed version, then the live answer (an empty {} means no open advisories)
node -p "require('./package.json').dependencies.hono" 2>/dev/null
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"name":"hono","ecosystem":"npm"},"version":"REPLACE_WITH_INSTALLED"}'
```

## Cloudflare Workers Footgun Checklist

- An API key, signing secret, or `JWT_SECRET` in `[vars]` / `"vars"` — plaintext, committed, and
  rotated only by a deploy; `.dev.vars` or `.env` tracked by git.
- A secret set once without `--env` and assumed present in production — bindings, vars and secrets
  are all non-inheritable per environment.
- `nodejs_compat` with `process.env` serialized anywhere: a debug route or error reporter dumps
  every Worker secret; a binding call keyed off the request rather than a row you own.
- An R2 binding fronted by a Worker with no authorization logic — the bucket is effectively public;
  `env.AI` reachable unauthenticated; an `AI Gateway Run` token in client code, which can spend
  every BYOK provider key in the account.
- `app.use('*', auth)` registered below the routes, or auth scoped to a prefix a sub-app is mounted
  outside of.
- `cors()` with no options, or `origin: '*'` with `credentials: true`, in front of a
  cookie-authenticated API; `csrf()` mistaken for JSON-API CSRF protection.
- `secureHeaders()` assumed to include a CSP (it sets none); `c.env` returned in a response,
  logged, or spread into a debug payload.
- `serveStatic` or any handler resolving a request-supplied path against asset storage.
- `x-forwarded-for` / `x-real-ip` parsed for rate limits, allowlists or audit logs instead of
  `cf-connecting-ip`; `request.cf` dereferenced without a null check.
- A separate origin reachable on its own IP, with no Cloudflare IP restriction and no Authenticated
  Origin Pulls — every edge control is optional for whoever finds that address.
- SQL built by template literal in `DB.prepare()` / `DB.exec()`, or `prepare()` with no `.bind()`.
- KV holding a rate-limit counter, OTP, nonce, lock, or revocation list — eventually consistent, up
  to 60s stale, no atomic increment.
- `Cf-Access-Jwt-Assertion` or `Cf-Access-Authenticated-User-Email` trusted without verifying the
  signature against the team JWKS, the issuer, and the `aud` claim.
- A Pages preview deployment wired to the production D1, KV, or secrets — Production and Preview are
  separate environments and must hold separate values.

## Cross-References

- `secaudit:object-storage-security` — R2 presigned URLs, bucket CORS, public buckets and
  object-key design. §2 covers the Worker in front of the bucket; that skill covers the bucket.
- `secaudit:secrets` — env-var prefixes, `.gitignore` hygiene, and what to do after a credential
  leaks; §1 is the Workers instance of it.
- `secaudit:framework-versions` — the live OSV lookup §8 defers to, and the rest of Hono's surface.
- `secaudit:rate-limiting` — where limits are required and why a counter must be tamper-proof; §6
  is the Workers-specific storage answer (Durable Objects, not KV).
- `secaudit:auth` — sessions, JWT verification, and why edge middleware is not a security boundary.
- `secaudit:data-access` — SQL injection and input validation beyond D1's prepared statements.
- `secaudit:deployment` — security headers and environment separation, including previews.
- `secaudit:ai-integration` — prompt injection and spend caps behind the `env.AI` binding in §2.

## Sources

- https://developers.cloudflare.com/workers/configuration/environment-variables/ -- `[vars]` are plaintext; "Do not use plaintext environment variables to store sensitive information"
- https://developers.cloudflare.com/workers/configuration/secrets/ -- `wrangler secret put`; secrets not visible in Wrangler or dashboard; `.dev.vars` gitignore guidance
- https://developers.cloudflare.com/workers/wrangler/environments/ -- non-inheritable keys; secrets per environment; environment-specific `.dev.vars.<name>`
- https://developers.cloudflare.com/workers/wrangler/configuration/ -- the non-inheritable key list (bindings, environment variables)
- https://developers.cloudflare.com/workers/runtime-apis/bindings/ -- `env` passed to every handler; "the permission is embedded within the API itself"
- https://developers.cloudflare.com/workers/runtime-apis/nodejs/ -- the `nodejs_compat` compatibility flag and dates
- https://developers.cloudflare.com/workers/runtime-apis/nodejs/process/ -- `nodejs_compat_populate_process_env` puts secrets in `process.env`
- https://developers.cloudflare.com/r2/api/workers/workers-api-usage/ -- an unguarded Worker makes the bucket public; authorization logic lives in your Worker
- https://developers.cloudflare.com/d1/worker-api/prepared-statements/ -- `prepare()` + `bind()` prevents SQL injection
- https://developers.cloudflare.com/kv/concepts/how-kv-works/ -- eventual consistency, up-to-60s staleness, write-heavy workloads, "consider using Durable Objects"
- https://developers.cloudflare.com/durable-objects/concepts/what-are-durable-objects/ -- transactional, strongly consistent, single-threaded storage
- https://developers.cloudflare.com/ai-gateway/configuration/authentication/ -- `cf-aig-authorization`; an `AI Gateway Run` token reaches every gateway and BYOK key
- https://developers.cloudflare.com/workers-ai/ -- the `env.AI` binding
- https://developers.cloudflare.com/fundamentals/reference/http-headers/ -- `CF-Connecting-IP` vs appended `X-Forwarded-For`
- https://developers.cloudflare.com/workers/runtime-apis/request/ -- `request.cf` and where it is unavailable
- https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/ -- origin IP discovery bypasses Cloudflare; block non-Cloudflare traffic
- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/ -- AOP ensures requests come from the Cloudflare network
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/ -- `Cf-Access-Jwt-Assertion`, team JWKS endpoint, `aud` claim, Workers example
- https://developers.cloudflare.com/pages/functions/bindings/ -- Pages Functions read bindings from `context.env`; Production and Preview are separate
- https://hono.dev/docs/guides/middleware -- middleware executes in registration order
- https://hono.dev/docs/getting-started/cloudflare-workers -- `c.env` bindings, typed `Bindings`, local `.dev.vars`
- https://hono.dev/docs/middleware/builtin/cors -- `origin` defaults to `*`
- https://hono.dev/docs/middleware/builtin/csrf -- Origin / `Sec-Fetch-Site` checks; form-submittable content types only
- https://hono.dev/docs/middleware/builtin/secure-headers -- default header pack; CSP is "No Setting" by default
- https://hono.dev/docs/middleware/builtin/jwt -- `secret`, `alg`, `Authorization` handling, `c.get('jwtPayload')`
- https://hono.dev/docs/middleware/builtin/ip-restriction -- requires the environment's `getConnInfo`
- https://hono.dev/docs/helpers/conninfo -- `getConnInfo` from `hono/cloudflare-workers`
- https://raw.githubusercontent.com/honojs/hono/main/src/adapter/cloudflare-workers/conninfo.ts -- the Workers adapter reads `cf-connecting-ip`
- https://github.com/advisories/GHSA-w332-q679-j88p -- CVE-2026-24473 serveStatic Workers-env key disclosure
- https://github.com/advisories/GHSA-gqvv-2mrq-wpjv -- CVE-2026-84365 `toSSG()` writes outside the output directory
- https://github.com/advisories/GHSA-88fw-hqm2-52qc -- CVE-2026-54290 cors() reflected origin with credentials
- https://github.com/advisories/GHSA-f23p-vx2j-j53r -- CVE-2026-71850 `memo()` cross-user SSR disclosure
- https://github.com/advisories/GHSA-f67f-6cw9-8mq4 -- CVE-2026-22817 JWK algorithm confusion
- https://github.com/advisories/GHSA-r354-f388-2fhh -- CVE-2026-24398 ipRestriction IPv4 range bypass
- https://github.com/advisories/GHSA-xpcf-pg52-r92g -- CVE-2026-39409 ipRestriction IPv4-mapped-IPv6 bypass
- https://github.com/advisories/GHSA-xrhx-7g5j-rcj5 -- CVE-2026-47674 ipRestriction non-canonical IPv6 bypass
- https://github.com/advisories/GHSA-f577-qrjj-4474 -- CVE-2026-47673 jwt middleware accepts any Authorization scheme
- https://github.com/advisories/GHSA-hm8q-7f3q-5f36 -- CVE-2026-44459 improper exp/nbf/iat validation
- https://github.com/advisories/GHSA-p77w-8qqv-26rm -- CVE-2026-44457 cache middleware ignores Vary
- https://github.com/advisories/GHSA-q5qw-h33p-qvwr -- CVE-2026-29045 serveStatic arbitrary file access
- https://github.com/advisories/GHSA-wmmm-f939-6g9c -- CVE-2026-39407 serveStatic middleware bypass via repeated slashes
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where §2, §3 and §7 land
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025, where §1, §3, §4 and §5 land
- https://top10.owasp.org/2025/A05_2025-Injection/ -- A05:2025, where §6 lands
