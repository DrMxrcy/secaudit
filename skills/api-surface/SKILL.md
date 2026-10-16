---
name: api-surface
description: Audits backend and internal APIs reachable by accident ("I thought only my frontend could call that"). Builds the real inventory of published ports, routes (Next.js route handlers, `pages/api`, Hono `showRoutes`), hosts (DNS, staging, CT logs) and old `/v1` mounts; flags services on `0.0.0.0` or Docker `ports:`, worker/bot endpoints trusting network location instead of service-to-service auth, origins reachable around Cloudflare, BFF catch-all proxies and `rewrites()` carrying a service token, backend keys in `NEXT_PUBLIC_*`, Swagger/introspection/`/metrics`/`--inspect` in production, whole-row responses (API3), unvalidated third-party responses (API10), and error passthrough. Use for multi-service or compose deploys, Next.js handlers or rewrites calling a backend, Hono/Express/Fastify/GraphQL APIs, apps behind Cloudflare or a proxy, and the recon step of a full audit. BFLA: secaudit:privilege-escalation; IDOR/SSRF: secaudit:web-vulns; header trust: secaudit:proxy-trust.
license: MIT
---

# API Surface (Accidentally Reachable Backends and Internal APIs)

Most API breaches in multi-service apps are not clever: someone found an endpoint the developer
didn't know was reachable. The Hono API "behind" Next.js that also listened on the VM's public IP;
the worker's `/jobs/run` that trusted the Docker network; the origin Cloudflare was meant to front;
a `/api/proxy/[...path]` handler forwarding any path with an admin token; the `/v1` nobody
unmounted. Each passes a functional test, because the test only uses the front door.

The AI-codegen failure mode is the shortest path from "frontend needs backend": a catch-all proxy
instead of one handler per endpoint, `NEXT_PUBLIC_API_KEY` so the browser calls the API directly,
`ports: ["8787:8787"]` because it made `curl` work, `swaggerUI(...)` from the tutorial,
`return c.json(user)` because the ORM type matched. None of these errors.

Findings map to the **OWASP API Security Top 10 (2023)**: **API9:2023 Improper Inventory
Management** (§1, §10); **API8:2023 Security Misconfiguration** (§2, §4, §6, §7, §11);
**API2:2023 Broken Authentication** (§3); **API3:2023 Broken Object Property Level Authorization**
(§8); **API10:2023 Unsafe Consumption of APIs** (§9). A BFF proxy (§5) is **API7:2023 Server Side
Request Forgery** when the client can influence the upstream host or URL; a proxy with a fixed
backend that forwards any path is function-level exposure (**API5:2023**, the
`secaudit:privilege-escalation` check) plus API8. In the **OWASP Top 10:2025**: **A01:2025**
(Broken Access Control), **A02:2025** (Security Misconfiguration), **A10:2025** (Mishandling of
Exceptional Conditions, §11).

This skill is about *what is reachable*. Per-endpoint questions belong elsewhere: admin/function
authorization in `secaudit:privilege-escalation`, IDOR in `secaudit:web-vulns`, and whether
`X-Forwarded-For` or `Remote-User` can be trusted in `secaudit:proxy-trust`.

## When to Use

- More than one deployable (`apps/web`, `apps/api`, `apps/worker`, `apps/bot`) or a compose file
  with more than one service.
- A Next.js Route Handler, Server Action, or `rewrites()` entry calls another backend; any
  `app/api/proxy/[...path]/route.ts`, `app/api/[...slug]/route.ts`, or `pages/api/[...path].ts`.
- A Hono/Express/Fastify/GraphQL server, OpenAPI/Swagger, `/metrics`, or a health route.
- The app sits behind Cloudflare, a CDN, or a reverse proxy and the origin is assumed unreachable.
- The **recon phase** of a full audit: §1's inventory decides what the other skills review.

Grep heuristics — these find most of it:

```bash
# Listeners and published ports
grep -rnE '\.listen\(|serve\((\{|app)|export default \{|Bun\.serve|hostname:|--hostname|-H 0\.0\.0\.0|--inspect' --include='*.[jt]s' --include='*.mjs' --exclude-dir=node_modules --exclude-dir=.next --include=package.json .
grep -rnE '^\s*EXPOSE' --include='Dockerfile*' . ; docker compose config 2>/dev/null | grep -nE 'published|host_ip|expose'
# Route inventory (Next route handlers + pages/api, Hono/Express/Fastify registrations)
find . -name node_modules -prune -o \( -path '*/app/*' -name 'route.[jt]s' -o -path '*/pages/api/*' \) -print
grep -rnE "app\.(route|basePath)\(|\.(get|post|put|patch|delete|all)\(['\"]/" --include='*.[jt]s' --include='*.mjs' --exclude-dir=node_modules --exclude-dir=.next .
# Proxies, rewrites, catch-all route handlers
grep -rnE 'rewrites\s*\(|destination:|createProxyMiddleware|reply\.from|hono/proxy' --include='*.[jt]s' --include='*.mjs' --exclude-dir=node_modules --exclude-dir=.next .
find . -name node_modules -prune -o -path '*\[...*\]*' -name 'route.[jt]s' -print
# Docs, introspection, debug, metrics; backend credentials headed for the browser
grep -rnE 'swagger|openapi|graphiql|introspection|landingPage|/graphql|/metrics|/debug|/health' --include='*.[jt]s' --include='*.mjs' --exclude-dir=node_modules --exclude-dir=.next .
grep -rnE 'NEXT_PUBLIC_[A-Z_]*(API|SERVICE|INTERNAL|SECRET|TOKEN|KEY)' --include='*.[jt]s' --include='*.[jt]sx' --exclude-dir=node_modules --exclude-dir=.next --include='.env*' .
```

## 1. Build the Real Inventory Before Judging Anything

**What to look for:** a mental model ("web talks to api, api talks to Postgres") never checked
against what actually listens, routes, and resolves. OWASP API9 treats an outdated host inventory
and "no retirement plan for each API version" as the vulnerability itself, and its fix is to
inventory every API host with its environment, intended audience, and version.

**Why it's exploitable:** an attacker enumerates from outside (DNS, CT logs, port scans, path
brute-forcing) and is not limited to the routes your frontend calls. Unlisted means unreviewed.

Build four lists, and treat every entry as internet-facing until shown otherwise:

1. **Services and ports.** `docker compose config` (resolved, after overrides) is the truth. Record
   each service's `ports:` (published to the host) vs `expose:` (container network only), every
   `listen(`/`serve(` and Dockerfile `EXPOSE`, and second listeners (a worker health server, a bot
   control endpoint, a metrics port). Confirm with `ss -lntp` and an **off-host** port scan.
2. **Routes.** Next.js: every `app/**/route.ts`, `pages/api/**`, every `'use server'` file (an
   exported action "is reachable via a direct POST request, not just through your application's
   UI"), and every `rewrites()` entry; `next build` prints a route table and `next build --debug`
   adds rewrites, redirects, and headers. Hono: `showRoutes()` from `hono/dev` prints every method
   and path of the composed app, including `app.route()` mounts. Fastify: `fastify.printRoutes()`.
   Express has no built-in lister; walk every `app.use`/`router.*` call.
3. **Hosts.** Every DNS record in the zone (including DNS-only records), every preview and staging
   hostname, and what certificate transparency says exists: CT logs are "publicly verifiable,
   append-only", and show "which CAs have issued which certificates, when, and for which domains"
   — search your apex on `crt.sh` and expect `staging.`, `api-old.`, `grafana.`.
4. **Versions.** Every `/v1`, `/v2`, `/legacy`, `/beta` prefix, and whether the old one has the
   same auth, validation, and rate limits as the current one (§10).

```ts
// scripts/print-routes.ts — run in CI (`npx tsx scripts/print-routes.ts`) and diff against the last run
import { showRoutes } from 'hono/dev'
import app from '../apps/api/src/app'   // the composed app, after every app.route() mount
showRoutes(app, { verbose: true, colorize: false })
```

A route in this output that is in neither your API docs nor your frontend is a finding to explain.

## 2. Internal Services Listening on Every Interface

**What to look for:** `ports: ["8787:8787"]` on an API, worker, or bot that only the proxy or web
app needs to reach; `server.listen(port)` / `serve({ fetch, port })` with no host; `next start`
(its `--hostname` default is `0.0.0.0`) on a VM with a public IP.

**Why it's exploitable:** Node's `server.listen()`: "If `host` is omitted, the server will accept
connections on the unspecified IPv6 address (`::`) when IPv6 is available, or the unspecified IPv4
address (`0.0.0.0`) otherwise." Compose `ports:` without a host IP binds all interfaces "bypassing
host firewall rules" — ufw included; the full Docker/ufw explanation and the datastore case are
`secaudit:docker-security` §6. An internal API is often worse than a datastore: it has *no*
password at all (§3).

```yaml
# docker-compose.yml — BAD: every service on the public interface "so I can curl it"
services:
  web:    { build: ./apps/web,    ports: ["3000:3000"] }
  api:    { build: ./apps/api,    ports: ["8787:8787"] }   # game-server API, now public on :8787
  worker: { build: ./apps/worker, ports: ["9000:9000"] }   # /jobs/run, /backups/trigger
  bot:    { build: ./apps/bot,    ports: ["3001:3001"] }   # /announce control endpoint
```

```yaml
# docker-compose.yml — GOOD: only the reverse proxy publishes. `default` is an ordinary bridge
# network: outbound internet works, inbound needs a `ports:` mapping, and nothing else has one.
services:
  proxy:  { image: caddy:2, ports: ["80:80", "443:443"], networks: [default] }  # the one public entry
  web:    { build: ./apps/web,    expose: ["3000"], networks: [default, data] }
  api:    { build: ./apps/api,    expose: ["8787"], networks: [default, data] }  # egress: game servers
  worker: { build: ./apps/worker, networks: [default, data] }  # egress: Discord webhooks, offsite backups, DNS
  bot:    { build: ./apps/bot,    networks: [default, data] }  # egress: Discord gateway
  db:     { image: postgres, networks: [data] }               # no ports, no egress (pin it: docker-security §4)
networks:
  data: { internal: true }   # "an externally isolated network": no internet in or out
```

Only put a service *solely* on an `internal: true` network if it needs no outbound access at all —
a worker or bot there can't reach Discord. Every service on `default` can still reach every other
service's exposed port, which is why §3 matters. If a human needs host access, publish on loopback
(`"127.0.0.1:8787:8787"`) and use an SSH tunnel.

## 3. "Internal" Means Unauthenticated: Add Service-to-Service Auth

**What to look for:** worker, bot, or admin routes with no auth because "only the web app calls
them" — `POST /jobs/run`, `/webhooks/dispatch`, `/backups/trigger`, `/domains/:id/verify`,
`/announce`; an internal router mounted on the public API's app and port; `// internal only` in
place of a check.

**Why it's exploitable:** network location is not identity. §2 is one way the "internal" network
becomes the internet; others are an SSRF anywhere in the stack (`secaudit:web-vulns` §2), a
compromised dependency in any container on the same network, a BFF proxy that forwards arbitrary
paths (§5), or an origin reachable around the gateway (§4). Then every unauthenticated internal
endpoint runs with its own privileges, and job-runner and backup endpoints tend to have all of them.

**Fix:** every service authenticates every caller with a credential specific to that caller:

- **Signed requests (HMAC)** with a per-caller secret and a timestamp window. Simple, no infrastructure.
- **Short-lived signed tokens** (a JWT with `aud` = the target service, expiry in seconds-to-minutes)
  when the call is on behalf of a user and the user id must travel with it (§5).
- **mTLS** with a per-service client certificate from your internal CA. Strongest, most overhead.

Give web, worker, and bot **separate** credentials, and apply the check on the internal router.
The helper below signs the canonical string `METHOD \n pathname+search \n timestamp \n
sha256-hex(body)`, where the timestamp is Unix epoch **milliseconds**. The query string is signed
so `?serverId=` can't be swapped, and the body is size-capped before it is hashed.

```ts
// packages/internal-auth/src/hmac.ts — shared by caller and receiver
import { createHmac, createHash, timingSafeEqual } from 'node:crypto'
import type { MiddlewareHandler } from 'hono'

const MAX_SKEW_MS = 60_000
const MAX_BODY = 1_000_000
const canonical = (method: string, url: URL, ts: number, body: Uint8Array) =>
  `${method}\n${url.pathname}${url.search}\n${ts}\n${createHash('sha256').update(body).digest('hex')}`

// Caller (web, bot): its own secret, never shared with another caller
export function signedFetch(caller: string, secret: string, url: URL, method: string, body = new Uint8Array()) {
  const ts = Date.now()
  const sig = createHmac('sha256', secret).update(canonical(method, url, ts, body)).digest('hex')
  return fetch(url, {
    method, body: body.byteLength ? body : undefined, redirect: 'error', signal: AbortSignal.timeout(5_000),
    headers: { 'x-svc-caller': caller, 'x-svc-timestamp': String(ts), 'x-svc-signature': sig },
  })
}

// Receiver (worker): secrets keyed by caller name; an unset secret fails closed
export const requireServiceAuth = (secrets: Record<string, string | undefined>): MiddlewareHandler => async (c, next) => {
  const caller = c.req.header('x-svc-caller') ?? ''
  const secret = Object.hasOwn(secrets, caller) ? secrets[caller] : undefined
  const ts = Number(c.req.header('x-svc-timestamp'))
  if (!secret || !Number.isFinite(ts) || Math.abs(Date.now() - ts) > MAX_SKEW_MS) return c.json({ error: 'unauthorized' }, 401)
  if (Number(c.req.header('content-length') ?? 0) > MAX_BODY) return c.json({ error: 'too large' }, 413)
  const body = new Uint8Array(await c.req.raw.clone().arrayBuffer())
  if (body.byteLength > MAX_BODY) return c.json({ error: 'too large' }, 413)   // chunked bodies
  const sig = Buffer.from(c.req.header('x-svc-signature') ?? '', 'hex')
  const expected = createHmac('sha256', secret).update(canonical(c.req.method, new URL(c.req.url), ts, body)).digest()
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return c.json({ error: 'unauthorized' }, 401)
  c.set('caller', caller)
  await next()
}

// apps/worker/src/server.ts — the check sits on the router, ahead of every internal route
const internal = new Hono()
internal.use('*', requireServiceAuth({ web: process.env.INTERNAL_SECRET_WEB }))
internal.post('/jobs/run', runJobHandler)
app.route('/internal', internal)
```

The receiver must see the same path and query the caller signed. A proxy that rewrites either
breaks verification, which is correct: don't loosen the check to fix it. To stop replays inside
the window, remember seen signatures for the window's length (`secaudit:webhook-security` §1).
Hono's `bearerAuth` (`hono/bearer-auth`: a token, an array of tokens, or `verifyToken`) is
acceptable for low-stakes calls with one token per caller, but a captured bearer token stays
reusable until rotated.

## 4. The Origin Is Reachable Around Cloudflare or the Proxy

**What to look for:** a WAF, rate limit, or Cloudflare Access policy at the edge, and an origin
whose 80/443 (or app port) accepts any IP. DNS-only (grey-cloud) records on the origin's IP. Mail
served from the web server. A `staging.` or `direct.` hostname in CT logs pointing at the origin.

**Why it's exploitable:** every edge control is skipped by connecting to the origin IP with the
right `Host` header. And origin IPs leak. Cloudflare's DNS troubleshooting page: for a DNS-only
record sharing the origin, "a dig query against that record reveals your origin server's IP
address". Its origin-protection guide adds SPF/TXT records, mail bounces from a co-hosted mail
server, and historical DNS, and recommends rotating origin IPs after onboarding. An attacker on the
origin also sets any `X-Forwarded-*` / `CF-Connecting-IP` they like (`secaudit:proxy-trust` §5).

**Fix, strongest first:**

- **Cloudflare Tunnel.** `cloudflared` "connects your resources to Cloudflare without a publicly
  routable IP address", so the host needs no inbound port at all; the web/proxy service keeps only
  `expose:`. Tunnel setup and the Access-JWT side are in `secaudit:proxy-trust` §5.
- **Authenticated Origin Pulls (mTLS).** The origin requires a Cloudflare client certificate. The
  *global* AOP certificate is shared across all Cloudflare accounts and only proves the request came
  from Cloudflare's network; **zone-level** or **per-hostname** AOP with your own certificate is
  "exclusive to your account". AOP needs SSL mode Full or Full (strict), not Off or Flexible.
- **Allowlist Cloudflare's IP ranges** at the host or cloud firewall (from `cloudflare.com/ips`, kept
  current). Cloudflare's origin-protection guide notes this alone is vulnerable to IP spoofing; layer
  it with AOP or the guide's application-layer options (a secret edge-added header, JWT validation).
- Then proxy every record that shares the origin IP, move mail elsewhere, and **rotate the origin IP**
  once locked down, since the old one is in historical DNS forever.

Verify from outside: `curl -sk --resolve app.example.com:443:<origin-ip> https://app.example.com/`
should fail to connect (Tunnel), or fail the TLS handshake / get rejected (AOP or IP allowlist).

## 5. BFF Route Handlers and Rewrites That Act as Open Proxies

**What to look for:** a Next.js catch-all that forwards the incoming path, method, query, and
headers to the backend with a service credential attached:

```ts
// app/api/proxy/[...path]/route.ts — BAD: the browser can now call ANY backend route as the BFF
const API = process.env.INTERNAL_API_URL!            // http://api:8787
async function handler(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params
  return fetch(`${API}/${path.join('/')}${new URL(req.url).search}`, {
    method: req.method,                               // any verb, including DELETE
    headers: { ...Object.fromEntries(req.headers), authorization: `Bearer ${process.env.API_SERVICE_TOKEN}` },
    body: req.method === 'GET' ? undefined : req.body,
    duplex: 'half',
  })
}
export { handler as GET, handler as POST, handler as PUT, handler as PATCH, handler as DELETE }
```

and the config equivalent. Next's docs describe rewrites as acting "as a URL proxy" that masks the
destination, with external destinations and `:path*` wildcards supported. So
`{ source: '/api/:path*', destination: 'http://api:8787/:path*' }` publishes the backend's whole
route tree under the web app's hostname, and a `fallback` rewrite to an internal service does the
same for every path Next doesn't handle.

**Why it's exploitable:**

- **Confused deputy.** The backend trusts the BFF's service token, so every route it exposes to the
  BFF — `/admin/*`, `/internal/*` — is now exposed to every browser with the BFF's privileges.
- **Path traversal out of the allowed prefix.** `..`, often percent-encoded so the BFF's check and the
  backend's router decode differently. A recurring proxy-library bug: **CVE-2025-66415** in
  `@fastify/reply-from` let a crafted URL with `%2e%2e` reach "routes that are not allowed, even
  though the `reply.from` is defined for specific routes" (fixed in **12.5.0**).
- **Header passthrough.** Copying `req.headers` forwards the user's `Cookie` and `Authorization`, a
  client-chosen `Host`, and `X-Forwarded-*`/identity headers the backend may trust
  (`secaudit:proxy-trust`). `Connection` is its own trap: **CVE-2026-33805** let a client list
  proxy-added headers in `Connection` so `@fastify/reply-from` / `@fastify/http-proxy` stripped
  them *after* injection, removing access-control headers upstream (fixed in **12.6.2** for
  reply-from and **11.4.4** for http-proxy). Hono's `proxy()` "ignores the `Connection` header to
  prevent Hop-by-Hop Header Injection attacks" by default, and its docs say to forward all request
  headers "only when forwarding all the request data (including credentials) is necessary".
- **Host-based routing that matches too loosely.** **CVE-2026-55602**: `http-proxy-middleware`'s
  host+path `router` used substring matching, so `Host: evillocalhost:3000` matched a
  `localhost:3000/api` key and routed to an unintended backend (fixed in **2.0.10**, **3.0.6** and
  **4.1.0**).
- **Client headers steering self-hosted Next.js.** **CVE-2024-34351**: in self-hosted Next.js using
  Server Actions, an action that redirects to a relative path starting with `/` could, with a
  modified `Host` header, make requests that appear to originate from the server (fixed in
  **14.1.1**). **CVE-2025-57822**: `next()` in middleware without the request object could lead to
  SSRF in self-hosted apps forwarding user-supplied headers (fixed in **14.2.32** and **15.4.7**).
  Current `next` advisories (rewrite smuggling, the 2026 proxy-bypass series) are in
  `secaudit:framework-versions`.
- **`proxy.ts` is not the boundary.** In Next.js 16 the `middleware` convention "is deprecated and
  has been renamed to `proxy`"; Next warns a matcher change "can silently remove Proxy coverage" for Server Functions.
  Authorize in the handler that makes the call (`secaudit:auth`).

**Fix:** an explicit allowlist of operations, the *user* authorized on every call, and a
user-scoped upstream credential instead of a god token.

```ts
// app/api/servers/[serverId]/status/route.ts — GOOD: one operation, one method, one upstream path
import 'server-only'
import { z } from 'zod'
import { getSession } from '@/lib/auth'
import { callApi } from '@/lib/internal-api'

const Params = z.object({ serverId: z.uuid() })   // Zod 4; on Zod 3, z.string().uuid()

// RouteContext is a global type generated by `next dev` / `next build` / `next typegen` (Next 15.5+)
export async function GET(_req: Request, ctx: RouteContext<'/api/servers/[serverId]/status'>) {
  const session = await getSession()
  if (!session) return Response.json({ error: 'unauthorized' }, { status: 401 })
  const parsed = Params.safeParse(await ctx.params)
  if (!parsed.success) return Response.json({ error: 'bad request' }, { status: 400 })
  // The backend still checks this user may see this server (object-level authz, web-vulns §4).
  const res = await callApi(`/servers/${parsed.data.serverId}/status`, { method: 'GET', actAs: session.user.id })
  if (!res.ok) return Response.json({ error: 'upstream error' }, { status: 502 })   // never relay (§11)
  return Response.json(await res.json())                                            // backend returns a DTO (§8)
}
```

```ts
// lib/internal-api.ts — GOOD: the only code path that talks to the backend
import 'server-only'
const BASE = new URL(process.env.INTERNAL_API_URL!)   // http://api:8787
const SAFE_PATH = /^\/[A-Za-z0-9/_-]+$/               // allowlist: no %, ., ?, #, \, or non-ASCII

export async function callApi(path: string, opts: { method: 'GET' | 'POST'; actAs: string; body?: unknown }) {
  if (!SAFE_PATH.test(path) || path.includes('//')) throw new Error('bad path')   // '//x' is a host
  const url = new URL(path, BASE)
  if (url.origin !== BASE.origin) throw new Error('bad path')                     // never leave the backend
  return fetch(url, {
    method: opts.method,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${await mintUserToken(opts.actAs)}` },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
  })
}
```

If a generic proxy is unavoidable, it needs all of these:
- an explicit route table (method + path pattern) matched against a path that passes a
  *character allowlist* like `SAFE_PATH`. Deny-lists of `..` / `%2e` lose to double encoding
  (`%252e`), `/./`, `//host`, and Unicode lookalikes;
- a check that the constructed URL's origin equals the backend's;
- a request-header allowlist (drop `host`, `cookie`, `authorization`, `connection`,
  `x-forwarded-*`, identity headers);
- a per-user upstream credential;
- the backend refusing the BFF's credential on admin and internal routes.

For `rewrites()`, use exact sources or constrained params (`:id(\\d{1,})`) instead of `:path*`, and
never point one at an internal-only service.

## 6. Backend Keys Shipped to the Browser

**What to look for:** `NEXT_PUBLIC_API_KEY`, `NEXT_PUBLIC_GAME_API_TOKEN`, or a client component
calling the backend with `Bearer ${process.env.NEXT_PUBLIC_…}`. Next "exposes any environment
variable prefixed with `NEXT_PUBLIC_` to the client"; the prefix rules are `secaudit:secrets`.

**Why it's exploitable:** the backend becomes a public API whose one credential is in every
visitor's bundle, and it is usually published (§2) so the browser can reach it — two findings.

**Fix:** the browser authenticates as the *user* (session cookie to the BFF, or a short-lived
per-user token minted server-side); backend credentials stay in server-only modules. Keys for
external callers (game servers posting to the API) are per-caller, stored hashed, scoped to that
caller's resources, revocable, and never reused as the web app's key.

## 7. Docs, Introspection, Metrics, and Debuggers Live in Production

**What to look for:**

- **OpenAPI / Swagger UI.** `@hono/swagger-ui`'s example mounts `app.get('/ui', swaggerUI({ url: '/doc' }))`
  with no access control; `@fastify/swagger-ui` defaults to `routePrefix` `/documentation` and
  offers `uiHooks` to protect it. The spec lists every route, including ones the frontend never calls.
- **GraphQL.** Apollo Server's `introspection` default "is `true`, **unless** the `NODE_ENV`
  environment variable is set to `production`", and its landing page is an embedded Apollo Sandbox
  when `NODE_ENV` isn't `production` — so the real failure is a container with `NODE_ENV` unset, or
  `introspection: true` hardcoded. GraphQL Yoga serves GraphiQL "only when in development" by
  default, warns that disabling it "does not really make your GraphQL server more secure", and
  points to `useDisableIntrospection` (`@graphql-yoga/plugin-disable-introspection`) and persisted
  operations for untrusted clients.
- **Prometheus `/metrics`.** Prometheus says "the `/metrics` endpoint of instrumented binaries"
  "should not be exposed to publicly accessible networks like the internet", and "metrics are not
  considered secret" — labels with user ids, emails, or internal hostnames are readable by anyone.
- **Node inspector.** `--inspect=0.0.0.0` or `NODE_OPTIONS=--inspect` in compose or a start script.
  Default is `127.0.0.1:9229`; "If the debugger is bound to a public IP address, or to 0.0.0.0, any
  clients that can reach your IP address will be able to connect to the debugger without any
  restriction and will be able to run arbitrary code." Unauthenticated RCE.
- **Debug and health routes.** `/debug`, `/_debug/env`, `/__routes`, a `/health` returning
  `process.env`, versions, DB hosts, or queue contents; `next dev` as a production `CMD`.

**Why it's exploitable:** each hands the attacker §1's inventory, or for the inspector, the process.
OWASP's API9 overview names "exposed debug endpoints" as an inventory failure, and API9 says to
"Make API documentation available only to those authorized to use the API"; API8 lists
"Unnecessary features are enabled".

```ts
// apps/api/src/app.ts — GOOD: docs off unless explicitly enabled, and never anonymous
import { Hono } from 'hono'
import { basicAuth } from 'hono/basic-auth'
import { swaggerUI } from '@hono/swagger-ui'

if (process.env.EXPOSE_API_DOCS === 'true') {
  const docs = new Hono()
  docs.use('*', basicAuth({ username: 'docs', password: process.env.API_DOCS_PASSWORD! }))
  docs.get('/openapi.json', (c) => c.json(openApiDocument))
  docs.get('/', swaggerUI({ url: '/_docs/openapi.json' }))
  app.route('/_docs', docs)
}

// GraphQL — explicit, not inferred from NODE_ENV
const server = new ApolloServer({
  schema,
  introspection: process.env.GRAPHQL_INTROSPECTION === 'true',
  plugins: [ApolloServerPluginLandingPageDisabled()],
})
```

Serve `/metrics` on a separate port with `expose:` and never `ports:`. Health checks need a status
code, not a payload: `200 ok` from `/healthz`, anything diagnostic behind service auth (§3).

## 8. Excessive Data Exposure: Returning the Whole Row (API3)

**What to look for:** `return c.json(user)`, `res.json(await prisma.user.findUnique(...))`, a
`SELECT *` result serialized to the client with the frontend expected to hide fields; Server
Actions returning `db.user.update(...)`.

**Why it's exploitable:** the client sees every column — password and API-key hashes, email, IP,
internal flags, the game server's RCON password — and a column added later is published silently.
OWASP API3:2023 merges excessive data exposure with mass assignment and says to "Avoid using
generic methods such as `to_json()` and `to_string()`", "cherry-pick specific object properties",
and "Implement a schema-based response validation mechanism". Next's data-security guide: "Only
return what the UI needs, not raw database records".

**Fix:** a response DTO per endpoint. A Zod object schema strips by default ("unrecognized keys
are *stripped* from the parsed result"), so parse the outgoing object through it; use
`z.strictObject()` in tests to fail when the source grows an unclassified field.

```ts
// BAD — every column, including ones added next quarter
app.get('/servers/:id', async (c) => c.json(await db.query.servers.findFirst({ where: eq(servers.id, c.req.param('id')) })))

// GOOD — the response schema is the contract; anything not listed never leaves
const ServerPublic = z.object({
  id: z.uuid(), name: z.string(), region: z.string(),
  playerCount: z.number().int(), status: z.enum(['online', 'offline', 'starting']),
})
app.get('/servers/:id', async (c) => {
  const row = await getServerForUser(c.get('userId'), c.req.param('id'))   // authz: web-vulns §4
  if (!row) return c.json({ error: 'not found' }, 404)
  return c.json(ServerPublic.parse(row))                                   // strips rconPassword, apiKeyHash…
})
```

The input-side half of API3 (mass assignment from a spread request body) is `secaudit:data-access`.

## 9. Unsafe Consumption of Third-Party APIs (API10)

**What to look for:** responses from Discord, a game server's HTTP/query API, an OAuth userinfo
endpoint, or a DNS/domain-verification lookup used directly as a DB write, an HTML render, a shell
argument, or the next URL to fetch; `fetch` with no timeout; redirects followed by default.

**Why it's exploitable:** OWASP API10:2023 notes that developers trust third-party data more than
user input, and lists the gaps: unencrypted channels, not validating "data gathered from other APIs
prior to processing it", "Blindly follows redirections", unbounded resources, and no timeouts. A
game server is often run by a *customer*, so its responses are attacker-controlled by definition.

```ts
// GOOD — validate shape and size, bound time, refuse redirects, TLS only
const GameStatus = z.object({ players: z.number().int().min(0).max(10_000), map: z.string().max(64) })
export async function fetchGameStatus(host: string) {     // host from your DB, re-checked per web-vulns §2
  const res = await fetch(new URL('/status', `https://${host}`), { redirect: 'error', signal: AbortSignal.timeout(3_000) })
  if (!res.ok || Number(res.headers.get('content-length') ?? 0) > 64_000) throw new Error('bad upstream')
  return GameStatus.parse(await res.json())                // reject, don't coerce
}
```

Verify inbound callbacks before consuming them (`secaudit:webhook-security`) and run user-influenced
outbound fetches through `secaudit:web-vulns` §2. API10 is what you do with the answer.

## 10. Staging, Preview, and Old API Versions

**What to look for:** `app.route('/v1', v1)` still mounted next to `/v2` where v1 predates the auth
or validation fix; a `beta.`/`staging.` host running the same code with rate limits, Access, or WAF
rules only on production; previews connected to the production database.

**Why it's exploitable:** OWASP API9's first scenario is exactly this: a password-reset rate limit
in front of the production host but not on a beta host running the same logic, so the reset token
was brute-forced there. API9 says to protect "all exposed versions of your APIs, not just for the
current production version", and to keep production data out of non-production deployments or
secure them as strictly as production.

**Fix:** retire old versions on a schedule. A retired prefix answers `410 Gone` from a catch-all
that logs who still calls it, and its old handlers are deleted, not left routed. Every environment
gets the same edge controls and its own credentials and database (`secaudit:deployment` covers
preview isolation and Vercel Deployment Protection).

## 11. Error Handlers and 404s That Map Your Topology

**What to look for:** a BFF relaying the backend's error body (`new Response(await upstream.text(),
{ status: upstream.status })`), so a 500 shows `connect ECONNREFUSED 172.18.0.5:8787` or an API
stack trace; framework default error pages; `X-Powered-By`; internal prefixes answering
"unauthorized" where unknown paths answer "not found".

**Why it's exploitable:** each leak narrows §1's search: internal hosts, service names, framework
versions, which internal routes exist. OWASP API8 lists error messages that "include stack traces,
or expose other sensitive information" and recommends schemas for "error responses". Express sends
`X-Powered-By` plus its own 404/error messages by default (`app.disable('x-powered-by')`); Next.js
adds `x-powered-by` by default (`poweredByHeader: false`).

**Fix:** map upstream failures to a generic `502`/`503` with a correlation id at the BFF, give every
API explicit handlers, and return the same `404` under internal prefixes as anywhere else. Logging
and stack traces are `secaudit:logging-monitoring` §1.

```ts
app.notFound((c) => c.json({ error: 'not found' }, 404))
app.onError((err, c) => { const ref = crypto.randomUUID(); logger.error({ ref, err }); return c.json({ error: 'internal error', ref }, 500) })
```

## Map-the-Surface Checklist

Run this before the per-domain review; it decides what the other skills look at.

- `docker compose config` resolved; each service's `ports:` vs `expose:` recorded; each published
  port justified as an intended public entry; `ss -lntp` and an off-host scan agree.
- Every route listed for every service: `app/**/route.ts`, `pages/api/**`, `'use server'` files,
  `rewrites()` (`next build --debug`), Hono `showRoutes`, Fastify `printRoutes`.
- Every hostname listed — DNS zone (incl. DNS-only), preview/staging, CT search on the apex — with
  environment, owner, and audience.
- Every API version prefix with auth/validation/rate-limit parity or a retirement date; every
  service-to-service call with its credential.
- Origin tested directly by IP with the production `Host` header.

Then flag any of:

- `ports:` on an API/worker/bot only the proxy needs; `listen(port)` / `next start` with no host on
  a public VM.
- An internal route with no service auth, or one secret shared by every service.
- An origin that accepts non-Cloudflare traffic, or global-certificate AOP treated as proof the
  traffic is *yours*.
- A catch-all `[...path]` handler or `:path*` rewrite to a backend; `req.headers` copied upstream;
  a deny-list path check; a service token where a per-user credential belongs.
- `NEXT_PUBLIC_*` holding a backend key.
- Anonymous Swagger / OpenAPI / introspection / Sandbox; `NODE_ENV` unset in production;
  `/metrics` on the public listener; `--inspect` off loopback; a chatty health endpoint.
- `c.json(row)` with no response schema; third-party responses with no validation, timeout, size
  bound, or redirect policy.
- `/v1` still routed to handlers; staging on production data; upstream error bodies or
  `X-Powered-By` reaching clients.

## Related skills

- `secaudit:privilege-escalation` — whether a non-admin can call the admin/internal routes §1 finds (API5).
- `secaudit:web-vulns` — IDOR on inventoried routes (§4 there); the SSRF guard for outbound fetches (§2 there).
- `secaudit:proxy-trust` — forwarded/identity-header trust; Cloudflare Tunnel and Access JWT verification (§5 there).
- `secaudit:deployment` — CORS, security headers, source maps, preview-deployment isolation.
- `secaudit:docker-security` — datastore ports, Docker vs ufw, image pinning, compose secrets.
- `secaudit:secrets` — client-inlined env prefixes and handling a leaked backend key.
- `secaudit:auth` — `proxy.ts` (formerly middleware) is not the boundary; Server Actions are public endpoints.
- `secaudit:cloudflare-workers-security` — the same questions for a Hono API on Workers.
- `secaudit:framework-versions` — Next.js rewrite-smuggling and proxy-bypass advisories by version.
- `secaudit:logging-monitoring` — stack traces and internals in error responses.
- `secaudit:realtime-security` — SSE, long-poll, and WebSocket endpoints found in the inventory.

## Sources

- https://api-security.owasp.org/editions/2023/en/0x11-t10/ -- OWASP API Security Top 10 2023 names; API9 overview cites exposed debug endpoints
- https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication/ -- API2:2023 Broken Authentication
- https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/ -- API3:2023; avoid to_json(), cherry-pick properties, schema-based response validation
- https://api-security.owasp.org/editions/2023/en/0xa7-server-side-request-forgery/ -- API7:2023 Server Side Request Forgery
- https://api-security.owasp.org/editions/2023/en/0xa8-security-misconfiguration/ -- API8:2023; unnecessary features, stack traces in errors, error-response schemas
- https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/ -- API9:2023; inventory, retirement plan, docs only for authorized users, beta-host scenario, protect all versions
- https://api-security.owasp.org/editions/2023/en/0xaa-unsafe-consumption-of-apis/ -- API10:2023; validation, redirects, resource limits, timeouts
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025
- https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/ -- A10:2025, where §11 lands
- https://nextjs.org/docs/app/api-reference/config/next-config-js/rewrites -- rewrites act as a URL proxy; external destinations; `:path*`; fallback; regex params
- https://nextjs.org/docs/app/api-reference/file-conventions/proxy -- middleware deprecated and renamed to proxy in v16.0.0; matcher changes can drop Server Function coverage
- https://nextjs.org/docs/app/guides/data-security -- Server Actions reachable via direct POST; DTOs; return only what the UI needs; NEXT_PUBLIC_ exposure
- https://nextjs.org/docs/app/api-reference/cli/next -- `next build` route table, `--debug` adds rewrites/redirects/headers, `next start` hostname default 0.0.0.0
- https://nextjs.org/blog/next-15-5 -- globally generated `RouteContext`/`PageProps`/`LayoutProps`; `next typegen`
- https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader -- x-powered-by on by default; `poweredByHeader: false`
- https://fastify.dev/docs/latest/Reference/Server/ -- `printRoutes()` route listing
- https://hono.dev/docs/helpers/dev -- `showRoutes` from `hono/dev`
- https://hono.dev/docs/middleware/builtin/bearer-auth -- `bearerAuth` token / token array / `verifyToken`
- https://hono.dev/docs/middleware/builtin/basic-auth -- `basicAuth` from `hono/basic-auth`
- https://hono.dev/docs/helpers/proxy -- `proxy()` ignores `Connection` by default; forward all headers only when necessary
- https://hono.dev/examples/swagger-ui -- `@hono/swagger-ui` on a GET route; no access control in the example
- https://github.com/fastify/fastify-swagger-ui -- default `routePrefix` `/documentation`; `uiHooks` for protecting docs routes
- https://www.apollographql.com/docs/apollo-server/api/apollo-server -- `introspection` default true unless NODE_ENV=production
- https://www.apollographql.com/docs/apollo-server/api/plugin/landing-pages -- Sandbox landing page outside production; `ApolloServerPluginLandingPageDisabled`
- https://the-guild.dev/graphql/yoga-server/docs/features/graphiql -- GraphiQL only in development by default; disabling it is not a security control
- https://the-guild.dev/graphql/yoga-server/docs/features/introspection -- `useDisableIntrospection`; persisted operations
- https://prometheus.io/docs/operating/security/ -- `/metrics` not for public networks; metrics not considered secret
- https://nodejs.org/learn/getting-started/debugging -- inspector default 127.0.0.1:9229; 0.0.0.0 binding allows arbitrary code; use SSH tunnels
- https://nodejs.org/api/net.html -- `server.listen()` with no host binds `::` / `0.0.0.0`
- https://docs.docker.com/reference/compose-file/services/ -- `expose` not published to host; `ports` without host IP bind 0.0.0.0, bypassing host firewall rules
- https://docs.docker.com/reference/compose-file/networks/ -- external connectivity by default; `internal: true` creates an externally isolated network
- https://docs.docker.com/engine/network/port-publishing/ -- publishing is insecure by default; loopback publishing
- https://docs.docker.com/engine/network/packet-filtering-firewalls/ -- Docker and ufw incompatible
- https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/ -- Tunnel, AOP, IP allowlist (spoofing caveat), SPF/TXT audit, mail separation, rotate origin IPs
- https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/exposed-ip-address/ -- "a dig query against that record reveals your origin server's IP address"
- https://developers.cloudflare.com/learning-paths/prevent-ddos-attacks/advanced/protect-origin-ip/ -- rotate origin IPs; no mail on the protected server
- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/ -- global vs zone-level vs per-hostname AOP; Full/Full (strict) required
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/ -- origin connects outbound; no publicly routable IP needed
- https://www.cloudflare.com/ips/ -- current Cloudflare IP ranges
- https://certificate.transparency.dev/ -- CT logs are public, append-only, and show certificates per domain
- https://expressjs.com/en/advanced/best-practice-security/ -- reduce fingerprinting: `x-powered-by`, default 404 and error messages
- https://zod.dev/api -- object schemas strip unrecognized keys by default; `z.strictObject()`; `z.uuid()`
- https://api.osv.dev/v1/vulns/CVE-2025-66415 -- @fastify/reply-from `%2e%2e` route bypass; fixed 12.5.0
- https://api.osv.dev/v1/vulns/CVE-2026-33805 -- Connection header strips proxy-added headers; fixed reply-from 12.6.2, http-proxy 11.4.4
- https://api.osv.dev/v1/vulns/CVE-2026-55602 -- http-proxy-middleware router host+path substring match; fixed 2.0.10 / 3.0.6 / 4.1.0
- https://api.osv.dev/v1/vulns/CVE-2024-34351 -- self-hosted Next.js Server Actions relative redirect + modified Host header SSRF; fixed 14.1.1
- https://api.osv.dev/v1/vulns/CVE-2025-57822 -- Next.js middleware `next()` SSRF when forwarding user headers; fixed 14.2.32 / 15.4.7
