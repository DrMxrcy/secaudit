---
name: multi-tenant-isolation
description: Audits multi-tenant apps for tenant isolation outside the database row, where cross-tenant leaks happen with no auth bug anywhere. Covers tenant resolution (tenant id from the session's current membership, never from a body, query, `x-tenant-id`/`x-org-id` header, or subdomain alone), host→tenant routing and custom domains (unknown hosts 404 instead of a default tenant, reserved and reused slugs, deleted-tenant subdomains), cache keys that drop the tenant (Redis/KV, Next.js `unstable_cache` / `'use cache'` keys and tags, CDN `Cache-Control: private`), background jobs, queues and cron that lose or trust tenant context (BullMQ, pg-boss, Inngest), inbound webhook→tenant mapping, search indexes and vector stores (Meilisearch tenant tokens, Algolia secured API keys, Elasticsearch document-level security, pgvector filters), and support impersonation. Use whenever the app has organizations, workspaces, teams, communities, or tenants, serves tenants on subdomains or custom domains, or is audited for cross-tenant data leaks. A hub: RLS, ORM scoping, realtime rooms, storage keys, custom-domain verification, and IDOR are pointers to the skills that own them (§8).
license: MIT
---

# Multi-Tenant Isolation

In a multi-tenant app one database, one cache, one queue and one search cluster hold every
customer's data. What keeps them apart is a tenant id, and that id has to be right at every place
where data is selected. Row-level security and ORM scoping guard the database. This skill covers
the places those controls never see. The questions are: who picks the tenant id, what happens to it
on the way from the request to a cache key, a job payload, a webhook, a search filter, or a support
session, and whether each of those places still applies it.

The usual AI-codegen mistake is a working tenant check on the main request path and none on the
side paths. The route checks membership, but the cache key, the queued job, the search key handed
to the browser, and the support "log in as" button do not. Findings map to OWASP **A01:2025**
(Broken Access Control). The OWASP Multi-Tenant Security Cheat Sheet lists the threat classes:
tenant context injection, broken isolation at the cache and storage layers, shared-resource
poisoning, and admin functions that reach other tenants.

This is a hub. Database-level isolation (RLS in force, a non-owner runtime role, per-transaction
`set_config`), realtime rooms, storage key prefixes, custom-domain verification, and IDOR basics
are owned by other skills. §8 maps each one to its section. Read those first and don't duplicate
them here.

## When to Use

- The schema has a `tenant_id`, `organization_id`, `org_id`, `workspace_id`, `team_id`, or
  `community_id` column, or the app uses Better Auth's organization plugin, Clerk Organizations, or
  a hand-rolled membership table.
- Tenants are served on subdomains (`acme.app.example.com`) or customer custom domains.
- The app has a cache (Redis, Upstash, KV, Next.js data cache, a CDN), a job queue or cron, inbound
  webhooks from per-tenant integrations, a search or vector index, or a support or impersonation
  feature.

Find the tenant surface first. Every grep in this skill excludes `node_modules`. In a tree with
build output, also add `--exclude-dir=.next --exclude-dir=dist --exclude-dir=build`:

```bash
grep -rnwE --include='*.ts' --include='*.prisma' --include='*.sql' --exclude-dir=node_modules \
  'tenantId|tenant_id|organizationId|organization_id|orgId|org_id|workspaceId|workspace_id|communityId|community_id' . | head -50
```

## 1. Tenant Resolution: Membership Is the Grant, Everything Else Is a Hint

**Why it matters:** the tenant id decides which slice of the data every later query, cache key and
job sees. If it comes from anything the client writes (a body field, a query string, an
`x-tenant-id` header, the subdomain), one member can set it to another tenant's id. A host, path
slug, or "active organization" selection may *choose* among tenants the user belongs to. It is
never the grant.

**What to look for:**

- An `x-tenant-id` / `x-org-id` / `x-workspace-id` header read by the API, often added "so the
  mobile app can switch orgs".
- The tenant taken from the subdomain or path with only a session check and no membership check. A
  session that is valid on tenant A's host then works on tenant B's host. A domain-wide cookie makes
  this worse (`secaudit:auth`, "1. One Host-Only `__Host-` Cookie per Host, and Session Rows Bound
  to Their Host").
- **Parent/child mismatch:** membership checked for `:orgId`, then the object fetched by
  `:projectId` alone. The check passes for your org, and the row belongs to someone else's.
- Membership read from a JWT claim or a session field set at sign-in or at org switch and never
  re-checked. A removed member keeps access until the token expires. Better Auth's
  `activeOrganizationId` records which org the user last selected. Treat it as a selection and still
  check the member's current role on each request (`secaudit:better-auth-security` §6 shows the
  server-side `hasPermission` call).
- A staff bypass inside the resolver (`if (user.isStaff) return next()`). That is §7's problem and
  needs §7's controls.

```ts
// BAD — the caller picks the tenant; the session only proves *someone* is signed in
app.use('/api/*', async (c, next) => {
  await requireSession(c);
  c.set('tenantId', c.req.header('x-tenant-id') ?? c.req.query('orgId'));   // attacker-chosen
  await next();
});
app.get('/api/projects/:id', async (c) =>
  c.json(await db.select().from(projects).where(eq(projects.id, c.req.param('id')))));  // no tenant predicate
```

```ts
// GOOD — the path is a hint, current membership is the grant, every query carries the resolved id
app.use('/api/t/:slug/*', async (c, next) => {
  const session = await requireSession(c);                                  // server-verified cookie
  const tenant = await liveTenantBySlug(c.req.param('slug'));               // hint -> row (null if deleted)
  const member = tenant && (await membership(session.userId, tenant.id));   // fresh, per request
  if (!member || member.status !== 'active') return c.notFound();           // 404: don't confirm it exists
  c.set('tenant', { id: tenant.id, role: member.role });
  await next();
});

app.get('/api/t/:slug/projects/:id', async (c) => {
  const { id: tenantId } = c.get('tenant');
  const [row] = await db.select().from(projects)
    .where(and(eq(projects.id, c.req.param('id')), eq(projects.tenantId, tenantId)));
  return row ? c.json(row) : c.notFound();
});
```

With RLS in force, run the query inside the tenant transaction instead (`secaudit:postgres-security`
§3). The membership check stays either way, because RLS scopes rows to a tenant and does not decide
whether this user belongs to that tenant.

```bash
# tenant chosen by a request header
grep -rniE --include='*.ts' --include='*.tsx' --exclude-dir=node_modules \
  "x-(tenant|org|organization|workspace|team|community)(-id)?['\"]" .
# tenant id read from client input: confirm a membership lookup sits between each hit and its first query
grep -rnE --include='*.ts' --include='*.tsx' --exclude-dir=node_modules \
  '(tenantId|organizationId|orgId|workspaceId|communityId)' . \
  | grep -E 'body|params|searchParams|query\(|req\.json|formData|header\('
```

## 2. Host → Tenant Routing, Reserved Names, and Hostnames That Outlive Their Tenant

**Why it matters:** on a multi-host platform the `Host` header selects the tenant for every request,
including anonymous ones (public pages, sign-in, password reset). Any client can send any `Host` to
your IP. A resolver that falls back to a default tenant, or that takes the first DNS label without
checking the rest of the hostname, serves tenant content on hostnames you never issued. A hostname
or slug that survives its tenant goes to whoever claims it next.

**What to look for:**

- **Fallback tenants:** `?? defaultTenant`, `|| 'main'`, or `catch { return DEFAULT_ORG }` in host
  resolution. An unknown host must get a 404 (or 421) with `Cache-Control: no-store`, not the main
  tenant's site.
- **Loose parsing:** `host.split('.')[0]` returns `acme` for `acme.attacker.example` too. Match
  your own suffix exactly, with one label in front of it, or exact-match a verified custom-domain
  row. Which `Host` / `X-Forwarded-Host` to believe behind a proxy is `secaudit:proxy-trust` §3.
- **Reserved labels:** slug creation that lets a tenant claim `www`, `app`, `api`, `admin`, `auth`,
  `login`, `mail`, `status`, or `static`. That tenant then owns a platform-looking host for
  phishing. Any CORS, CSP, cookie, or OAuth redirect allowlist written as `*.app.example.com` also
  trusts it.
- **Slug and subdomain reuse:** a deleted tenant's slug freed for immediate re-registration. The new
  owner of `acme.app.example.com` inherits the old tenant's inbound links, emailed invite and reset
  links, OAuth redirect URIs registered with third parties, and any cache or search entry keyed by
  host. Tombstone deleted slugs (never reuse them, or hold them for a long cool-down) and purge the
  host's caches.
- **Stale host caches:** an in-process or Redis host→tenant cache that domain removal, verification
  lapse, and tenant deletion don't clear. A removed domain keeps routing until the TTL runs out.
  Clear the cache on every domain or tenant mutation, keep the TTL short, and never cache a failed
  lookup as a hit.
- **Custom domains:** DNS TXT ownership verification before activation, re-verification, unique
  verified hostnames, on-demand TLS restrictions, and teardown when a tenant is deleted are covered
  in `secaudit:auth`, "5. Custom-Domain Verification and the Dangling-Domain Lifecycle". Don't
  re-implement them here. On your own DNS zone, a record that points at a deprovisioned resource
  (an old load balancer, a deleted Pages or bucket site) is classic subdomain takeover (OWASP
  WSTG-CONF-10). Enumerate the zone and remove dangling records as part of tenant and
  infrastructure teardown.

```ts
// BAD (proxy.ts) — any Host resolves to *some* tenant
export async function proxy(req: NextRequest) {
  const slug = (req.headers.get('host') ?? '').split('.')[0];            // 'acme' from acme.attacker.example
  const tenant = (await tenantBySlug(slug)) ?? (await defaultTenant());   // unknown host -> main tenant
  return NextResponse.rewrite(new URL(`/t/${tenant.slug}${req.nextUrl.pathname}`, req.url));
}
```

```ts
// GOOD (proxy.ts) — exact matches only; everything else is a 404 no cache keeps.
// Routing only: handlers still run §1's membership check.
const APP_HOST = new URL(process.env.APP_URL!).hostname;                  // config, never a header
const RESERVED = new Set(['www', 'app', 'api', 'admin', 'auth', 'login', 'mail', 'status', 'static']);

export async function proxy(req: NextRequest) {
  const host = (req.headers.get('host') ?? '').toLowerCase().replace(/:\d+$/, '');
  if (host === APP_HOST) return NextResponse.next();                      // the platform's own host
  let tenant: Tenant | null = null;
  if (host.endsWith(`.${APP_HOST}`)) {
    const label = host.slice(0, -(APP_HOST.length + 1));
    if (/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label) && !RESERVED.has(label)) {
      tenant = await liveTenantBySlug(label);                             // deleted or suspended -> null
    }
  } else {
    tenant = await tenantByVerifiedDomain(host);                          // status = 'verified' rows only
  }
  if (!tenant) return new NextResponse('Not Found', { status: 404, headers: { 'cache-control': 'no-store' } });
  const url = req.nextUrl.clone();
  url.pathname = `/t/${tenant.slug}${req.nextUrl.pathname}`;
  return NextResponse.rewrite(url);
}
```

Enforce the same `RESERVED` set and the same label pattern when a slug is created. Without that,
the check above is only half of the rule. The rewrite target is an ordinary route: anyone can
request `/t/<slug>/...` directly on the platform host (or on another tenant's host, where it is
rewritten to `/t/<own>/t/<slug>/...`). So every handler under `/t/` runs §1's membership check
itself, or the proxy refuses direct `/t/` paths before rewriting.

```bash
# first-label parsing and default-tenant fallbacks in host resolution
grep -rnE --include='*.ts' --exclude-dir=node_modules \
  "split\(['\"]\.['\"]\)\[0\]|defaultTenant|DEFAULT_(TENANT|ORG|WORKSPACE|COMMUNITY)" .
# every place the Host header picks a tenant: check suffix matching, 404 on miss, cache clearing
grep -rnE --include='*.ts' --exclude-dir=node_modules "headers\.get\(['\"](host|x-forwarded-host)['\"]\)|req\.hostname" .
# slug creation: is there a reserved list, and are deleted slugs tombstoned?
grep -rniE --include='*.ts' --exclude-dir=node_modules 'reserved(Slugs|Names|Subdomains)?|tombstone' .
```

## 3. Cache Keys: The Cache Has No WHERE Clause

**Why it matters:** a cache is a second database without row-level security. The key you compute is
its only isolation. A key built from an id that is unique only *within* a tenant (a slug, an
invoice number, the literal `'settings'`), or from nothing that names the tenant, serves tenant A's
value to tenant B on the next hit. The OWASP cheat sheet puts the rule plainly: "Include the tenant
identifier in every cache key whose value or authorization varies by tenant."

**What to look for:**

- **Redis / KV:** ``redis.get(`stats:${slug}`)``, `kv.get('plan-limits')`, keys built from
  per-tenant ids. Prefix every tenant-scoped key with the tenant id resolved in §1, and add the user
  id when the value depends on the viewer's role. Put intentionally shared values in an explicit
  global namespace.
- **Next.js `unstable_cache`:** the key is the function's arguments, its stringified source, and
  `keyParts`. A tenant id captured by closure is **not** part of the key. `unstable_cache(async () =>
  getProjects(orgId), ['projects'])()` has one entry for every tenant. `'use cache'` is different:
  per the Next.js docs, closed-over variables "are automatically captured and bound as arguments,
  making them part of the cache key". Both miss a tenant read *inside* the function from a
  module-level store or an AsyncLocalStorage helper. Pass the tenant id as an argument. The
  per-user variant (a session read hoisted out of the cached function) is in
  `secaudit:better-auth-security`, "12. Per-User Data Pulled Into a Shared Next.js Cache".
- **Tags:** `cacheTag('projects')` / `revalidateTag('projects', 'max')` with no tenant in the tag.
  That is not a leak, but one tenant's writes invalidate every tenant's cache. Use
  `projects:${tenantId}`, and in a Server Action that must show the writer their own change, use
  ``updateTag(`projects:${tenantId}`)`` (Next.js 16; the one-argument `revalidateTag` is deprecated).
- **fetch cache:** caching is opt-in (`cache: 'force-cache'` or `next: { revalidate }`), and a
  cached request "matches on its URL, method, headers, and body", so a differing `Authorization`
  header does get its own entry. The risk is opting a tenant-credentialed request into the cache
  when the tenant is visible in neither its URL nor the arguments of the cached function that wraps
  it: the wrapper's entry is then shared by every tenant. Keep the tenant in the URL or in those
  arguments, or use `cache: 'no-store'`.
- **CDN and shared proxies:** a tenant-authenticated response sent with `public`, `s-maxage`, or no
  `Cache-Control`. A CDN keys on host and path, not on your session cookie. If the tenant comes from
  a cookie or header instead of the host, that response is served to other tenants. Send
  `Cache-Control: private` (or `no-store`) on anything session- or tenant-dependent. `Vary: Cookie`
  is a weak substitute: it fragments the cache, and not every cache honours it
  (`secaudit:cloudflare-workers-security` §8 lists a cache middleware that ignored `Vary`).

```ts
// BAD — slug is unique per tenant, not globally; the closure's orgId is not in unstable_cache's key
const stats = await redis.get(`stats:${slug}`);
const projectsFor = unstable_cache(
  async () => db.select().from(projects).where(eq(projects.orgId, orgId)),
  ['projects'],
);
await projectsFor();                                          // first tenant's list, served to all
```

```ts
// GOOD — the tenant id from §1 is a key component wherever a value differs by tenant
const tkey = (tenantId: string, ...parts: string[]) => ['t', tenantId, ...parts].join(':');
const stats = await redis.get(tkey(tenantId, 'stats', slug));

const projectsFor = (orgId: string) =>
  unstable_cache(
    async (id: string) => db.select().from(projects).where(eq(projects.orgId, id)),
    ['projects', orgId],
    { tags: [`projects:${orgId}`] },
  )(orgId);                                                    // argument + keyPart + per-tenant tag

async function projectsCached(orgId: string) {                 // Next 16: 'use cache' with an explicit argument
  'use cache';
  cacheTag(`projects:${orgId}`);
  return db.select().from(projects).where(eq(projects.orgId, orgId));
}

return Response.json(data, { headers: { 'cache-control': 'private, no-store' } });   // no shared cache
```

```bash
# Redis/KV calls with a literal key: list those whose key never names a tenant (heuristic; read each hit)
grep -rnE --include='*.ts' --exclude-dir=node_modules \
  "\.(get|set|setex|del|hget|hset|incr|expire|mget)\(\s*[\`'\"]" . | grep -viE 'tenant|org|workspace|community|tkey\(|headers?\.get|searchParams\.get'
# Next.js data cache: check each for the tenant in arguments/keyParts and in tags
grep -rnE --include='*.ts' --include='*.tsx' --exclude-dir=node_modules \
  "unstable_cache\(|['\"]use cache|cacheTag\(|revalidateTag\(" .
# responses that ask shared caches to keep them
grep -rniE --include='*.ts' --include='*.js' --include='*.json' --exclude-dir=node_modules 's-maxage|public, *max-age' .
# cached functions that also touch a session or request API (hoisted-session variant: read each hit)
grep -rl --null -E "['\"]use cache|unstable_cache\(" --include='*.ts' --include='*.tsx' --exclude-dir=node_modules --exclude-dir=.next . | xargs -0 -r grep -nE "getServerSession|getSession|getToken|(^|[^a-zA-Z.])auth\(\)|currentUser\(|cookies\(|headers\("
```

## 4. Jobs, Queues, and Cron: The Worker Has No Session

**Why it matters:** a job runs after the request that queued it, without that request's session,
and often on a privileged connection with no RLS "because workers are trusted". The job's tenant is
whatever the payload says. If the payload came from the client, or the worker reuses one connection
or one transaction across tenants, the job reads, writes, or emails data across tenants with no one
having authorized it. The OWASP cheat sheet says a privileged job "must explicitly authorize and
constrain its tenant set or cross-tenant operation because RLS will not do so."

**What to look for:**

- `queue.add('export', await req.json())`, `{ ...body }`, or `inngest.send({ data: body })`: the
  payload's `tenantId`, `userId`, or recipient email chosen by the client.
- A worker on a service-role / BYPASSRLS pool whose queries lack a tenant predicate.
- No re-authorization at run time. The admin who queued an export was removed an hour ago, and the
  export still runs and emails the CSV to them. A scheduled job keeps running for a user who has
  since left.
- Tenant context set once per worker connection, or once per cron run before looping over tenants,
  or set with session scope (`set_config(..., false)`). Use one transaction per tenant per unit of
  work (`secaudit:postgres-security` §3, `secaudit:prisma-security` §3).
- A cron loop over all tenants whose accumulator (a recipient list, a batch array, a digest)
  outlives one iteration.
- **Dedupe ids that collide across tenants:** BullMQ ignores a job whose `jobId` already exists ("if
  you add a job with an existing id then that job will just be ignored"). A `jobId` built from a
  per-tenant number lets tenant A's job swallow tenant B's. Include the tenant id, and use `-` as
  the separator, because BullMQ custom ids "must not contain the `:` separator".
- Fairness: one tenant's backlog starving everyone else. That is availability, not confidentiality.
  Inngest has per-tenant flow-control keys for it. Separate the queues or concurrency keys by
  tenant where it matters.

```ts
// BAD — tenant, actor and recipient come from the body; the worker believes them on a BYPASSRLS pool
app.post('/api/exports', async (c) => {
  await exportsQueue.add('export', await c.req.json());          // { tenantId, userId, email } — client-chosen
  return c.json({ ok: true });
});
new Worker('exports', async (job) => {
  const rows = await systemDb.select().from(invoices).where(eq(invoices.tenantId, job.data.tenantId));
  await emailCsv(job.data.email, rows);
});
```

```ts
// GOOD — the route stamps ids from §1; the worker re-loads, re-authorizes, and runs inside the tenant's transaction
app.post('/api/t/:slug/exports', async (c) => {
  const { id: tenantId } = c.get('tenant');
  const { format } = ExportReq.parse(await c.req.json());        // only what the client may choose
  const exp = await createExport({ tenantId, userId: c.get('session').userId, format });
  await exportsQueue.add('export', { exportId: exp.id }, { jobId: `export-${tenantId}-${exp.id}` });
  return c.json({ id: exp.id }, 202);
});

new Worker('exports', async (job) => {
  // claimExport: UPDATE exports SET status = 'running', claimed_at = now() WHERE id = $1
  //   AND (status = 'pending' OR (status = 'running' AND claimed_at < now() - interval '15 minutes')) RETURNING *
  const exp = await claimExport(job.data.exportId);                      // the server row: tenant and actor come from it
  if (!exp) {
    if ((await exportStatus(job.data.exportId)) === 'running') throw new Error('leased');   // retry after backoff
    return;                                                              // done, denied, failed, or missing
  }
  try {
    const member = await membership(exp.userId, exp.tenantId);           // still a member, still allowed?
    if (!member || member.status !== 'active' || !can(member.role, 'invoice:export')) {
      return await markExport(exp.id, 'denied');                         // terminal; log it
    }
    const rows = await withTenantTx(exp.tenantId, (tx) =>                // non-owner role + set_config(..., true)
      tx.select().from(invoices).where(eq(invoices.tenantId, exp.tenantId)));   // and the predicate: not RLS alone
    await emailCsv(member.email, rows);                                  // recipient from the membership row
    await markExport(exp.id, 'done');
  } catch (err) {
    const last = job.attemptsMade + 1 >= (job.opts.attempts ?? 1);
    await markExport(exp.id, last ? 'failed' : 'pending');               // release the lease for BullMQ's retry
    throw err;
  }
});
```

The claim is a lease, not a one-way flag. Two runs never hold it at once as long as a run finishes
within the lease (size it above your slowest export), a thrown run releases it,
and a crashed run's lease expires so a later retry can take over. The cost: a crash between
`emailCsv` and `markExport` sends the CSV twice. If that matters, make the send itself idempotent.

The same shape applies to pg-boss (`boss.send` / `boss.work`), Inngest functions (`event.data`), and
plain cron. The payload carries a reference to a server-created row, and the worker re-derives the
tenant and the actor from that row.

```bash
# enqueue calls fed from request input
grep -rnE --include='*.ts' --exclude-dir=node_modules \
  "\.add\(|boss\.(send|publish)\(|inngest\.send\(|enqueue\(" . | grep -E 'req\.json|c\.req\.json|body|\.\.\.'
# workers and schedules: for each, check which DB pool, the tenant predicate, and a run-time membership re-check
grep -rnE --include='*.ts' --exclude-dir=node_modules \
  "new Worker\(|boss\.work\(|createFunction\(|cron\.schedule\(|schedule\(['\"]" .
# BullMQ jobIds without a tenant component
grep -rnE --include='*.ts' --exclude-dir=node_modules 'jobId:' . | grep -viE 'tenant|org|workspace|community'
```

## 5. Inbound Webhooks: The Signature Names the Sender, Not the Tenant

**Why it matters:** a webhook arrives with no session. Its only identity is the signature, and that
proves who *sent* it, not which of your tenants it belongs to. When every tenant shares one
endpoint and one secret, a tenant id in the body is just data. If any part of the payload is
customer-authored (form-builder submissions, CRM custom fields, checkout `metadata` copied from the
client), one tenant can file events into another tenant.

**What to look for:**

- One `/api/webhooks/<sender>` route verifying with a single env secret, then picking the tenant
  from `payload.metadata.tenantId`, a custom field, or a `?tenant=` query parameter.
- Per-tenant integrations (each tenant connects its own form tool, Shopify store, or Twilio
  account) all verified against one global secret.
- Objects the event references (a customer, an order, a member) loaded by id alone instead of with
  the mapped tenant's predicate.

**The two correct shapes:**

1. **Per-tenant endpoint and secret.** Issue each connection a random endpoint id
   (`/api/webhooks/forms/:endpointId`) and its own signing secret. Look up the endpoint row, verify
   with *that row's* secret, and take the tenant from the row.
2. **Platform-signed senders** (Stripe Connect, a GitHub App) sign with one platform secret, but the
   sender itself sets the account identifier. Stripe: "Each event for a connected account contains
   a top-level `account` property that identifies the connected account". GitHub App payloads
   "contain the `installation` property when the event is configured for and sent to a GitHub App";
   key on its `installation.id`. Map that identifier to a tenant through a table you wrote at
   onboarding. Never use a tenant id from `metadata`. For Stripe, this only holds on a Connect
   endpoint (created with `connect=true`); platform-scope events carry no `account` at all.

```ts
// BAD — one secret for every tenant; the body names the tenant
app.post('/api/webhooks/forms', async (c) => {
  const raw = await c.req.text();
  if (!verify(raw, c.req.header('x-signature'), process.env.FORMS_SECRET!)) return c.body(null, 401);
  const evt = JSON.parse(raw);
  await db.insert(leads).values({ tenantId: evt.metadata.tenantId, ...evt.fields });   // tenant from payload, spread
  return c.body(null, 204);
});
```

```ts
// GOOD — the URL names an endpoint row; the row names the tenant and holds that tenant's secret
app.post('/api/webhooks/forms/:endpointId', async (c) => {
  const ep = await webhookEndpointById(c.req.param('endpointId'));        // random id issued at connect time
  if (!ep || ep.disabledAt) return c.body(null, 404);
  const raw = await c.req.text();
  if (!verify(raw, c.req.header('x-signature'), await openSecret(ep))) return c.body(null, 401);
  const evt = FormEvent.parse(JSON.parse(raw));                             // schema, no spread
  await withTenantTx(ep.tenantId, (tx) => tx.insert(leads).values({ tenantId: ep.tenantId, email: evt.email }));
  return c.body(null, 204);
});

// Platform-signed sender (Stripe Connect endpoint, connect=true): the sender sets the account field
if (!event.account) return handlePlatformEvent(event);                     // platform-scope: no account, never a null lookup
const tenantId = await tenantForStripeAccount(event.account);              // onboarding mapping, not metadata
if (!tenantId) return new Response(null, { status: 200 });                 // unknown account: acknowledge, ignore
```

Signature verification itself (raw body, constant-time compare, timestamp tolerance, dedupe) is
`secaudit:webhook-security` §1 and, for Stripe, `secaudit:payments`. Storing each tenant's secret
encrypted and bound to its row is `secaudit:cryptography` §9.

```bash
# tenant taken from a webhook payload
grep -rnE --include='*.ts' --exclude-dir=node_modules \
  "metadata\??\.(tenant|org|organization|workspace|community)|custom_?[fF]ields?\??\.(tenant|org)" .
# webhook handlers verifying with one global env secret: fine for a single-account sender,
# a finding when each tenant connects its own account
grep -rlE --include='*.ts' --exclude-dir=node_modules 'webhook' . | xargs -r grep -nE 'process\.env\.[A-Z_]*SECRET' 2>/dev/null
```

## 6. Search and Vector Indexes: The Server Writes the Tenant Filter

**Why it matters:** a shared search index is a shared table with its own query language and its own
credentials, and your RLS doesn't reach it. Teams index every tenant into one index and filter by
tenant, so what matters is who writes the filter. If the browser holds a key that can search the
whole index, or the server appends a filter the client sent, any user can drop the tenant clause.

**What to look for, per engine:**

- **Meilisearch:** a master, admin, or plain search key shipped to the browser for a multi-tenant
  index. The docs describe the search key as "Safe to use in frontend applications when data is not
  multi-tenant." For multi-tenant data, mint a **tenant token** on the server with
  `generateTenantToken` (from `meilisearch/token`), using the default search key's value and
  `apiKeyUid`. Tokens "embed search rules (filters) that automatically apply to every search
  request", and a token "has access to the same indexes and routes as the API key used to generate
  it". So declare the tenant attribute in `filterableAttributes`, scope the parent key to the right
  indexes, avoid `'*'` rules with no filter, and set a short `expiresAt`. Tenant tokens restrict the
  search endpoint only, not indexing or settings. Quote the tenant value in the filter, and never
  splice client text into a rule.
- **Algolia:** an admin or unrestricted search key in client code, or filters built in the browser.
  Use `generateSecuredApiKey` on the server with a search-only `parentApiKey` and `restrictions: {
  filters, validUntil, restrictIndices }`. Algolia's guide says users "can't alter these filters".
  Declare the attribute `filterOnly(...)`, add it to `unretrievableAttributes`, and rotate the
  parent search key if a secured key leaks.
- **Elasticsearch / OpenSearch:** a filtered alias treated as the boundary. Elastic says "Don't use
  filtered aliases in place of document level security. Elasticsearch doesn't always apply alias
  filters": they "are not applied when retrieving a document by ID", and read on a data stream also
  grants read on its backing indices. If clients query the cluster directly, use document-level
  security (a role query that can be templated on the authenticated user). More often the cluster should not be client-reachable at all. The server
  builds the query with a `bool.filter` tenant term and never accepts raw Query DSL from the client.
  Document-level security "doesn't apply to write APIs", so check indexing paths separately.
- **pgvector / RAG:** the tenant predicate belongs in the same SQL as the distance `ORDER BY`, not
  in a filter applied after `LIMIT`. See `secaudit:prisma-security` §8–9 and `secaudit:ai-integration`,
  "RAG Retrieval Access Control".
- **Indexing and offboarding:** documents indexed without the tenant attribute (they match no
  filter, and someone "fixes" that by removing the filter), and a deleted tenant's documents left in
  the index. Delete them by tenant filter when the tenant is offboarded.

```ts
// BAD — the browser holds a key that searches every tenant and writes its own filter
//   NEXT_PUBLIC_MEILI_KEY=<search key>   ->   index.search(q, { filter: `org_id = ${orgId}` })
// BAD — the server forwards whatever filter the client sent
app.get('/api/search', async (c) =>
  c.json(await index.search(c.req.query('q') ?? '', { filter: c.req.query('filter') })));
```

```ts
// GOOD (Meilisearch) — the server mints a short-lived token whose rule the client cannot change
import { generateTenantToken } from 'meilisearch/token';

app.get('/api/t/:slug/search-token', async (c) => {
  const { id: tenantId } = c.get('tenant');                                 // §1; a server uuid
  const token = await generateTenantToken({
    apiKey: process.env.MEILI_SEARCH_KEY!,                                   // search-only parent, never the master key
    apiKeyUid: process.env.MEILI_SEARCH_KEY_UID!,
    searchRules: { docs: { filter: `tenant_id = "${tenantId}"` } },
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  return c.json({ token }, 200, { 'cache-control': 'private, no-store' });
});
// A token stays valid until expiresAt, even after the member is removed: keep the TTL short, and for
// high-risk tenants rotate or delete the parent key on removal (that invalidates every token minted from it).

// GOOD (Algolia) — same shape: HMAC-signed restrictions on a search-only parent key
const securedKey = await client.generateSecuredApiKey({
  parentApiKey: process.env.ALGOLIA_SEARCH_KEY!,
  restrictions: {
    filters: `tenant_id:"${tenantId}"`,
    validUntil: Math.floor(Date.now() / 1000) + 15 * 60,
    restrictIndices: ['docs'],
  },
});
```

```bash
# search credentials exposed to the client bundle
grep -rnE --include='*.ts' --include='*.tsx' --include='.env*' --exclude-dir=node_modules \
  '(NEXT_PUBLIC|VITE|EXPO_PUBLIC|PUBLIC)_[A-Z_]*(MEILI|ALGOLIA|ELASTIC|OPENSEARCH|TYPESENSE|SEARCH)[A-Z_]*KEY' .
# server-side search calls: check that the tenant filter comes from §1 and nothing client-supplied is appended
grep -rnE --include='*.ts' --exclude-dir=node_modules \
  "generateTenantToken|generateSecuredApiKey|searchRules|\.search\(|_search|filter: *(c\.req|req\.|searchParams|body)" .
```

## 7. Impersonation and Support Access

**Why it matters:** support impersonation is a deliberate bypass of tenant isolation, so its limits
*are* the isolation. Consider an impersonation session the app can't tell apart from a real one,
that doesn't expire, that can target other staff, or that can change a tenant's billing, SSO, or MFA
settings. With that, one phished support account becomes an admin of every tenant.

**What to look for:**

- **Who can start it:** impersonation gated on any `role === 'admin'`, so a *tenant* admin can
  impersonate users outside their tenant, or platform staff. Nobody should be able to impersonate a
  user with equal or higher privilege. In Better Auth's admin plugin, roles are platform-wide, not
  per-organization. Don't map organization owners onto the plugin's `admin` role. By default the
  plugin's "admins cannot impersonate other admin users". Granting `user: ['impersonate-admins']`
  (the legacy `allowImpersonatingAdmins` option is deprecated) removes that protection, so keep it
  off every role.
- **Standing access instead of a grant:** staff aren't members, so §1's resolver gets a staff
  bypass. Make the bypass a support grant instead: tenant-approved, time-boxed, read-only by
  default, and recorded in the *tenant's* audit log, where the tenant owner can see it.
- **No time box:** Better Auth's `impersonationSessionDuration` defaults to one hour. The docs show
  a one-day value as an example. Don't copy it.
- **Not marked or not enforced:** the admin plugin stamps `session.impersonatedBy`. Every sensitive
  handler must check it and refuse: billing and plan changes, payment methods, password, email,
  MFA and passkey changes, SSO/SCIM settings, API-key creation, member role changes, bulk export,
  and tenant deletion. The UI shows a persistent banner from the same flag.
- **Not audited:** start and stop of impersonation and every write made during it go to the audit
  log with both the actor (staff) and the subject (the impersonated user)
  (`secaudit:logging-monitoring` §3).

```ts
// BAD — a long session, and nothing downstream can tell it is not the user
admin({ impersonationSessionDuration: 60 * 60 * 24 });           // a day, copied from the docs example
// ...and the billing route only checks that a session exists
```

```ts
// GOOD — short, audited at the source, and refused by every sensitive handler
export const auth = betterAuth({
  plugins: [admin({ impersonationSessionDuration: 30 * 60 })],  // 30 min; the plugin default is 1 h
  hooks: {
    after: createAuthMiddleware(async (ctx) => {
      const s = ctx.context.newSession;
      if (ctx.path === '/admin/impersonate-user' && s) {
        await audit({ action: 'impersonate.start', actorId: s.session.impersonatedBy, subjectId: s.user.id });
      }
    }),
  },
});

export function denyDuringImpersonation(session: { session: { impersonatedBy?: string | null } }) {
  if (session.session.impersonatedBy) throw new HTTPException(403, { message: 'Not available during support access' });
}
// billing, security settings, member roles, API keys, export, deletion: call denyDuringImpersonation first
```

```ts
// GOOD — in §1's resolver: staff are not members; an active support grant is the only door, and it is logged
if (!member && isPlatformStaff(session)) {
  const grant = await activeSupportGrant(tenant.id, session.userId);        // tenant-approved, expiresAt > now()
  if (!grant) return c.notFound();
  await auditTenant(tenant.id, { actorId: session.userId, action: 'support.access', path: c.req.path, grantId: grant.id });
  c.set('tenant', { id: tenant.id, role: 'support-readonly' });
}
```

```bash
# impersonation and support-access surfaces
grep -rniE --include='*.ts' --include='*.tsx' --exclude-dir=node_modules \
  'impersonat|impersonatedBy|actAs|act_as|loginAs|login_as|supportMode|support_grant|isStaff' .
# sensitive handlers that never consult the impersonation flag (heuristic; read each file listed)
grep -rlE --include='*.ts' --exclude-dir=node_modules \
  'billing|checkout|subscription|paymentMethod|twoFactor|passkey|changePassword|changeEmail|createApiKey|scim|sso' . \
  | xargs -r grep -L 'impersonatedBy' 2>/dev/null
```

## 8. Where the Rest Lives

These controls are part of tenant isolation, but other skills own them. Audit them there. Headings
are quoted exactly.

| Concern | Skill | Section |
|---|---|---|
| RLS declared but not in force (`ENABLE` / `FORCE`) | `secaudit:postgres-security` | 1. Drizzle RLS Declared in the Schema, Not in Force in the Database |
| Runtime role is the table owner or `BYPASSRLS` | `secaudit:postgres-security` | 2. The Runtime Role: Not the Owner, Not BYPASSRLS — Summary and the Drizzle Shape |
| Same, with Prisma | `secaudit:prisma-security` | 2. Postgres RLS Is Silently Inert When the App Connects as the Table Owner |
| Per-transaction tenant GUC (`set_config(..., true)`), `tx` vs `db`, NULL vs `''` | `secaudit:postgres-security` | 3. Tenant Context in Drizzle Transactions — and the NULL vs Empty-String Trap |
| Same, with Prisma and pooled connections | `secaudit:prisma-security` | 3. `set_config` Outside a Transaction Leaks Tenant Context Across Pooled Connections |
| Transaction pooling and session state | `secaudit:postgres-security` | 4. PgBouncer Transaction Pooling Breaks Session State, LISTEN, and Session Locks |
| Tenant predicate on every ORM query, without RLS | `secaudit:prisma-security` | 1. No Row-Level Security — Every Query Carries the Tenant Predicate |
| Scoping extensions that miss `include` / raw SQL | `secaudit:prisma-security` | 4. A Tenant-Scoping Extension Never Reaches `include` or Raw Queries |
| SQLite / Turso / D1 tenant predicates | `secaudit:data-access` | Tenant isolation is application code |
| Supabase RLS policies | `secaudit:database` | Supabase Row-Level Security (RLS) |
| `LISTEN`/`NOTIFY` payloads bypass RLS | `secaudit:postgres-security` | 5. LISTEN/NOTIFY: Payloads Bypass RLS and Any Connected Role Can Listen |
| Realtime rooms and channels joined from client input | `secaudit:realtime-security` | 5. Channel, Room, and Subscription Authorization |
| Cross-tenant fan-out from a shared bus | `secaudit:realtime-security` | 8. Fan-Out From a Shared Pub/Sub |
| Storage object keys and tenant prefixes | `secaudit:object-storage-security` | 2. The Server Must Mint the Object Key, Never the Client |
| Object reads authorized per tenant | `secaudit:object-storage-security` | 7. Object-Level Authorization on Read — Unguessable Is Not a Control |
| Better Auth organization tenant id from the request | `secaudit:better-auth-security` | 6. Organization Plugin: Tenant ID From the Request |
| Per-user data in a shared Next.js cache | `secaudit:better-auth-security` | 12. Per-User Data Pulled Into a Shared Next.js Cache |
| Clerk Organizations membership checks | `secaudit:auth` | 9. Organizations: Membership and Role Checked Server-Side, Per Operation |
| Sessions across tenant hosts | `secaudit:auth` | 1. One Host-Only `__Host-` Cookie per Host, and Session Rows Bound to Their Host |
| Custom-domain verification and dangling domains | `secaudit:auth` | 5. Custom-Domain Verification and the Dangling-Domain Lifecycle |
| Which `Host` to believe; failing closed | `secaudit:proxy-trust` | 3. Host-Header Trust: Absolute URLs, Password-Reset Poisoning, and Failing Closed |
| Object IDOR inside a tenant | `secaudit:web-vulns` | 4. IDOR / Broken Object-Level Authorization |
| Tenant admin reaching platform-admin functions | `secaudit:privilege-escalation` | 1. Vertical escalation — unprotected admin endpoints |
| Role field mass-assigned (tenant role or platform role) | `secaudit:privilege-escalation` | 4. Mass-assignment of the role field |
| Webhook signature verification | `secaudit:webhook-security` | 1. Cross-Cutting Rules — Apply to Every Sender Below |
| Stripe checkout metadata set client-side | `secaudit:payments` | Checkout Session Metadata |
| Per-tenant secrets encrypted and bound to their row | `secaudit:cryptography` | 9. Encrypting Stored Secrets You Must Use Later (Webhook URLs, Third-Party Keys) |
| API keys that carry a tenant and scopes | `secaudit:cryptography` | 7. API Keys: Public Prefix, Lookup Id, Hashed Secret |
| Vector retrieval without a tenant predicate | `secaudit:prisma-security` | 8. pgvector — Retrieval Without an Access-Control Predicate |
| RAG access control | `secaudit:ai-integration` | RAG Retrieval Access Control |
| Tenant-authored content on a shared origin | `secaudit:rich-text-security` | 10. Blast Radius: Where Stored Rich Content Runs |
| Audit trail for cross-tenant and support actions | `secaudit:logging-monitoring` | 3. Missing Audit Logging + Alerting |

## Multi-Tenant Isolation Checklist

- §1 The tenant id is resolved from the server-verified session plus a *current* membership row.
  A header, body, query, subdomain, or path value is only a hint that is checked against
  membership. Every query by object id also carries the resolved tenant predicate.
- §1 No `x-tenant-id` / `x-org-id` header is honoured. No JWT or session claim stands in for a
  membership lookup when access is granted.
- §2 An unknown host returns a 404/421 with `no-store`. It never falls back to a default tenant.
  Subdomains match the platform suffix exactly. Custom domains are routed only from verified rows
  (`secaudit:auth`, "5. Custom-Domain Verification and the Dangling-Domain Lifecycle").
- §2 Platform labels (`www`, `api`, `admin`, `auth`, ...) are reserved when a slug is created.
  Deleted tenants' slugs and hostnames are tombstoned, not reissued. Host→tenant caches are cleared
  on every domain or tenant change. Dangling DNS records on your own zone are removed (WSTG-CONF-10).
- §3 Every tenant-scoped Redis/KV key, `unstable_cache` key, `'use cache'` argument list, and
  cache tag contains the tenant id, plus the user id when the value is per-viewer. No tenant id is
  captured only by closure in `unstable_cache`.
- §3 Tenant- or session-dependent responses send `Cache-Control: private` / `no-store`. Nothing
  tenant-specific is marked `public` or `s-maxage`.
- §4 Job payloads carry references to server-created rows, never client-chosen tenant, user, or
  recipient fields. Workers re-load the row, re-check membership and permission at run time, and
  run each tenant's work in its own transaction with transaction-local `set_config`.
- §4 BullMQ `jobId`s (and any dedupe keys) include the tenant id and contain no `:`.
- §5 Webhooks map to a tenant through a per-tenant endpoint id and secret, or through a
  sender-set account id (`event.account`, `installation.id`) and an onboarding mapping. They never
  map through payload metadata or a query parameter.
- §6 No search key that can read the whole index reaches the client. Meilisearch tenant tokens or
  Algolia secured API keys are minted server-side from a search-only parent key, with a short
  expiry and a filter built from the §1 tenant id. Elasticsearch filtered aliases are not treated
  as a boundary. Client-supplied filters or Query DSL are never forwarded.
- §6 Vector and RAG queries carry the tenant predicate in the same SQL as the similarity ordering.
  Offboarding deletes the tenant's documents from every index.
- §7 Impersonation is limited to platform staff, can't target equal- or higher-privileged users,
  runs for 30–60 minutes at most, is audited with actor and subject, shows a banner, and is refused
  by billing, security, membership, API-key, export, and deletion handlers via `impersonatedBy`.
- §7 Staff access to a tenant goes through a tenant-approved, expiring support grant that is
  recorded in the tenant's own audit log, not through a standing `isStaff` bypass.
- §8 The database, realtime, storage, custom-domain, and IDOR controls in the pointer table have
  been audited in their own skills.

## Sources

- https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html -- threat classes; tenant context from the authenticated principal; "Include the tenant identifier in every cache key"; privileged jobs must constrain their tenant set
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html -- deny by default; authorization checked on every request
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where cross-tenant findings land
- https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/10-Subdomain_Takeover/ -- WSTG-CONF-10 subdomain takeover: dangling CNAME/NS records, expired domains
- https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Subdomain_takeover -- subdomain takeover and the hosting vendor's duty to verify claims
- https://nextjs.org/docs/app/api-reference/functions/unstable_cache -- key = arguments + stringified function + `keyParts`; replaced by `use cache` in Next.js 16
- https://nextjs.org/docs/app/api-reference/directives/use-cache -- cache key composition; closed-over variables become part of the key
- https://nextjs.org/docs/app/api-reference/functions/cacheTag -- tag-based invalidation
- https://nextjs.org/docs/app/api-reference/functions/revalidateTag -- `revalidateTag(tag, profile)`; the one-argument form is deprecated
- https://nextjs.org/docs/app/api-reference/functions/updateTag -- read-your-own-writes invalidation from Server Actions
- https://nextjs.org/docs/app/api-reference/functions/fetch -- caching is opt-in; a cached request matches on URL, method, headers, and body
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control -- `private`, `no-store`, `s-maxage`
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Vary -- `Vary` and shared-cache keying
- https://docs.bullmq.io/guide/jobs/job-ids -- duplicate `jobId` is ignored; custom ids must not contain `:`
- https://docs.bullmq.io/guide/jobs/ -- BullMQ job model
- https://pgboss.io/ -- pg-boss `send` / `work`
- https://www.inngest.com/docs/durable-execution/flow-control -- per-tenant flow-control keys
- https://docs.stripe.com/connect/webhooks -- the top-level `account` property on connected-account events
- https://docs.stripe.com/api/webhook_endpoints/create -- the `connect` parameter: a Connect endpoint receives events from connected accounts
- https://docs.github.com/en/webhooks/webhook-events-and-payloads -- the `installation` property on GitHub App webhook payloads
- https://www.meilisearch.com/docs/capabilities/security/overview -- tenant tokens; search key "safe ... when data is not multi-tenant"; search-endpoint only
- https://www.meilisearch.com/docs/capabilities/security/getting_started -- `generateTenantToken({ apiKey, apiKeyUid, searchRules, expiresAt })` from `meilisearch/token`
- https://www.meilisearch.com/docs/capabilities/security/advanced/tenant_token_payload -- search rules, `*` rules, parent-key scope, expiry
- https://www.algolia.com/doc/libraries/sdk/methods/search/generate-secured-api-key -- `generateSecuredApiKey`, `parentApiKey`, `filters`, `validUntil`, `restrictIndices`
- https://www.algolia.com/doc/guides/security/api-keys/how-to/user-restricted-access-to-data -- embedded filters users "can't alter"; `filterOnly`; `unretrievableAttributes`
- https://www.elastic.co/docs/manage-data/data-store/aliases -- filtered aliases; filters not applied to get-by-ID
- https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/granting-privileges-for-data-streams-aliases -- "Don't use filtered aliases in place of document level security"; data stream read also grants read on backing indices
- https://www.elastic.co/docs/deploy-manage/security/limitations -- "Aliases containing filters are not a secure way to restrict access to individual documents"
- https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/controlling-access-at-document-field-level -- document-level security role queries; not applied to write APIs
- https://github.com/pgvector/pgvector -- filtering with approximate indexes
- https://better-auth.com/docs/plugins/admin -- `impersonateUser`, `impersonationSessionDuration` (default 1 h), `session.impersonatedBy`, `impersonate-admins`, `stopImpersonating`
- https://better-auth.com/docs/plugins/organization -- `activeOrganizationId`, `setActiveOrganization`
- https://better-auth.com/docs/concepts/hooks -- `hooks.after`, `createAuthMiddleware`, `ctx.path`, `ctx.context.newSession`
