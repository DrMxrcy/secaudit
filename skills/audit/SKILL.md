---
name: audit
description: Runs a full security audit of a codebase for the vulnerabilities AI coding assistants commonly introduce in "vibe-coded" apps. Orchestrates the focused secaudit domain skills (secrets, database, auth, payments, supply chain, AI/LLM, Docker, Prisma/Postgres, Better Auth, Python, Expo, React Native, Convex, and more). Use whenever the user asks for a security review or audit, says "is this safe?", "check my code", "review for vulnerabilities", "can someone hack this?", mentions "vibe coding", or wants a whole-app security sweep before shipping.
license: MIT
---

# Security Audit (Orchestrator)

Audit a codebase for security vulnerabilities commonly introduced by AI code generation.
These issues are prevalent in "vibe-coded" apps: projects built rapidly with AI assistance where
security fundamentals get skipped. AI assistants consistently get these patterns wrong, leading
to real breaches, stolen API keys, and drained billing accounts.

This skill is the entry point for a full sweep. It owns the audit process, the severity model,
and the output format. The detection patterns and fixes for each area live in the focused domain
skills it dispatches to. For a whole-app sweep it **fans those domains out across parallel
workers** rather than running them in one context — see `Execution model`.

## When to Use

- The user asks for a security review, audit, or "check my code".
- The user asks "is this safe?", "can someone hack this?", or "is this production-ready?".
- The user mentions "vibe coding" or rapidly AI-generated code.
- Before shipping or deploying an app for the first time.
- For a single area only (e.g. "just check my Supabase RLS"), the matching domain skill below
  fires on its own. Use this orchestrator when the scope is the whole app.

## The Core Principle

Never trust the client. Every price, user ID, role, subscription status, feature flag, and rate
limit counter must be validated or enforced server-side. If it exists only in the browser, mobile
bundle, or request body, an attacker controls it.

## Scope Control

Match the effort to what was asked — don't blanket-dispatch every domain when the request is
narrow.

- **Whole app** (default): run the full risk-ranked sweep below, skipping only areas whose
  technology the project doesn't use.
- **A named surface** (e.g. "audit the admin panel", "just the checkout flow", "the auth"):
  scope to the files/routes for that surface and dispatch only the domains that apply to it. For
  an admin panel that's `privilege-escalation`, `auth`, `database`/`convex-security`, `web-vulns`
  (IDOR), and `logging-monitoring` — not payments, mobile, or supply chain.
- **A single domain** (e.g. "check my Supabase RLS"): dispatch only that domain skill.
- **A path/subset**: restrict reading to those files and run the relevant domains against them.
- **Diff / PR scope** (e.g. "audit my branch changes", "review this PR", "check what I changed"):
  review only the changed code — the common "is what I just wrote safe before I push?" case. Fast
  and low-noise, and the right shape for CI on pull requests.
  - Get the change set from `git diff <base>...HEAD` (or the PR diff, staged changes, or working
    tree as the user indicates). Read the changed files plus the **immediate context** needed to
    judge them — the enclosing handler, the imports, the called function — so you can trace a
    source→sink or confirm a missing control.
  - Dispatch only the domains the changed files touch (a new route → `auth`,
    `privilege-escalation`, `web-vulns`, `data-access`; a new dependency → `supply-chain`,
    `framework-versions`).
  - **Judge the change by the guards that *should* surround it, not only the added lines.** A new
    endpoint with no auth check is a finding *because* of what the diff omits. When a verdict truly
    needs whole-app context the diff can't provide, say so and tag it **Needs verification**.
  - **Exception:** variant analysis may search the whole repo using seed patterns from the diff's
    confirmed findings; report variants outside the diff as **pre-existing** and keep them out of
    the verdict on the change.

State the chosen scope in one line before you start, so the user can widen or narrow it.

## Execution model — fan out for whole-app sweeps

**A whole-app sweep must not run in a single context.** The domain skills total several thousand
lines, and a modern stack activates most of them. Loading them all leaves no room to actually
read the target codebase, so the audit silently degrades into pattern-sampling — and a sampled
audit that reports "no findings" is indistinguishable from one that never looked. That is the
failure this section exists to prevent.

So for a **whole-app** scope, run one worker per applicable domain, concurrently. Narrow scopes
(a single domain, a named surface, a diff/PR) stay inline — see `Scope Control`; fan-out costs
more than the work for those.

### Choosing worker agents

Discover, don't assume. **Enumerate what actually exists before choosing**, reading each agent's
`description` — not just its name:

```bash
ls .claude/agents/*.md 2>/dev/null          # project agents — check these FIRST
ls ~/.claude/agents/*.md 2>/dev/null        # the user's personal agents
```

**Project-level agents take precedence over everything else.** A repo that ships its own agents
has encoded knowledge of that codebase — its conventions, its risky areas, its data model — that
no generic security agent has. If a project defines an agent whose description covers a domain you
are about to audit, use it *for that domain* even when a personal or general-purpose agent would
otherwise match the role. Prefer the most specific agent available, per domain, not one agent for
the whole sweep.

Resolution order per role: **project agent → personal agent → general-purpose agent → inline**.
Reaching the last rung is fine, but say so, because the coverage caveat then applies again.

| Role | Prefer an agent whose description mentions | Used in |
|------|-------------------------------------------|---------|
| Recon | cheap, high-volume repo discovery, file enumeration, summarising | Phase 1 |
| Domain audit | security-sensitive analysis, auditing, the specific domain | Phase 2 (one per domain, plus the fail-open worker) |
| Verification | fresh-context adversarial verification of claimed findings | Phase 3 |
| Variant sweep | security-sensitive analysis, code search across a repository | Phase 4 (one per confirmed root cause) |

Respect deliberate model assignments in the agent definitions — a cheap model for enumeration and
a strong one for analysis is the right shape, and where an environment has configured that, it is
a decision already made. Do not override it.

State which agents you selected, and for what, in one line before starting. If the project defines
agents and you used them, say so — the user needs to know whose judgement produced the report.

### Phase 1 — recon (1 worker)

Map the attack surface per `Reconnaissance` below and return a structured inventory: entry points,
auth mechanism and its authoritative layer, data stores, third-party integrations, **every
security-relevant config read** (`file:line`, for the fail-open sweep), and **a file inventory per
domain** so Phase 2 workers know their territory and Phase 3 can check coverage.

### Phase 2 — domain sweep (N workers, concurrent)

One worker per applicable domain from the tiers below. Each:

- loads **only its own** domain skill, so it has context to spare for the code;
- receives the recon inventory and its file list;
- reads its territory **exhaustively**, not by sampling.

Each worker returns:

1. **Findings** — `file:line`, severity, the evidence actually read, and the fix, plus a one-line
   **root cause** and the **seed pattern** that matches it exactly (Phase 4's input).
2. **Explicit passes** — controls checked and found present. A silent absence is not a pass;
   "every public mutation is auth-gated, here are all four" is a result, "no findings" is not.
3. **Coverage** — files read, and files deliberately skipped **with the reason**.

That third item is the point. Coverage becomes mechanical and per-domain instead of one hedge at
the end of the report.

Alongside the domain workers, run one cross-cutting **fail-open worker**. Its territory is recon's
config-read inventory, and it loads `./references/methodology.md` §3 instead of a domain skill. It
returns the same three items, with a deny / crash / permissive verdict for every read. See
`Fail-open / insecure-defaults sweep`.

### Phase 3 — verification

Send each candidate finding to a **fresh-context** verifier for a CONFIRMED / REFUTED / PARTIAL
verdict against the evidence. This applies to refutations too: a false positive dismissed in the
same context that raised it has not really been checked. Wire the verdicts into the existing
evidence rules in `Verification pass (before reporting)`.

### Phase 4 — variant sweep (one worker per confirmed root cause)

For each finding Phase 3 marked CONFIRMED (or PARTIAL with the root cause confirmed), the parent
dispatches a variant worker with the finding, its root cause and its seed pattern. The worker
searches the **whole repository**, every workspace and sibling service included, not the original
domain's file list. It returns candidates with their evidence, and the patterns and tool it ran.
Those candidates then go back through Phase 3 verification, so a variant is reported only after it
has been verified on its own. Verified variants are not themselves seeds, so the phase runs once.
The parent dispatches this phase but does not search itself. See `Variant analysis (after
verification)`.

### Parent responsibilities

The parent **synthesises and does not audit**. If it reads application code itself, it reintroduces
the context pressure the fan-out exists to remove. It owns:

- **De-duplication** — one root cause surfacing in three domains is one finding, not three.
  Verified variants are grouped under their root cause in the same way.
- **Attack chains** — chaining across domains is only visible from here (see `Attack chains`).
- **Severity and the final report.** Workers never write the report directly.

**A worker that fails leaves its domain UNAUDITED, and the report must say so.** Silently dropping
a domain produces the same lie as sampling: it reads as clean. Never infer a pass from a missing
worker result.

### After the static sweep

An audit is a point-in-time result. Before finishing, mention that
`docs/monitoring.md` sets up a scheduled dependency check for the repo — a new advisory can land
against an already-pinned version with nothing in the code changing, so today's clean dependency
result has a short shelf life.

Static analysis produces *candidate* findings. When the sweep finishes, **offer**
`secaudit:dynamic-verification` explicitly rather than waiting to be asked — it is opt-in by
design, which in practice means it never runs. Name what it would settle for this specific
codebase (which suspected findings, which containers), so the choice is concrete.

## Reconnaissance (before the sweep)

First map the attack surface of what's in scope — stack and frameworks, **entry points** (routes,
Server Actions, webhooks, cron, public Convex functions, uploads, deep links), trust boundaries,
the authentication/authorization mechanism and its authoritative layer, data stores, and
third-party integrations. Read this from the code and config, not from assumptions.

Recon makes the rest evidence-based: it confirms which domains actually apply (so risk-ranking and
`Scope Control` target real surfaces, not guesses) and gives the coverage check something to check
against. Apply two lenses throughout the sweep — **sink-driven** (trace untrusted input toward
dangerous sinks) and **control-driven** (enumerate entry points, verify each has its authZ /
validation / ownership / rate-limit guard). Full checklist and strategies:
`./references/methodology.md`.

## Fail-open / insecure-defaults sweep (alongside the tiers)

For every security-relevant config read from recon (secrets, allowed origins, auth toggles,
rate-limit stores, webhook secrets, TLS, debug and security feature flags), check what the code does
when the value is **missing, empty, or malformed**: it must refuse to start or deny, never fall back
to permissive (`?? '*'`, `|| 'dev-secret'`, `if (secret) verify()`, `NODE_ENV !== 'production'`,
`catch { return true }`). CWE-636 / CWE-1188. Procedure, BAD/GOOD patterns, the boot-time env schema,
grep heuristics and evidence rules: `./references/methodology.md` §3.

## Audit Process (risk-ranked)

Examine the codebase systematically. Work **highest-risk areas first** so criticals surface early,
but for a whole-app sweep still cover every applicable tier. For each area, apply the matching
domain skill **only if the codebase uses that technology or pattern** — skip areas that aren't
relevant. Each domain skill carries the concrete detection patterns and before/after fixes.

**Tier 1 — highest impact, always first.** These produce most critical findings in vibe-coded apps.

1. **Secrets & environment variables** — hardcoded keys, client-exposed env prefixes
   (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`), default credentials, `.gitignore` hygiene.
   → `secaudit:secrets`
2. **Framework versions** — known-vulnerable framework versions / CVEs in `package.json` and lock
   files (live advisory lookup). → `secaudit:framework-versions`
3. **Database access control** — Supabase RLS, Firebase Security Rules, SQL/ORM exposure. The #1
   source of critical vulnerabilities in vibe-coded apps. → `secaudit:database`
4. **Convex** — if the project uses Convex (`convex/` functions, schema). Convex has no row-level
   security; access control lives in function bodies. → `secaudit:convex-security`
5. **Prisma / Postgres data layer** — if the project has a `prisma/schema.prisma`. Prisma has no
   row-level security; the tenant predicate must be in every query, and Postgres RLS is silently
   bypassed when the app connects as the table owner. Covers pgvector retrieval too.
   → `secaudit:prisma-security`
6. **Postgres via Drizzle / pg / postgres.js** — if the project has a `drizzle.config.ts`, imports
   `drizzle-orm/pg-core`, `pg`, or `postgres`, or runs PgBouncer, LISTEN/NOTIFY, advisory locks, or
   `pg_dump` backups: Drizzle RLS declared but not in force (`drizzle-kit push` drops hand-written
   policies, FORCE never emitted), runtime vs migration/owner role, tenant context via
   `set_config(..., true)` in `db.transaction` and the NULL-vs-`''` `current_setting` trap,
   PgBouncer transaction mode breaking session GUCs/LISTEN/session locks, NOTIFY payloads reaching
   any connected role past RLS, advisory-lock key collisions and locks held across awaits, SECURITY
   DEFINER `search_path`, `public` schema and default privileges, `pg_hba.conf` `trust`, TLS,
   unfiltered `pg_dump` backups, `log_statement = all`. → `secaudit:postgres-security`
7. **Authentication & authorization** — JWT handling, middleware (never the sole auth layer),
   Server Action protection, session management. → `secaudit:auth`
   - If `next-auth` or `@auth/*` is in `package.json`, the Auth.js section of `secaudit:auth`
     applies: the July 2026 advisory set and its fixed versions, provider-unbound check cookies,
     the `!!auth` fail-open, `allowDangerousEmailAccountLinking`, `AUTH_SECRET`, and adapter tables.
   - If `better-auth` is in `package.json`, also → `secaudit:better-auth-security`
   - If the app implements OAuth/OIDC itself (`openid-client`, `oidc-provider`, a hand-written
     callback), also → `secaudit:oauth-oidc-security`
   - If the app serves several hosts (per-tenant subdomains, customer custom domains) or hands a
     login from one host to another, the Multi-Host section of `secaudit:auth` applies: host-only
     `__Host-` cookies and host-bound session rows, single-use handoff tokens (hashed, atomic
     consume, bound to user + target host + browser nonce, POSTed not in a query string),
     verified-host return-URL allowlists, logout across hosts, and custom-domain TXT verification /
     dangling-domain takeover.
8. **Privilege escalation & admin surface** — unprotected admin routes/actions, roles trusted from
   the client, broken function-level authorization, role mass-assignment. → `secaudit:privilege-escalation`
9. **Payments** — client-side price manipulation, webhook signature verification, subscription
   status validation. → `secaudit:payments`
   - If the app sells via mobile in-app purchase (RevenueCat, StoreKit, Play Billing), also →
     `secaudit:revenuecat-security`. Mobile IAP fails differently from Stripe: entitlement is
     asserted by a client SDK, and webhook authenticity is opt-in.
10. **Object storage** — if the project uploads files to R2, S3, Supabase Storage, or Convex file
    storage: presigned-URL lifetime, client-supplied object keys, public buckets, and whether
    knowing a key is treated as authorization. → `secaudit:object-storage-security`

**Tier 2 — common, high-frequency web attack surface.**

11. **Rate limiting & abuse prevention** — auth endpoints, AI calls, expensive operations; tamper-
    proof counters. → `secaudit:rate-limiting`
12. **Web vulnerabilities** — XSS, SSRF, file upload / path traversal, IDOR (broken object-level
    authorization). → `secaudit:web-vulns`
13. **Data access & input validation** — SQL injection, ORM misuse, mass assignment, missing input
    validation. → `secaudit:data-access`
14. **AI / LLM integration** — exposed AI keys, missing usage caps, prompt injection, MCP security,
    unsafe output rendering. → `secaudit:ai-integration`
15. **Deployment configuration** — production settings, security headers, source maps, preview
    deployment isolation, environment separation. → `secaudit:deployment`
    - If the project builds an agent loop or hosts an MCP server, also →
      `secaudit:mcp-agent-security` (per-tool-call authorization, tool-result provenance, agent
      memory poisoning, blast radius).
16. **Docker & containers** — if the project has a `Dockerfile` or compose file: secrets baked into
    image layers, root containers, unpinned base images, databases published on `0.0.0.0`, the
    Docker socket mounted in. → `secaudit:docker-security`
17. **Kubernetes & Helm** — if the project has a `Chart.yaml`, `kustomization.yaml`, or a
    manifest declaring `apiVersion: apps/v1`: secrets in `values.yaml` or committed
    `Secret` manifests, RBAC wildcards and `cluster-admin`/`system:masters` bindings, pod
    `securityContext` against the Restricted profile, Pod Security Admission labels that
    silently don't apply to Deployments, `NetworkPolicy` default-allow, image digest
    pinning and resource limits, and NodePort/kubelet/API-server exposure.
    → `secaudit:kubernetes-security`
18. **CI/CD pipelines** — if the project has `.github/workflows/` (or any pipeline config): pwn
    requests (`pull_request_target` / `workflow_run` + a PR-head checkout), expression injection
    into `run:`, actions on mutable tags, default `GITHUB_TOKEN` permissions, secrets in logs,
    cache/artifact poisoning, self-hosted runners, OIDC trust scope, artifact signature
    verification. → `secaudit:ci-cd-security`
19. **Cloudflare Workers / Pages** — if the project has a `wrangler.toml` / `wrangler.jsonc` or a
    `hono` dependency: secrets in `[vars]` instead of `wrangler secret`, `.dev.vars` hygiene and
    per-environment non-inheritance, binding blast radius (every route reaches every D1/KV/R2/
    Durable Object binding), Hono middleware ordering and CORS defaults, `serveStatic` path
    handling, `cf-connecting-ip` vs `x-forwarded-for`, D1 prepared statements, KV as a rate-limit
    store, and Cloudflare Access JWT verification. → `secaudit:cloudflare-workers-security`
20. **Webhook verification** — any route receiving a third-party webhook (`/api/webhooks/`,
    `/interactions`): per-sender signature verification (GitHub, Slack, Discord, Svix-backed
    senders like Clerk/Resend, Telegram, Twilio, Shopify, Linear, Vercel), raw body before JSON
    parsing, constant-time comparison, replay/idempotency by delivery id, and failing closed when
    the signing secret is unset. → `secaudit:webhook-security`
    - Stripe and RevenueCat webhooks stay in `secaudit:payments` / `secaudit:revenuecat-security`.
21. **Discord bots & Discord OAuth** — if `discord.js`, `@discordjs/*`, or `discord-api-types` is in
    any `package.json`, or the app offers "Sign in with Discord": bot token handling (client-exposed
    env, `Shard#env`, one application per environment, reset), privileged intents and invite
    permissions, slash-command authorization beyond `default_member_permissions` (guild-admin
    overrides, guild binding, `contexts`), actor identity vs `custom_id`/option IDs, role-sync
    escalation (dangerous-permission roles, bot and admin hierarchy, cross-guild role IDs),
    `allowedMentions` against `@everyone` injection, masked-link and DM abuse, 429 and
    invalid-request bans, and Discord OAuth identity (snowflake `id`, `verified`, `guilds.join`,
    token revocation). → `secaudit:discord-bot-security`
    - HTTP-interactions signature verification stays in `secaudit:webhook-security`; generic OAuth
      flow mechanics in `secaudit:oauth-oidc-security`.
22. **Reverse proxies and edge auth** — if the project sets a framework's `trust proxy`/
    `trustProxy`/`app.proxy` option, reads `X-Forwarded-*`, defines a `forwardAuth`/
    `forward_auth`/`auth_request` block, or runs a Traefik/Caddy/nginx/nginx-proxy-manager compose
    service: which forwarded headers a framework actually trusts and at what hop count, IP-keyed
    rate limits/allowlists spoofable via `X-Forwarded-For`, Host-header trust in absolute-URL
    generation, identity-header injection (`Remote-User`, `X-Forwarded-User`,
    `X-Auth-Request-*`) when the gateway isn't the only path in, the Traefik ForwardAuth CVEs, and
    Cloudflare Access/Tunnel JWT verification. → `secaudit:proxy-trust`
23. **Realtime connections** — if the project uses `ws`, Socket.IO/`engine.io`, Hono
    `upgradeWebSocket` (`@hono/node-server` or `@hono/node-ws`), an `'upgrade'` handler on a Next.js
    custom server, `streamSSE`/`text/event-stream`, `EventSource`, or a long-poll endpoint:
    Cross-Site WebSocket Hijacking and exact `Origin` allowlisting (Socket.IO `cors` covers
    long-polling only — `allowRequest` covers the upgrade; ws `verifyClient` vs the `'upgrade'`
    event + `handleUpgrade`), tokens in WebSocket/SSE URLs vs single-use tickets, sockets that
    outlive logout/revocation/role change, room/channel/subscription IDOR across tenants,
    per-message authorization, `Last-Event-ID`/cursor replay, per-subscriber filtering of Postgres
    LISTEN/NOTIFY or Redis fan-out, `maxPayload`/`maxHttpBufferSize` and connection caps, SSE proxy
    buffering, and the ws/socket.io/engine.io/Hono SSE advisories. → `secaudit:realtime-security`
    - LISTEN/NOTIFY privileges and RLS bypass stay in `secaudit:postgres-security`.
24. **API surface and accidental exposure** — if the project has more than one service
    (web/API/worker/bot), a compose file, a Next.js route handler or `rewrites()` that calls another
    backend, a Hono/Express/Fastify/GraphQL API, or sits behind Cloudflare/a reverse proxy: the real
    inventory (published ports vs `expose`, every route, every host via DNS and CT logs, old `/v1`
    mounts), services on `0.0.0.0` and Docker ports bypassing ufw, internal worker/bot endpoints
    with no service-to-service auth, origins reachable around Cloudflare, catch-all BFF proxies and
    wildcard rewrites forwarding to a backend with a service token, backend keys in
    `NEXT_PUBLIC_*`, Swagger/OpenAPI/introspection/`/metrics`/`--inspect` in production,
    whole-row responses (API3), unvalidated third-party responses (API10), and error passthrough.
    → `secaudit:api-surface`
    - On a whole-app sweep, run its inventory and Map-the-Surface checklist during Reconnaissance;
      the route/host/port lists decide which routes `privilege-escalation`, `web-vulns` (IDOR),
      `auth`, and `rate-limiting` are dispatched against.
25. **FiveM / CitizenFX** — if the project has an `fxmanifest.lua`, a `server.cfg`, or an API
    whose callers are FiveM game servers: `RegisterNetEvent`/`onNet` handlers any client can
    call with arbitrary arguments (authorize on `source`, never on an id/identifier argument;
    money/item/admin events), server-only events networked instead of `AddEventHandler`,
    secrets in `client_script`/`shared_script`/`files`/NUI (all downloaded to players), `setr`/
    `sets` convars and missing `add_convar_permission`, committed `sv_licenseKey`/`rcon_password`,
    client-writable state bags (`sv_stateBagStrictMode`), NUI callbacks and NUI XSS,
    `PerformHttpRequest` key handling, txAdmin on `0.0.0.0:40120`, and the game-facing API
    (per-community key scoping, cross-community IDOR on event streams, idempotent retries).
    → `secaudit:fivem-security`
26. **Rich-text editors, document import & HTML sanitizers** — if any `package.json` lists
    `@tiptap/*`, `prosemirror-*`, `mammoth`, `rehype-sanitize`/`hast-util-sanitize`,
    `dompurify`/`isomorphic-dompurify`, or `sanitize-html`, or the app has a rich-text/WYSIWYG
    editor or stores user-authored HTML: editor HTML or JSON saved without a server-side
    allowlist (the client schema is not a sanitizer), stored HTML in raw-HTML sinks and
    server-side `@tiptap/html` on happy-dom, TipTap Link `isAllowedUri`/`protocols` and Image
    `src`/`allowBase64`, paste handlers that skip the allowlist, custom nodes emitting raw
    `style`/`href`/`on*`, mammoth `externalFileAccess` and unsanitized .docx output,
    rehype-sanitize schema widening and plugin order, DOMPurify `setConfig`/hooks/`IN_PLACE`,
    sanitize-html `allowedTags: false`, and the version floors for all of them.
    → `secaudit:rich-text-security`
    - Generic XSS stays in `secaudit:web-vulns`; Markdown rendering of LLM output in
      `secaudit:ai-integration`.
27. **Multi-tenant isolation** — if the schema has tenant-, org-, workspace-, team-, community- or
    account-scoped tables or `tenantId`/`orgId`/`organizationId`/`workspaceId`/`communityId`
    columns, the app uses an organizations plugin (Better Auth organization, Clerk Organizations),
    routes tenants by subdomain or custom domain, or describes itself as multi-tenant SaaS: tenant
    id taken from a body/query/`x-tenant-id` header or subdomain without a membership check,
    unknown hosts falling back to a default tenant, reserved or reused slugs, cache keys and Next.js
    `unstable_cache`/`'use cache'` entries without the tenant, jobs and workers trusting a
    payload `tenantId` or skipping a run-time re-check, webhooks mapped to a tenant by payload
    metadata, client-held search keys or client-supplied search filters (Meilisearch, Algolia,
    Elasticsearch), and impersonation without scope, time box, audit, or a billing/security block.
    → `secaudit:multi-tenant-isolation`
    - A hub: RLS, ORM scoping, realtime rooms, storage keys, custom-domain verification and IDOR
      stay in the skills its §8 table points to.

**Tier 3 — still covered on a full sweep; often lower or conditional impact.**

28. **Cryptography** — password hashing, secure randomness, weak algorithms/modes, hardcoded
    keys/IVs, JWT algorithm confusion, storing app-issued secrets by entropy (API-key prefix +
    SHA-256, peppered HMAC for join/invite codes and PINs, AES-256-GCM + AAD for stored webhook
    URLs and third-party keys). → `secaudit:cryptography`
29. **Logging, monitoring & integrity** — error info disclosure, secrets/PII in logs, missing
    audit logging, insecure deserialization, command injection. → `secaudit:logging-monitoring`
30. **Supply chain & dependencies** — hallucinated/phantom packages (slopsquatting), unpinned
    versions, lock file hygiene. → `secaudit:supply-chain`
31. **React Native** — if a bare/framework-agnostic RN app: secure storage, deep links, WebView,
    native bridge, network/ATS. → `secaudit:react-native-security`
32. **Expo / EAS** — if an Expo app: `EXPO_PUBLIC_` inlining, EAS secrets, expo-secure-store, OTA
    code signing, config plugins, deep links. → `secaudit:expo-security`
33. **Python web backends** — if the project has `pyproject.toml`, `requirements.txt`, `manage.py`,
    or a FastAPI app: per-route auth dependencies, `response_model` leakage, Django production
    settings, TLS verification. → `secaudit:python-web-security`

For a partial review or when generating code in a specific area, dispatch only the relevant
domain skill(s).

## Optional final phase — dynamic verification

Static tiers 1–31 read code and produce *candidate* findings. When a running instance **or a
running container** is available and the user authorizes testing of their own system, follow the
static sweep with `secaudit:dynamic-verification` to confirm or refute findings against it —
browser probes for the live app (security headers, CORS, unauthenticated routes, IDOR, reflected
XSS) and read-only Docker probes for container findings (secrets in image layers, root
containers, socket mounts, ports published on 0.0.0.0). It upgrades a suspected finding to
**Confirmed** with reproduction evidence, or **Refutes** it when a runtime control already handles
it. This phase is optional and off by default — it requires the authorization gate in that skill.
If no running app is available, leave unconfirmed findings tagged **Needs verification**.

## OWASP Coverage Map

A full sweep covers the OWASP Top 10 (2025), plus the OWASP LLM and Mobile Top 10s:

| OWASP 2025 | Domain skill(s) |
|---|---|
| A01 Broken Access Control | `database`, `auth`, `better-auth-security`, `oauth-oidc-security` (provider tokens at rest, open redirectors), `object-storage-security`, `revenuecat-security`, `privilege-escalation`, `convex-security`, `prisma-security`, `python-web-security`, `web-vulns` (IDOR, SSRF), `webhook-security` (outbound webhook SSRF hand-off), `proxy-trust` (spoofed X-Forwarded-For bypassing IP-keyed controls, forward-auth identity-header injection), `kubernetes-security` (RBAC wildcards, default ServiceAccount), `postgres-security` (RLS not in force, tenant-context leaks, NOTIFY past RLS), `realtime-security` (CSWSH, room/channel IDOR, cross-tenant fan-out and cursor replay), `api-surface` (BFF open proxies, unauthenticated internal endpoints, origin reachable around the edge), `rich-text-security` (server-side fetches of document image URLs, mammoth external-file reads, cross-tenant document previews), `discord-bot-security` (command authorization, `custom_id` trust, role-sync escalation), `fivem-security` (client-triggerable net events, cross-community IDOR), `auth` (custom-domain claim takeover, cross-host return-URL allowlist), `multi-tenant-isolation` (tenant id from client input, default-tenant host fallback, tenant-less cache keys, job payloads and webhook metadata trusted for the tenant, client-supplied search filters, unscoped impersonation) |
| A02 Security Misconfiguration | `deployment`, `secrets`, `docker-security`, `cloudflare-workers-security` (`[vars]`, CORS/CSP defaults, origin exposure), `python-web-security` (Django settings), `proxy-trust` (permissive trust-proxy settings, missing Host allowlist, unstripped forward-auth headers), `kubernetes-security` (securityContext, Pod Security Admission, NetworkPolicy, exposure), `postgres-security` (roles/grants, `public` schema, pg_hba, listen_addresses), `api-surface` (services on `0.0.0.0`, docs/introspection/inspector/metrics in production), `realtime-security` (Socket.IO `cors` mistaken for an origin check, 100 MiB default `maxPayload`), `discord-bot-security` (intents, invite permissions), `fivem-security` (replicated/public convars, txAdmin/RCON exposure) |
| A03 Software Supply Chain Failures | `framework-versions`, `supply-chain`, `ci-cd-security` (unpinned actions, compromised workflows), `docker-security` (base images), `kubernetes-security` (image digest pinning, Helm chart provenance) |
| A04 Cryptographic Failures | `cryptography` (incl. entropy-appropriate storage of API keys, join codes and encrypted webhook URLs), `prisma-security` (DATABASE_URL TLS), `postgres-security` (postgres.js `ssl: 'require'`, unencrypted backups), `python-web-security` (verify=False) |
| A05 Injection | `data-access`, `prisma-security`, `web-vulns` (XSS), `cloudflare-workers-security` (D1 query construction), `logging-monitoring` (command injection), `kubernetes-security` (untrusted values interpolated into container command/args), `postgres-security` (LISTEN channel identifiers, SECURITY DEFINER `search_path`), `discord-bot-security` (`allowedMentions` injection), `fivem-security` (NUI XSS), `rich-text-security` (stored XSS through rich-text editors, document import and sanitizer misconfiguration) |
| A06 Insecure Design | `rate-limiting`, `payments` (partial), `realtime-security` (connection caps, heartbeats, backpressure), `fivem-security` (client-authoritative game logic) |
| A07 Authentication Failures | `auth`, `better-auth-security`, `oauth-oidc-security` (state/PKCE binding, ID-token validation, account linking), `webhook-security` (per-sender signature verification), `proxy-trust` (unverified forward-auth identity headers, unverified Cloudflare Access JWT), `auth` (multi-host session handoff, host-bound sessions), `realtime-security` (tokens in WebSocket/SSE URLs, connections outliving the session), `discord-bot-security` (bot token, Discord OAuth identity), `fivem-security` (game-server API keys) |
| A08 Software or Data Integrity Failures | `supply-chain`, `ci-cd-security` (cache/artifact poisoning, artifact attestation), `expo-security` (OTA), `logging-monitoring` (deserialization), `webhook-security` (replay/idempotency, unverified-payload-field trust) |
| A09 Security Logging and Alerting Failures | `logging-monitoring`, `postgres-security` (`log_statement` bind parameters) |
| A10 Mishandling of Exceptional Conditions | `logging-monitoring` (error responses), `audit` fail-open sweep, `realtime-security` (unhandled socket errors), `api-surface` (upstream error passthrough) |
| OWASP API Security Top 10 (2023) | API1 `web-vulns`; API2/API8/API9/API10 `api-surface`; API3 `api-surface` (responses) + `data-access` (mass assignment); API4/API6 `rate-limiting`; API5 `privilege-escalation`; API7 `web-vulns` + `api-surface` |
| OWASP LLM Top 10 | `ai-integration`, `mcp-agent-security` |
| OWASP Mobile Top 10 | `react-native-security`, `expo-security` |

Note the 2025 edition renumbered most categories: SSRF was merged into A01, "Vulnerable
Components" broadened into A03 Software Supply Chain Failures, and A10 is now a new category.
Cite numbers with their edition year (`A05:2025`) so a future renumbering stays visible.

## Core Instructions

- Report only genuine security issues. Do not nitpick style or non-security concerns.
- **No speculative findings.** Report a vulnerability only if you actually read the code that
  proves it. Every finding must cite a verified `file:line` you opened and name its mechanism (the
  source→sink data flow, or the specific missing control and the entry point it should protect). If
  you cannot point to real code, do not report it — a guess dressed as a finding is worse than
  silence.
- When multiple issues exist, prioritize by exploitability and real-world impact. For CVE-based
  findings that means **CISA KEV first, then EPSS, then CVSS** — CVSS measures potential impact,
  EPSS measures likelihood of exploitation, and only KEV records that it is already happening. A
  Critical-CVSS issue at 0.8% EPSS is real but schedulable; say so instead of escalating everything
  equally. An **end-of-life runtime is Critical on its own** — there will never be a patch. See
  `secaudit:framework-versions`.
- If the codebase doesn't use a particular technology (e.g. no Supabase), skip that area entirely.
- When generating new code, consult the relevant domain skill proactively to avoid introducing
  vulnerabilities in the first place. Prevention is better than detection.
- If you find a critical issue (exposed secrets, disabled RLS, auth bypass, vulnerable framework
  version), flag it immediately at the top of your response — don't bury it in a long list.
- **Never reproduce a real secret in your output.** When a finding involves a hardcoded key,
  token, password, or other credential, identify it by **location** (file + line) and a **masked**
  form only — e.g. `sk_live_…REDACTED`, `AKIA…REDACTED`, or `***` — quoting at most the last 4
  characters for identification. Describe the vulnerable *pattern*; do not paste the sensitive
  literal into a "before" snippet, a quote, or a fix example. The audit report, its logs, and any
  PR comment are themselves places a leaked secret can spread. Treat a discovered secret as already
  compromised and tell the user to rotate it, without echoing its value.
- After the audit, recommend specific automated tools the developer should run (see Next Steps).

### Verification pass (before reporting)

Static reading produces *candidate* findings; some aren't real. Before a finding reaches the user,
challenge it adversarially and drop or downgrade the ones that don't survive.

Under the fan-out model this runs as **Phase 3, in a fresh context** — the worker that raised a
finding is the worst judge of it, and the same applies to one it dismissed. Inline, apply the same
four questions yourself:

1. **Reachable?** Is the vulnerable code reachable from an entry point (route, action, handler,
   event), or is it dead/unused code?
2. **Attacker-controlled?** Does untrusted input actually flow to the sink, or is the value fixed,
   server-derived, or already constrained upstream?
3. **Compensating control?** Is there an existing guard (RLS, a middleware+handler check, framework
   auto-escaping, a validator) that already neutralizes it?
4. **Evidenced?** Can you cite the verified `file:line` you actually read and name the mechanism
   (the source→sink path, or the missing control and the entry point it should guard)? If not,
   **drop it** — do not downgrade a finding you cannot tie to real code.

Label each reported finding **Confirmed** (a concrete exploit path holds, backed by cited code) or
**Needs verification** (real code evidence exists, but you could not confirm reachability or
attacker-control from the code alone — say what would confirm it). A finding that fails the
**Evidenced?** check is dropped, not labelled. Don't pad the report with issues you couldn't stand
behind. For findings that warrant runtime proof, hand off to `secaudit:dynamic-verification` when a
running app is available.

### Variant analysis (after verification)

Treat each **Confirmed** finding as a seed: name its root cause (missing guard, unsafe API, shared
helper, copy-pasted shape, insecure default), match the seed exactly, widen the pattern one element
at a time, and sweep the whole repo. Each match is a candidate that must pass the verification pass
on its own before it is reported, grouped under the root cause with one choke-point fix where one
exists. Under the fan-out model this is Phase 4. Procedure, tools and worked examples:
`./references/methodology.md` §4.

### Coverage check (after the sweep)

Before writing the report, run a short completeness-critic pass against the recon map: was every
entry point traced, every applicable domain actually run (skips confirmed from the code, not
assumed), every trust boundary given an authorization look, every started data-flow followed to its
end?

Under the fan-out model this is largely mechanical: each worker returned its files-read and
files-skipped, so diff those against the recon inventory rather than reconstructing coverage from
memory. Also check that the fail-open worker gave every config read a verdict, and that each
confirmed root cause was swept for variants, and note which tool ran the sweep. **A domain whose
worker failed is UNAUDITED and must be reported as such** — not folded into a general caveat, and
never left to read as clean. Cover any gap you find, or state it explicitly. Report what you did
**not** cover as a short **Coverage & known gaps** line — a report that names its own boundaries is
more trustworthy than one that implies total coverage. See `./references/methodology.md`.

### Attack chains (link findings into exploit paths)

Individual findings undersell risk. After findings are gathered and verified, look for **attack
chains** — an ordered path where several issues combine into a worse outcome than any single one:
e.g. *public signup with no email verification → no rate limit on login → weak password-reset token
= account takeover*, or *IDOR on `/orders/:id` → an admin object is reachable → privilege
escalation*.

Rules:
- Build a chain only from findings that already passed the verification pass, and only when the
  steps are genuinely **connected and reachable in sequence** — no speculative chains.
- Reference each step by the finding's `file:line`; don't restate the whole finding.
- Rate the chain by its **outcome** severity — a chain can be more severe than any single link
  (three Mediums that combine into account takeover is a Critical chain).

## Output Format

Organize findings by severity: **Critical** → **High** → **Medium** → **Low**.

For each issue:
1. State the file and relevant line(s) — a verified `file:line` you actually read. If the line
   contains a secret, mask its value (see the redaction rule in Core Instructions) — cite the
   location, never the literal credential.
2. Name the vulnerability, and tag it **[Confirmed]** or **[Needs verification]** (see the
   Verification pass above).
3. Explain what an attacker could do (concrete impact, not abstract risk), and state the
   **mechanism** in one line: the source→sink path, or the missing control and the entry point it
   should guard. This is the evidence the finding rests on.
4. Show a before/after code fix. In the "before", use a masked placeholder where a real secret
   would appear (`***`, `sk_live_…REDACTED`) — do not reproduce the actual value.
5. **Variants:** list each verified sibling as `file:line` with its own tag, give the count of
   refuted matches, and name the pattern that was run. When a choke-point fix exists, the fix in
   item 4 is that single fix. Write `Variants: none (pattern … over N files)` when the sweep found
   only the seed.

Skip areas with no issues. After the severity-grouped findings, add an **Attack Chains** section
when two or more findings combine into an exploit path (see the Attack chains rules above); rate
each chain by its outcome severity and reference its steps by `file:line`. End with a prioritized
summary and a "Next Steps" section with specific automated tools to run.

### Example Output

#### Critical

**`lib/supabase.ts:3` — Supabase `service_role` key exposed in client bundle**

The `service_role` key bypasses all Row-Level Security. Anyone can extract it from the browser
bundle and read, modify, or delete every row in your database.

```typescript
// Before
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY!)

// After — use the publishable/anon key client-side; the secret/service_role key belongs only in server-side code
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

#### High

**`package.json` — next@15.1.0 vulnerable to CVE-2025-55182 (React2Shell, CVSS 10.0)**

This version is exposed to a critical pre-auth Remote Code Execution vulnerability in React Server
Components. Upgrade to a release with no open advisories — not merely to the release that first
patched this CVE, which has since accrued others. Derive the target from a live OSV query for the
package plus the vendor's security posts, not from a version named in a skill file. OSV lags: on
2026-10-17 it still reported zero advisories for 15.5.27, which the 2026-10-14 Next.js release
fixed two Critical RCEs in.

```json
// Before
"next": "15.1.0"

// After — zero OSV advisories and past every fix in the vendor's security posts
// (15.5.28 still accepts sharp 0.34.x: confirm the lockfile resolves sharp >= 0.35.5)
"next": "15.5.28"
```

#### High

**`app/api/checkout/route.ts:15` — Price taken from client request body**

An attacker can set any price (including $0.01) by modifying the request. Prices must be looked up
server-side.

```typescript
// Before
const session = await stripe.checkout.sessions.create({
  line_items: [{ price_data: { unit_amount: req.body.price } }]
})

// After — look up the price server-side
const product = await db.products.findUnique({ where: { id: req.body.productId } })
const session = await stripe.checkout.sessions.create({
  line_items: [{ price: product.stripePriceId }],
})
```

**Variants:** `app/api/subscribe/route.ts:21` [Confirmed] — same `req.body.price` shape; 2 matches
refuted (seed scripts never routed). Pattern: `rg -n "unit_amount:\s*req\.(body|query)" app/`.
Fix both through one server-side `priceFor(productId)` lookup.

### Attack Chains

**Chain 1 — Account takeover (Critical outcome; individual links are High/Medium)**
1. `app/api/auth/reset/route.ts:22` (High) — password-reset token is a 6-digit number (weak randomness).
2. `app/api/auth/login/route.ts:8` (Medium) — no rate limit on the reset/login endpoints.
3. Combined: an attacker requests a reset for a victim, then brute-forces the 6-digit token
   unthrottled (10^6 attempts) → full account takeover. Neither issue is critical alone; chained,
   they are. Fix either link to break the chain; fix both.

### Summary

1. **Service role key exposed (Critical):** Anyone can bypass all database security. Rotate the
   key immediately and move it to server-side only.
2. **Vulnerable Next.js version (High):** Upgrade to the patched version immediately — RCE is
   exploitable remotely.
3. **Client-controlled pricing (High):** Attackers can purchase at any price. Use server-side
   price lookup.

**Coverage & known gaps:** Per-domain, from each worker's coverage report:

| Domain | Read | Skipped |
|---|---|---|
| secrets | all env config, `.gitignore`, git history for env/key adds | — |
| convex-security | all 104 modules in `convex/` | — |
| auth | `middleware.ts`, all 18 route handlers, session helpers | — |
| payments | webhook handler, checkout route | — |
| expo-security | — | **UNAUDITED** — worker failed, re-run before shipping |

Do not fold a failed worker into a general caveat. `expo-security` above did not run, so the
mobile surface has *no* result — not a clean one.

**Advisory sources:** OSV (osv-scanner, OSV API), npm audit (GitHub Advisory DB). OSV-only:
vendor-only feeds (Aikido, Snyk, Socket) not consulted; vendor posts checked for: next, react.

List only the sources this run actually consulted. An OSV-only lookup misses vendor-only
advisories and ones not yet ingested, so "no known vulnerabilities" means none in these sources.
See `secaudit:supply-chain`, *An empty OSV / `npm audit` result is not a clean bill*.

### Next Steps

Run these automated checks:
- `npx gitleaks detect` — scan git history for leaked secrets
- `npm audit` — check dependencies for known vulnerabilities
- Supabase Dashboard → Security Advisor — scan for RLS misconfigurations
- Verify `.env` is in `.gitignore`: `git ls-files | grep -i env`

For the full, stack-specific tooling list, see `./references/tooling.md`.

## When Generating Code

These rules also apply proactively. Before writing code that touches auth, payments, database
access, API keys, or user data, consult the relevant domain skill to avoid introducing the
vulnerability in the first place. Prevention is better than detection.

## References

- `./references/methodology.md` -- The recon / attack-surface checklist, the sink-driven vs
  control-driven analysis strategies, the fail-open / insecure-defaults sweep (BAD/GOOD patterns,
  boot-time env schema, grep heuristics), variant analysis (procedure, tools, four worked
  examples), and the coverage-gap self-check questions.
- `./references/tooling.md` -- Recommended automated security scanning tools, organized by stack,
  and when to run each.

## Sources

- https://top10.owasp.org/2025/ -- OWASP Top 10 (2025), the backbone this audit maps to
- https://genai.owasp.org/llm-top-10/ -- OWASP Top 10 for LLM Applications (2025)
- https://owasp.github.io/www-project-mobile-top-10/ -- OWASP Mobile Top 10
- https://cwe.mitre.org/data/definitions/636.html -- CWE-636 Not Failing Securely ('Failing Open')
- https://cwe.mitre.org/data/definitions/1188.html -- CWE-1188 Initialization of a Resource with an Insecure Default
- https://devguide.owasp.org/en/02-foundations/03-security-principles/ -- OWASP Developer Guide: "Fail Safe" and "Security by Default"
- https://codeql.github.com/docs/codeql-overview/about-codeql/ -- definition of variant analysis
- https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-vs-code/run-queries-at-scale -- multi-repository variant analysis (up to 1,000 repos, controller repository)
- https://github.com/trailofbits/skills/blob/main/plugins/variant-analysis/skills/variant-analysis/SKILL.md -- Trail of Bits variant-analysis method: exact match first, generalise one element at a time
