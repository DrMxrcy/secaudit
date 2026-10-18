# Secaudit v3.3 - Installable Claude Code Plugin

> An installable Claude Code plugin that audits AI-assisted apps for security vulnerabilities, organized as one orchestrator plus focused, fully-sourced per-domain skills. Builds on earlier open-source work (see Credits).

A security plugin that audits "vibe-coded" apps (projects built rapidly with AI assistance) for the vulnerabilities AI coding assistants consistently introduce: exposed secrets, broken database access control, missing auth, client-side trust, insecure payments, dependency supply-chain risks, web vulnerabilities, cryptographic failures, and mobile/backend platform issues.

## What changed

v2.0 was a single monolithic skill. v3.x is a proper plugin: **one orchestrator skill plus 38 focused domain skills**, each with a precise trigger so the right one fires on its own during targeted work and code generation, while the orchestrator still runs the full sweep.

- **Installable as a plugin** via `/plugin marketplace add` (no more copying a folder).
- **Focused skills** that trigger independently: ask "check my Supabase RLS" and only the database skill loads.
- **Comprehensive coverage**: the full OWASP Top 10 (2025) and the OWASP API Security Top 10 (2023), plus the OWASP LLM and Mobile Top 10s. Dedicated skills for Convex, Expo/EAS, and React Native.
- **Every claim is sourced.** Each skill cites primary sources (official docs, NVD/GitHub advisories, OWASP); see [`SOURCES.md`](SOURCES.md). Content was research-verified in mid-2026 (which caught and corrected a rejected CVE reference).

> **Breaking change:** the old top-level `vibe-security/` skill folder is gone. If you installed v2.0 by copying that folder, re-install as a plugin (below). Skills are now namespaced as `secaudit:<name>`.

## Installing

In Claude Code:

```
/plugin marketplace add DrMxrcy/secaudit
/plugin install secaudit@secaudit
```

That registers the marketplace from this repo and installs the plugin. All skills auto-load.

## Using it

Ask naturally and the right skill fires:

- "audit my app for security" or "is this safe?" runs the full sweep (`secaudit:audit`).
- "check my Supabase RLS" loads only `secaudit:database`.
- "is my Convex backend secure?" loads only `secaudit:convex-security`.

The orchestrator skips areas whose technology you do not use. If you have no Stripe, it skips payments; no Firebase, it skips Firebase rules.

## Skills

| Skill | Covers |
|-------|--------|
| `secaudit:audit` | Orchestrator: runs the full security sweep, dispatches to the domain skills, hunts variants of every confirmed finding, and sweeps for fail-open defaults |
| `secaudit:framework-versions` | Known-vulnerable framework versions and critical CVEs (Next.js, React, Astro, Hono, Fastify, Koa, Elysia, TanStack Start, Auth.js, Drizzle, Traefik) |
| `secaudit:secrets` | Hardcoded keys, client-exposed env prefixes, default credentials, `.gitignore` hygiene |
| `secaudit:database` | Supabase RLS, Firebase Security Rules, storage policies, Edge Functions, the new key model |
| `secaudit:convex-security` | Convex: public vs internal functions, validators, auth in handlers, file-storage access |
| `secaudit:prisma-security` | Prisma has no RLS: tenant scoping in every query, Postgres RLS silently bypassed by the table owner, pgvector retrieval |
| `secaudit:postgres-security` | Self-hosted Postgres via Drizzle/pg/postgres.js: Drizzle RLS not in force (push drops policies, no FORCE), tenant GUCs and the NULL-vs-'' trap, PgBouncer transaction mode, LISTEN/NOTIFY payloads past RLS, advisory-lock collisions, SECURITY DEFINER search_path, roles/grants, pg_hba/TLS, pg_dump backups, log_statement |
| `secaudit:auth` | JWT verification, why middleware is not a security boundary, Server Actions, sessions, Clerk, Auth.js/NextAuth (July 2026 advisories, unbound check cookies, `!!auth` fail-open, account linking, `AUTH_SECRET`, adapter tables), multi-host sessions and cross-host handoff tokens, custom-domain verification |
| `secaudit:better-auth-security` | Better Auth: getSessionCookie is not a gate, cookieCache vs revocation, org/admin roles, account linking |
| `secaudit:privilege-escalation` | Admin-surface review: unprotected admin routes/actions, roles trusted from the client, broken function-level authorization, role mass-assignment |
| `secaudit:rate-limiting` | Where limits are required, tamper-proof counters, billing and spend caps |
| `secaudit:payments` | Client-side price manipulation, webhook signature verification, subscription validation |
| `secaudit:revenuecat-security` | Mobile in-app purchase: client-asserted entitlement, opt-in webhook auth, sandbox purchases, entitlement writes |
| `secaudit:webhook-security` | Inbound webhook verification beyond Stripe/RevenueCat: GitHub, Slack, Discord (Ed25519), Svix-backed senders (Clerk, Resend), Telegram, Twilio, Shopify, Linear, Vercel — raw body, constant-time compare, replay/idempotency, fail-closed secrets |
| `secaudit:discord-bot-security` | discord.js v14 bots & Discord OAuth login: bot token handling, privileged intents, slash-command authorization beyond `default_member_permissions`, `custom_id` tampering, role-sync escalation and hierarchy, `allowedMentions` injection, DM/masked-link abuse, 429/invalid-request bans, snowflake-keyed identity and `guilds.join` scope |
| `secaudit:supply-chain` | Slopsquatting / hallucinated packages, lock-file hygiene, weak default secrets |
| `secaudit:react-native-security` | RN core: secure storage, deep links, WebView, native bridge, network/ATS, PKCE |
| `secaudit:expo-security` | Expo/EAS: `EXPO_PUBLIC_` inlining, EAS secrets, secure-store, OTA code signing, config plugins |
| `secaudit:ai-integration` | AI key exposure, usage caps, prompt injection, MCP threat model, chat/RAG layer, output sanitization |
| `secaudit:mcp-agent-security` | Agents and MCP servers: per-tool-call authorization, tool-result laundering, memory poisoning, blast radius |
| `secaudit:deployment` | Production config, security headers, source maps, preview-deployment isolation, clickjacking |
| `secaudit:docker-security` | Secrets in image layers, root containers, unpinned bases, docker.sock mounts, ports on 0.0.0.0 |
| `secaudit:kubernetes-security` | Kubernetes/Helm manifests: secrets in `values.yaml`/`Secret` objects, RBAC wildcards and `cluster-admin`, pod `securityContext`, Pod Security Admission, `NetworkPolicy` default-allow, image pinning, NodePort/kubelet/API-server exposure |
| `secaudit:oauth-oidc-security` | OAuth/OIDC you implement: per-flow `state` + PKCE S256, exact `redirect_uri`, ID-token validation and mix-up, account linking on unverified email, provider tokens at rest, refresh rotation, and the provider side (`oidc-provider`) |
| `secaudit:object-storage-security` | R2/S3: presigned URLs as bearer credentials, client-minted keys, public buckets, read authorization |
| `secaudit:ci-cd-security` | GitHub Actions: pwn requests, `run:` expression injection, unpinned actions, token permissions, cache/artifact poisoning, OIDC scope, cosign verification |
| `secaudit:cloudflare-workers-security` | Workers/Pages + Hono: `[vars]` vs `wrangler secret`, binding blast radius (D1/KV/R2/Durable Objects), middleware ordering, `serveStatic` paths, `cf-connecting-ip` trust, Access JWT |
| `secaudit:proxy-trust` | Reverse proxies & edge auth: `X-Forwarded-*`/Host trust, `trust proxy`/`app.proxy`/`trustProxy`, IP-keyed control bypass, forward-auth identity-header injection (Traefik/Caddy/nginx), Cloudflare Access JWT verification, Tailscale Serve headers |
| `secaudit:realtime-security` | WebSocket/SSE/long-poll: CSWSH and `Origin` allowlists (ws `'upgrade'` + `handleUpgrade`, Socket.IO `allowRequest`, Hono `upgradeWebSocket`), single-use tickets vs URL tokens, sockets outliving the session, room/channel IDOR, `Last-Event-ID` replay, per-subscriber pub/sub fan-out, `maxPayload`/connection limits, SSE proxy buffering |
| `secaudit:api-surface` | Accidentally reachable backends and internal APIs: real route/port/host inventory (compose ports vs expose, `showRoutes`, CT logs, old `/v1`), `0.0.0.0` binding, service-to-service auth for worker/bot endpoints, origin lockdown behind Cloudflare (Tunnel/AOP/allowlist), BFF catch-all proxies and wildcard rewrites, Swagger/GraphQL introspection/`/metrics`/`--inspect` in production, API3 response DTOs, API10 third-party response validation |
| `secaudit:fivem-security` | FiveM/CitizenFX resources and game-facing APIs: client-triggerable `RegisterNetEvent` handlers (authorize on `source`), files shipped to players, `setr`/`sets` convars, state bags, NUI callbacks/XSS, `PerformHttpRequest` keys, txAdmin exposure, per-community API key scoping |
| `secaudit:data-access` | SQL injection, ORM operator injection, Drizzle `sql.raw()` / identifier injection, SQLite / Turso / D1 file and tenancy specifics, runtime input validation, mass assignment |
| `secaudit:web-vulns` | XSS, SSRF, file upload + path traversal, IDOR (broken object-level authorization) |
| `secaudit:rich-text-security` | Rich-text editors and HTML sanitizers: TipTap/ProseMirror stored HTML vs JSON and sanitize-on-write, render sinks and server-side `@tiptap/html` on happy-dom, Link `isAllowedUri` and Image `src`, paste handlers, custom nodes, mammoth .docx import, rehype-sanitize schemas and plugin order, DOMPurify / sanitize-html configs and version floors |
| `secaudit:multi-tenant-isolation` | Hub for tenant isolation outside the row: tenant id from membership (never a header, body or subdomain alone), host→tenant routing with no default-tenant fallback, reserved and reused slugs, tenant in every cache key (Redis/KV, `unstable_cache`/`'use cache'`, CDN `private`), jobs and workers that re-authorize, webhook→tenant mapping, server-minted search keys (Meilisearch tenant tokens, Algolia secured keys, Elasticsearch DLS), scoped and audited impersonation |
| `secaudit:cryptography` | Password hashing, secure randomness, weak algorithms/modes, hardcoded keys, JWT alg confusion, API-key/join-code/session-token storage by entropy, encrypted stored secrets (webhook URLs) |
| `secaudit:logging-monitoring` | Error info disclosure, secrets in logs, audit logging, insecure deserialization, command injection |
| `secaudit:python-web-security` | FastAPI/Django: per-route auth gaps, response_model leakage, production settings, TLS verification |
| `secaudit:dynamic-verification` | Optional runtime pass: browser probes (headers, CORS, unauth routes, IDOR, XSS) and read-only container probes confirm or refute findings |


## Continuous monitoring

An audit is point-in-time. `docs/monitoring.md` adds a scheduled check to an app repo that runs
the same OSV → EPSS → CISA KEV → end-of-life pass against its own lockfile and opens an issue
when something is actually being exploited — the prioritisation layer Dependabot lacks.

## Why a security plugin for AI-generated code

AI assistants reliably get a recurring set of security patterns wrong, which leads to real breaches: stolen API keys, drained billing accounts, and fully exposed databases. The core principle running through every skill: **never trust the client.** Every price, user ID, role, subscription status, and rate-limit counter must be validated or enforced server-side.

The content is based on published research, official security advisories, and documented real-world breaches. If you spot gaps, outdated patterns, or mistakes, please open an issue or PR.

## Credits

- Original skill by [Chris Raroque](https://github.com/raroque) and the team at [Aloa](https://aloa.co).
- v2.0 content updates by the [fartiacht](https://github.com/fartiacht) fork.
- Research sources include the Supabase Security Retro 2025, Next.js and React security advisories, the OWASP Top 10 for LLM Applications (2025), the MCP security best-practices guidance, and the USENIX 2025 study on package hallucinations.

## License

MIT, same as the original.
