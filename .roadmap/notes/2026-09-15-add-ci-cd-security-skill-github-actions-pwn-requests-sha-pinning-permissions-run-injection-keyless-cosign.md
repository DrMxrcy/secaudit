# Add ci-cd-security skill: GitHub Actions pwn-requests, SHA pinning, permissions, run: injection, keyless cosign

# Coverage gap research — 2026-09-15

Source: surveying two recent self-hosted projects (an OIDC/forward-auth service behind Traefik/Caddy/nginx, and a Kubernetes platform with a Next.js control plane, Go CLI, Helm charts, cosign-signed images) against the 24 shipped skills, then checking each candidate gap against 2026 advisories. Projects are deliberately not named; they are idea sources, not audit targets.

Grep of `skills/` for each topic (zero hits unless noted):

| Topic | Hits today | 2026 evidence that vibe apps hit this |
|---|---|---|
| GitHub Actions / CI workflow security | none | AsyncAPI compromise Jul 2026 via `pull_request_target` + PR-head checkout; prt-scan campaign stole AWS/Cloudflare/Netlify secrets from 50+ repos; hackerbot-claw AI campaign got RCE in >50% of targeted repos; TanStack npm breach May 2026 via Actions; 38% of orgs have injectable/dangerous-trigger workflows |
| Auth.js / NextAuth (most-used Next.js auth) | none (Better Auth, Clerk covered) | Jul 2026 Auth.js advisory set: CVE-2026-73419 state/nonce/PKCE cookies not bound to provider -> account linking takeover; malformed Bearer, email normalization, existence-based fail-open. Fixed @auth/core 0.41.3, next-auth 4.24.15, 5.0.0-beta.32 |
| Reverse-proxy / forward-auth header trust | X-Forwarded-Host in better-auth only, X-Forwarded-For in rate-limiting only | Traefik CVE-2026-35051 (spoofed X-Forwarded-Prefix bypasses ForwardAuth, fixed 2.11.43/3.6.14) and CVE-2026-39858 (underscore alias X_Forwarded_Proto not stripped). Express `trust proxy`, Koa `app.proxy`, Host-header trust, identity-header injection (Remote-User) on forward-auth, Cloudflare Access `Cf-Access-Jwt-Assertion` must be verified not trusted |
| Hono / Cloudflare Workers (D1, KV, R2 bindings, wrangler secrets) | Hono once, in revenuecat | Hono CVE-2026-24473 serve-static env-key disclosure (fixed 4.11.7); XSS via ErrorBoundary, IP-restriction IPv4 bypass in <=4.11.6; CVE-2026-84363 |
| Drizzle ORM / SQLite / Turso / D1 | none | Drizzle CVE-2026-39356 identifier injection via sql.identifier()/sql.as() (fixed 0.45.2 / 1.0.0-beta.20) plus the sql.raw footgun; SQLite file perms, WAL/backup leakage, no RLS so all tenancy is app-level |
| OAuth client + provider flows ("Sign in with X", Lucia/Arctic, oidc-provider) | redirect_uri only in web-vulns | state/nonce/PKCE binding, redirect_uri exact-match, account linking on unverified email, provider token encryption at rest (AES-GCM + AAD + HKDF purpose keys), refresh-token family rotation, JWKS rotation |
| Inbound webhook verification beyond Stripe (Discord Ed25519, Slack signing secret + timestamp, GitHub HMAC, Svix, Telegram secret_token) | Stripe/RevenueCat only | Discord bot token leaks remain top incident class (Bheem breach); CVE-2025-26604 bot-framework token extraction; role-name vs role-ID gating |
| Kubernetes / Helm (RBAC wildcards, securityContext, hostPath, secrets in values.yaml, NetworkPolicy, admission) | docker-security mentions k8s in passing | Homelab k3s crowd; AI-generated charts default to privileged/root and `*` verbs |
| CLI credential storage (config 0600, tokens via stdin/env not argv, update verification) | none | small; fold into secrets |

Improvements to existing skills surfaced by the same survey:
- framework-versions: add clean floors for Hono, Auth.js/@auth/core, Drizzle, Traefik (self-hosted), Koa/Fastify/Elysia, TanStack Start. Add the "shared image pipeline" pattern: Next.js and Astro shipped AVIF RCEs the same day (2026-09-08); when one framework's image optimizer gets a CVE, check siblings.
- auth: `NEXT_SERVER_ACTIONS_ENCRYPTION_KEY` for multi-replica deploys; cookie prefixes `__Host-`/`__Secure-`; `Sec-Fetch-Site` as a CSRF primitive alongside tokens.
- cryptography: token-vault pattern for third-party OAuth tokens (AES-256-GCM, per-row AAD, HKDF-separated purpose keys, versioned KEK) as a positive reference.
- rate-limiting: per-IP limits are bypassable when `trust proxy` is unset or set to `true` behind a CDN; tie to the proxy-trust skill.
- logging-monitoring: pino `redact` paths are depth-limited (no recursive wildcard); nested payloads leak.
- supply-chain: GitHub Actions is the missing leg (SHA pinning, `permissions:` least privilege, `${{ }}` injection into `run:`, keyless cosign verification, Renovate `pinDigests`/minimumReleaseAge).
- check-freshness.py: fix-claim pairs every CVE on a line with every "fixed X" clause; two CVEs in one bullet produce a false positive (hit today). Pair each clause with the nearest preceding CVE instead.
