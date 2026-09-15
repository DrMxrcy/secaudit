# 🗺️ Roadmap: Secaudit

## 💡 Idea Incubator
- framework-versions: add Hono, Auth.js, Drizzle, Traefik, Koa/Fastify/Elysia, TanStack Start floors and the shared image-pipeline CVE pattern
- Freshness fix-claim check pairs every CVE on a line with every fixed clause; pair with nearest CVE
- Add kubernetes-security skill or docker-security section: Helm values secrets, RBAC wildcards, securityContext, hostPath, NetworkPolicy
- Generalize payments webhook section into webhook-security: Discord Ed25519, Slack, GitHub, Svix, Telegram verification and replay
- Add oauth-oidc-security skill: client flows (Lucia/Arctic, Sign in with X) and provider side (redirect_uri, token vault, JWKS rotation)
- Extend data-access with Drizzle (CVE-2026-39356 identifier injection, sql.raw) and SQLite/Turso/D1 file and tenancy specifics
- Add cloudflare-workers-security skill: Hono (CVE-2026-24473), D1/KV/R2 bindings, wrangler secrets vs [vars]
- Add proxy-trust skill: X-Forwarded-* and Host trust, forward-auth identity-header injection, Traefik CVE-2026-35051/39858, Cloudflare Access JWT verification
- Add Auth.js/NextAuth coverage to auth (CVE-2026-73419 state/nonce/PKCE binding, account linking, AUTH_SECRET, trustHost)
- Add ci-cd-security skill: GitHub Actions pwn-requests, SHA pinning, permissions, run: injection, keyless cosign ([notes](.roadmap/notes/2026-09-15-coverage-gap-research.md))
<!-- Free-form. Drop loose ideas here; scripts never touch this region. -->
<!-- roadmap:auto:start -->
**Current version: v3.9.0**

## 📊 Versions

### [x] v3.0.0 — 100% · 1 item · shipped 2026-06-27 ([history](CHANGELOG.internal.md))

### [x] v3.1.0 — 100% · 1 item · shipped 2026-06-28 ([history](CHANGELOG.internal.md))

### [x] v3.2.0 — 100% · 4 items · shipped 2026-07-17 ([history](CHANGELOG.internal.md))

### [x] v3.3.0 — 100% · 4 items · shipped 2026-07-19 ([history](CHANGELOG.internal.md))

### [x] v3.3.1 — 100% · 1 item · shipped 2026-07-20 ([history](CHANGELOG.internal.md))

### [x] v3.4.0 — 100% · 6 items · shipped 2026-08-21 ([history](CHANGELOG.internal.md))

### [x] v3.5.0 — 100% · 7 items · shipped 2026-08-24 ([history](CHANGELOG.internal.md))

### [x] v3.6.0 — 100% · 4 items · shipped 2026-08-24 ([history](CHANGELOG.internal.md))

### [x] v3.7.0 — 100% · 5 items · shipped 2026-08-25 ([history](CHANGELOG.internal.md))

### [x] v3.8.0 — 100% · 2 items · shipped 2026-08-25 ([history](CHANGELOG.internal.md))
<!-- roadmap:auto:end -->
