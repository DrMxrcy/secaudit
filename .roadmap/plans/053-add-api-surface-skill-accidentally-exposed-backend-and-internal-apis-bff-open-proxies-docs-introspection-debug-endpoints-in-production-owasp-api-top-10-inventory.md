---
id: 53
title: Add api-surface skill: accidentally exposed backend and internal APIs, BFF open proxies, docs/introspection/debug endpoints in production, OWASP API Top 10 inventory
type: feature
version: 3.10.0
status: active
created: 2026-10-16
---

# Plan 53: Add api-surface skill: accidentally exposed backend and internal APIs, BFF open proxies, docs/introspection/debug endpoints in production, OWASP API Top 10 inventory
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/api-surface/` for backend and internal APIs reachable by accident: services meant to sit behind a gateway/BFF but bound to 0.0.0.0 or published ports, origin servers reachable directly around Cloudflare/the proxy, internal service-to-service endpoints (worker, bot, admin) trusting network location instead of authenticating, Next.js route handlers / rewrites acting as open proxies to a backend with service credentials (catch-all `[...path]` proxies, path traversal into the backend, SSRF), API keys shipped to the browser so the frontend calls the backend directly, OpenAPI/Swagger UI, GraphQL introspection/playground, `/metrics`, `/debug`, health and framework dev endpoints live in production, forgotten old API versions and preview/staging hosts (OWASP API9 improper inventory), excessive data exposure in responses (API3 BOPLA), unsafe consumption of third-party APIs (API10), and how to enumerate the real surface (route manifests, framework route lists, compose ports, DNS/certificate transparency).
- **Out of scope:** BFLA/admin role checks (in `privilege-escalation`), IDOR (in `web-vulns`), header trust (in `proxy-trust`), CORS headers (in `deployment`) — cross-referenced.

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/api-surface/SKILL.md`
- **Files to modify:** `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator's recon phase uses it to inventory the attack surface.

## ✅ Acceptance
- **Passes when:** the skill fires on a multi-service repo and gives a concrete check + fix for every listed exposure, mapped to OWASP API Security Top 10 2023 ids exactly as owasp.org states.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default or advisory is asserted that the vendor docs or OSV do not confirm; or it duplicates a sibling skill instead of cross-referencing.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Research primary sources and write the skill -> target: `skills/api-surface/SKILL.md`
  > evidence: verifier PARTIAL→fixed: BFF path guard SSRF (//evil.com) replaced by allowlist + origin assert, node test 16 rejected/1 accepted; HMAC signs path+query, body cap; compose egress fixed; OWASP API9 quote re-verified on 0x11-t10; 621 lines, 48 sources 200 (2026-10-16) (2026-10-16)
- [ ] Step 2: Register the skill: audit tier + OWASP map, README, plugin.json/marketplace.json, sibling cross-refs -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
