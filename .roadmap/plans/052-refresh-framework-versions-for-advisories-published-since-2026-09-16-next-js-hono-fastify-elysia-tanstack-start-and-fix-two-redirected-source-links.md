---
id: 52
title: Refresh framework-versions for advisories published since 2026-09-16 (Next.js, Hono, Fastify, Elysia, TanStack Start) and fix two redirected source links
type: bug
version: 3.10.0
status: planned
created: 2026-10-16
---

# Plan 52: Refresh framework-versions for advisories published since 2026-09-16 (Next.js, Hono, Fastify, Elysia, TanStack Start) and fix two redirected source links
> Type: bug · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** `python3 scripts/check-freshness.py` reports drift: new advisories against the cited clean floors next@15.5.24 (CVE-2026-94484, CVE-2026-94543), next@16.3.3 (CVE-2026-94483/94484/94485/94486/94543 and more), hono@4.13.5 (CVE-2026-93981), fastify@5.12.1 (CVE-2026-76169/84428/84469/84504/92081), elysia@1.4.27 (CVE-2026-56669), @tanstack/react-start@1.168.54 (CVE-2026-102989); and two redirected links (docs.stripe.com/webhooks/signature, arcticjs.dev). Verify each advisory on GHSA/OSV, add the entries with exact fixed versions, raise the floors, and fix the links. Also sweep advisories since 2026-09-16 for the packages the new v3.10.0 skills cover (ws, socket.io, engine.io, discord.js, pg, postgres, drizzle-orm, better-auth, next-auth, Node.js 22 security releases, PostgreSQL minor releases) and record any that change advice.
- **Out of scope:** new skills; prose rewrites unrelated to a changed advisory.

## 🏗️ Architectural Blueprint
- **Files to create:** none
- **Files to modify:** `skills/framework-versions/SKILL.md`, `skills/cloudflare-workers-security/SKILL.md` (Hono floor if cited), `skills/payments/SKILL.md`, `skills/oauth-oidc-security/SKILL.md`, `SOURCES.md`
- **Schema/interface changes:** none
- **Downstream impact:** version-floor advice used by every audit.

## ✅ Acceptance
- **Passes when:** every drifted floor is replaced by a version with zero open advisories per OSV, and each new CVE is listed with its GHSA id, affected range and fixed version exactly as GHSA states.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** a fixed version or CVE id is asserted that GHSA/OSV does not confirm.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Verify each drifted advisory on GHSA/OSV and update floors + CVE entries; sweep the extra stack packages -> target: `skills/framework-versions/SKILL.md`
- [ ] Step 2: Replace the two redirected links with their final URLs -> target: `skills/payments/SKILL.md`, `skills/oauth-oidc-security/SKILL.md`, `SOURCES.md`
- [ ] Step 3: `python3 scripts/check-freshness.py` all-current -> target: `SOURCES.md`
