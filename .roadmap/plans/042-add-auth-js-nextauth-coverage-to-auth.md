---
id: 42
title: Add Auth.js/NextAuth coverage to auth
type: feature
version: 3.9.0
status: planned
created: 2026-09-15
---

# Plan 42: Add Auth.js/NextAuth coverage to auth
> Type: feature · Target: v3.9.0

## 🎯 Target Scope & Boundaries
- **Core objective:** add an "Auth.js / NextAuth" section to `skills/auth/SKILL.md` (parallel to the Clerk section): the July 2026 advisory set and its fixed versions (`@auth/core` 0.41.3, `next-auth` 4.24.15, 5.0.0-beta.32) incl. CVE-2026-73419 state/nonce/PKCE cookies not bound to a provider -> account-linking takeover; `allowDangerousEmailAccountLinking`; `trustHost` / `AUTH_TRUST_HOST` and `AUTH_URL`; `AUTH_SECRET` strength and rotation; `session.strategy: "jwt"` claims trusted as roles; `callbacks.jwt`/`session` leaking provider tokens to the client; `auth()` in middleware not being authorization (ties to the existing middleware section); Credentials provider footguns (no rate limit, plaintext compare); database adapter tables exposed via Supabase/Prisma without tenant scoping.
- **Out of scope:** generic OAuth mechanics (plan 41, cross-ref).

## 🏗️ Architectural Blueprint
- **Files to modify:** `skills/auth/SKILL.md`, `skills/audit/SKILL.md` (dispatch line under item 6), `skills/framework-versions/SKILL.md` (cross-ref only; floors live in plan 37), `README.md`, `.claude-plugin/plugin.json`, `SOURCES.md`.

## ✅ Acceptance
- **Passes when:** the section fires when `next-auth` or `@auth/*` is in package.json and covers the advisory set, account linking, trustHost, secret, JWT-claim roles, token leakage in callbacks, and Credentials provider, with fixed versions matching OSV exactly.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** a version, advisory ID or provider capability is asserted that OSV or the provider's docs do not confirm; or the freshness check reports drift.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Write the new section(s), verifying every advisory ID and fixed version against OSV / live docs -> target: `skills/auth/SKILL.md`
- [ ] Step 2: Update description/keywords, cross-references, sources, and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`, `README.md`, `.claude-plugin/plugin.json`
