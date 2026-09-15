---
id: 41
title: Add oauth-oidc-security skill: client flows (Lucia/Arctic, Sign in with X) and provider side
type: feature
version: 3.9.0
status: planned
created: 2026-09-15
---

# Plan 41: Add oauth-oidc-security skill: client flows (Lucia/Arctic, Sign in with X) and provider side
> Type: feature · Target: v3.9.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/oauth-oidc-security/` covering both sides of OAuth 2.0 / OIDC. Client side ("Sign in with X" via Arctic, Lucia patterns, openid-client, hand-rolled fetches): `state` and `nonce` generation, storage and per-flow binding; PKCE S256 on every flow (RFC 9700); exact-match `redirect_uri`; account linking only on provider-verified email; provider access/refresh tokens encrypted at rest with per-row AAD and purpose-separated keys; refresh-token rotation and reuse detection; ID token validation (`iss`, `aud`, `exp`, `alg`, JWKS by `kid`). Provider side (node-oidc-provider, hand-rolled IdPs): client secret hashing, PKCE required, code single-use with family revocation on reuse, pairwise subjects, JWKS rotation overlap, consent and logout (back-channel) handling.
- **Out of scope:** Auth.js specifics (plan 42), Clerk/Better Auth (already covered), mobile PKCE (react-native-security).

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/oauth-oidc-security/SKILL.md`.
- **Files to modify:** `skills/audit/SKILL.md` (Tier 1 under auth), `skills/auth/SKILL.md` and `skills/cryptography/SKILL.md` (cross-refs), `README.md`, `.claude-plugin/plugin.json`, `SOURCES.md`.

## ✅ Acceptance
- **Passes when:** the skill fires on `arctic`, `openid-client`, `oidc-provider`, `lucia`, or a hand-written `/callback` route exchanging `code`, and covers state/nonce/PKCE binding, redirect_uri, account linking, token storage, refresh rotation, ID-token validation, and the provider-side list above, citing RFC 9700 / OIDC Core sections.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** a version, advisory ID or provider capability is asserted that OSV or the provider's docs do not confirm; or the freshness check reports drift.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Write the skill, verifying every advisory ID, fixed version and provider claim against OSV / live docs -> target: `skills/oauth-oidc-security/SKILL.md`
- [ ] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json description/keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
