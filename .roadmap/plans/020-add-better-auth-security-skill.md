---
id: 20
title: Add better-auth-security skill
type: feature
version: 3.5.0
status: done
created: 2026-08-24
---

# Plan 20: Add better-auth-security skill
> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

New `skills/better-auth-security/` — `grep -ril "better-auth"` returned nothing across the repo,
while `auth` covered only framework-generic material.

Twelve library-specific gaps, each a Better Auth config flag or API misuse the generic skill
cannot express. The sharpest: `getSessionCookie()` tests for cookie *presence* only — Better
Auth's own docs put `// THIS IS NOT SECURE!` in that snippet, and assistants copy it without the
comment.

**Out of scope:** middleware-is-not-a-boundary, Server Actions, cookie flags, CSRF — all already
in `auth`.

## 🏗️ Architectural Blueprint

- **New:** `skills/better-auth-security/SKILL.md` (520 lines, 12 sections + checklist).
- **Modified:** `auth` gains the Next.js 16 `middleware.ts` → `proxy.ts` rename note; `audit`
  dispatches it conditionally when `better-auth` is in `package.json`.
- Highest-value non-obvious items: `cookieCache` delays revocation/bans/role changes;
  `trustedProxyHeaders` defaults to **true**; `checkRolePermission` is client-only and
  synchronous; `accountLinking.trustedProviders` skips the email-verification guard.

## ✅ Acceptance

- **Passes when:** every section is Better-Auth-specific and cross-references rather than
  duplicates `auth` and `privilege-escalation`.
- **Fails if:** any cited doc URL redirects — the freshness check fails the build.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write the skill -> target: `skills/better-auth-security/SKILL.md`
- [x] Step 2: Add the proxy-rename note to `auth` -> target: `skills/auth/SKILL.md`
- [x] Step 3: Register conditionally in the audit tiers and OWASP map
- [x] Step 4: Add sources and plugin keywords
- [x] Step 5: Verify — all `www.better-auth.com` URLs 307'd to the apex domain and one path 404'd;
  fixed and re-verified 200 without redirect
