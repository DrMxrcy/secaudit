---
id: 32
title: Add Clerk coverage to auth
type: feature
version: 3.7.0
status: done
created: 2026-08-25
---

# Plan 32: Add Clerk coverage to auth
> Type: feature · Target: v3.7.0

## 🎯 Target Scope & Boundaries

Add Clerk coverage to the **existing** `auth` skill rather than a new file. Clerk's failure modes
are mostly *where the check goes*, which is what `auth` already teaches — a separate skill would
have split one lesson across two files.

Sharpest item: **`unsafeMetadata` is writable by the client by design**, so any role, plan or
entitlement stored there is attacker-controlled. `publicMetadata` is server-writable but still a
claim to verify, not a permission.

**Out of scope:** a `clerk-security` skill; middleware/Server Action fundamentals already in
`auth`.

## 🏗️ Architectural Blueprint

- **Modified:** `skills/auth/SKILL.md` only — one `## Clerk` section (290 lines, 9 subsections),
  taking the file from 216 to 518 lines, with the description widened so it fires on
  `@clerk/nextjs` / `clerkMiddleware` / `ClerkProvider`.
- Covers: `auth()` checked only in a layout; `clerkMiddleware` matchers mistaken for
  authorization; identity taken from the request; the metadata trap; JWT template claims;
  **Clerk + Convex** (`ctx.auth.getUserIdentity()`, never a client-passed `userId`); Svix webhook
  verification over the raw body; publishable vs secret key; organization roles.
- Every pre-existing line preserved — the only deletion was the description rewrite.

## ✅ Acceptance

- **Passes when:** the section is Clerk-specific and cross-references `auth`'s existing
  middleware material rather than restating it.
- **Fails if:** a CVE is added — the file's only CVE references must remain the pre-existing ones.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write the Clerk section and widen the description -> target: `skills/auth/SKILL.md`
- [x] Step 2: Verify no new CVE IDs (`git diff` confirmed only CVE-2025-29927 referenced by name)
- [x] Step 3: Verify all 13 clerk.com URLs 200 without redirect; five candidate URLs were
  rejected during research (404/308) and not used
- [x] Step 4: Verify freshness green and pre-existing content intact
