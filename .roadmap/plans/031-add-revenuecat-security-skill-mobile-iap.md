---
id: 31
title: Add revenuecat-security skill (mobile IAP)
type: feature
version: 3.7.0
status: done
created: 2026-08-25
---

# Plan 31: Add revenuecat-security skill (mobile IAP)
> Type: feature · Target: v3.7.0

## 🎯 Target Scope & Boundaries

New `skills/revenuecat-security/` — `payments` assumes a Stripe webhook verified server-side.
Mobile in-app purchase fails differently and had zero coverage.

Highest-impact section is the **Convex interaction**: entitlement written to a Convex table, where
no RLS means a public mutation setting `isPro` is a one-call upgrade. Same warning given for
Supabase and Firebase.

**Out of scope:** Stripe material in `payments`.

## 🏗️ Architectural Blueprint

- **New:** `skills/revenuecat-security/SKILL.md` (515 lines, 9 sections + checklist).
- **Modified:** `audit` Tier 1 as a branch off Payments; OWASP A01:2025 row; keywords; `SOURCES.md`.
- **Research corrected the original brief twice, both verified against live docs:**
  1. RevenueCat now supports **optional HMAC signing** (`X-RevenueCat-Webhook-Signature`), not
     only a bearer header — so the real footgun is that **both** mechanisms are opt-in and the
     default is an unauthenticated public endpoint.
  2. **There is no `REFUND` event type.** Refunds arrive as `CANCELLATION` with
     `cancel_reason=CUSTOMER_SUPPORT`, so a handler waiting for `REFUND` leaves refunded users
     premium indefinitely.
- Also documents that `GET /v1/subscribers/{id}` is *get-or-create*, so a 200 is not
  authorization, and that the Test Store key grants real entitlements.
- Deliberately tells auditors **not** to flag the public SDK key — a known false positive.

## ✅ Acceptance

- **Passes when:** the skill fires on a RevenueCat dependency and the entitlement-write path is
  covered for Convex, Supabase and Firebase.
- **Fails if:** any RevenueCat event name or field is asserted without doc verification.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write the skill, verifying event names and the webhook auth mechanism against live
  docs -> target: `skills/revenuecat-security/SKILL.md`
- [x] Step 2: Register in the audit tiers and OWASP map
- [x] Step 3: Add sources and plugin keywords
- [x] Step 4: Verify — first draft failed the freshness gate on API URLs extracted from code
  fences; fixed by using a base-URL constant, re-verified green
- [x] Step 5: Verify — no CVE IDs, no version targets, OWASP 2025 numbering only
