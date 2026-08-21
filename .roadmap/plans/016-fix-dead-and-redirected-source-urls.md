---
id: 16
title: Fix dead and redirected source URLs
type: bug
version: 3.4.0
status: done
created: 2026-08-21
---

# 🐛 Plan 16: Fix dead and redirected source URLs

> Type: bug · Target: v3.4.0

## 🔍 Symptom & Reproduction

- **Observed:** One cited source is a hard 404, and three others answer only through a redirect.
  Every claim in these skills is supposed to be backed by a reachable primary source, so a dead
  citation silently removes the evidence for a check.
- **Expected:** Every URL resolves directly, with no redirect hop and no 404.
- **Repro steps:** extract URLs from `SOURCES.md` and `skills/**/SKILL.md`, then
  `curl -s -o /dev/null -w '%{http_code}' <url>` (no `-L`, so a redirect shows as 30x).

Verified 2026-08-21:

| Cited in | URL | Status | Replacement |
|---|---|---|---|
| `SOURCES.md`, `payments` | `docs.stripe.com/payments/checkout/price-options` | **404** | `docs.stripe.com/products-prices/how-products-and-prices-work` (200) |
| `SOURCES.md` ×2, `database`, `secrets` | `supabase.com/docs/guides/api/api-keys` | 308 | `supabase.com/docs/guides/getting-started/api-keys` (200) |
| `SOURCES.md`, `data-access` | `prisma.io/docs/orm/prisma-client/queries/raw-database-access/raw-queries` | 308 | `prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries` (200) |
| `SOURCES.md`, `convex-security` | `docs.convex.dev/file-storage` | 301 | `docs.convex.dev/file-storage/overview` |

**Known false positives — do not "fix" these:** `w3.org/TR/webauthn-2/` returns 403 to a browser
User-Agent but 200 with none (it is alive and still the Recommendation), and `api.osv.dev/v1/query`
returns 405 on GET because it is POST-only, exactly as the reference documents.

## 🩺 Root Cause

- **Culprit:** `SOURCES.md` and the `## Sources` blocks of `payments`, `database`, `secrets`,
  `data-access`, and `convex-security`.
- **Why:** Vendor documentation sites reorganize their information architecture; Stripe removed
  the price-options page outright rather than redirecting it. `SOURCES.md` carries a "Last
  verified" date but nothing re-checks the links, so rot is invisible until someone clicks.

## ✅ Acceptance

- **Passes when:** every URL in `SOURCES.md` and in every skill's `## Sources` block returns 200
  **without** following a redirect, except the two documented false positives above.
- **Passes when:** the `Last verified` date in `SOURCES.md` reflects this check.
- **Fails if:** a replacement URL points at a page that does not actually support the claim it is
  cited for — each replacement must be read, not just status-checked.

## 🛠️ Checklist

- [x] Step 1: Replace the dead Stripe price-options URL in `SOURCES.md` and
  `skills/payments/SKILL.md`, confirming the new page actually documents server-side Price IDs
  -> target: `SOURCES.md`, `skills/payments/SKILL.md`
- [x] Step 2: Update the three redirecting URLs (Supabase api-keys, Prisma raw-queries, Convex
  file-storage) to their final destinations everywhere they appear -> target: `SOURCES.md`,
  `skills/database/SKILL.md`, `skills/secrets/SKILL.md`, `skills/data-access/SKILL.md`,
  `skills/convex-security/SKILL.md`
- [x] Step 3: Sweep every remaining URL across `SOURCES.md` and all skills for non-200 responses
  and fix anything else that surfaces -> target: all files
- [x] Step 4: Refresh the `Last verified` date in `SOURCES.md` -> target: `SOURCES.md`
- [x] Step 5: Verify — full link sweep returns 200 for every URL bar the two documented false
  positives -> target: manual verification
