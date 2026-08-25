---
id: 33
title: Add object-storage-security skill (R2, S3, Supabase Storage)
type: feature
version: 3.7.0
status: done
created: 2026-08-25
---

# Plan 33: Add object-storage-security skill (R2, S3, Supabase Storage)
> Type: feature · Target: v3.7.0

## 🎯 Target Scope & Boundaries

New `skills/object-storage-security/` — R2, S3 and S3-compatible stores are where user uploads
live and had no dedicated coverage. `web-vulns` covered upload/traversal generically and
`database` covered Supabase Storage bucket policy; neither covered presigned URLs.

Organising idea: **a presigned URL is a bearer credential in a string**, and **knowing an object
key is not authorization** — unguessable is a delay, not a control.

**Out of scope:** duplicating `web-vulns` upload validation or `database`'s Supabase material.

## 🏗️ Architectural Blueprint

- **New:** `skills/object-storage-security/SKILL.md` (612 lines, 8 sections).
- **Modified:** `audit` Tier 1 item 9; OWASP A01:2025 row; keywords; `SOURCES.md`.
- Facts verified against live provider docs rather than assumed, and one changed the structure:
  **R2 does not support presigned POST** (GET/HEAD/PUT/DELETE only), so the S3
  `content-length-range` policy trick does not transfer — §4 gives R2 a separate
  `HeadObject`-then-delete path instead.
- Also covers the stored-XSS angle: an uploaded `.svg` or `.html` served inline from your origin
  executes in your origin.
- Two deliberate omissions where docs could not confirm: R2 object versioning, and whether
  `ContentLength` binds into a presigned PUT signature (only `ContentType` is confirmed).

## ✅ Acceptance

- **Passes when:** the skill fires on an R2/S3 upload path and covers presign lifetime, key
  minting, public buckets, content validation, CORS, credential scoping, read authorization, and
  lifecycle.
- **Fails if:** a provider capability is asserted that the docs do not confirm.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write the skill, verifying provider capabilities against live docs -> target:
  `skills/object-storage-security/SKILL.md`
- [x] Step 2: Register in the audit tiers and OWASP map
- [x] Step 3: Add sources and plugin keywords
- [x] Step 4: Verify — negative-tested the freshness gate by injecting a known-302 URL and
  confirming it was reported, then removed
- [x] Step 5: Verify — no CVE IDs, no version targets, OWASP 2025 numbering only
