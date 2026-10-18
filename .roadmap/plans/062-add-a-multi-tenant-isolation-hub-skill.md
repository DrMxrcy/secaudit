---
id: 62
title: Add a multi-tenant-isolation hub skill
type: feature
version: 3.12.0
status: done
created: 2026-10-17
---

# Plan 62: Add a multi-tenant-isolation hub skill
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new short hub skill `skills/multi-tenant-isolation/SKILL.md`: cross-cutting tenant isolation. New material only; everything already covered elsewhere is a pointer, not a copy.
- **New sections:**
  1. Tenant resolution: tenant id must come from the session's membership, never from body/query/header (`x-tenant-id`, `x-org-id`) or subdomain alone; header/subdomain/path hints are validated against membership. Greps: `x-tenant|x-org|organizationId.*(body|params|searchParams)`.
  2. Host → tenant routing & custom domains: unknown host must 404, not fall back to a default tenant; custom-domain claims verified by DNS TXT before activation; dangling CNAME / deleted-tenant subdomain takeover; Host header trust behind proxies (link proxy-trust).
  3. Cache keys: Redis/KV keys, `unstable_cache`/`use cache` keys, fetch cache, CDN `Vary`/`Cache-Control: private` — key must include tenant (and user when per-user). Greps for `redis.(get|set)(` template keys without tenant.
  4. Jobs/queues/cron: BullMQ / pg-boss / Inngest / cron jobs losing tenant context or trusting `tenantId` from a job payload that a user can influence; re-resolve and re-authorize inside the worker; per-tenant set_config in the job's transaction.
  5. Inbound webhook → tenant mapping: map via per-tenant endpoint or per-tenant secret, not payload metadata (link webhook-security / payments).
  6. Search & vector indexes: Meilisearch tenant tokens, Algolia secured API keys, Elasticsearch filtered aliases, pgvector filter (link prisma §9) — server-enforced tenant filter, never client-supplied filter.
  7. Impersonation / support access: scoped, time-boxed, audited, visible banner, cannot impersonate higher-privileged users or other platform staff, cannot act on billing/security settings.
  8. Pointer table: postgres-security §1-3 (RLS FORCE, non-owner role, per-transaction GUC), prisma-security §1-4, realtime-security (room fan-out), object-storage-security (tenant key prefix), better-auth-security (activeOrganizationId), web-vulns §IDOR, privilege-escalation.
  9. Checklist + Sources (OWASP Multi-Tenant cheat sheet if it resolves, WSTG-CONF-10 subdomain takeover, vendor docs for each search engine).
- **Out of scope:** rewriting existing RLS content.

## 🏗️ Architectural Blueprint
- **Files to create:** skills/multi-tenant-isolation/SKILL.md
- **Files to modify:** skills/web-vulns/SKILL.md (one pointer in IDOR section), skills/audit/SKILL.md (dispatch trigger: tenant/org/community/workspace columns or orgId in schema; OWASP A01 map), README.md, .claude-plugin/plugin.json, SOURCES.md.

## ✅ Acceptance
- **Passes when:** sections 1-7 each carry a concrete grep/config check and a BAD/GOOD snippet; the pointer table cites real section headings that exist (verify by grep); audit dispatches it; README/plugin.json list it; freshness clean.
- **Fails if:** RLS/realtime/object-storage content is duplicated rather than referenced, or any cited heading does not exist.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Write multi-tenant-isolation SKILL.md sections 1-9 -> target: skills/multi-tenant-isolation/SKILL.md
  > evidence: freshness --only links/fixclaims/cves: All current (manifest drift expected until step 2); 33/33 pointers resolve; 18 greps BSD+GNU; host resolver failed closed on all attack hosts; spec MET; quality PARTIAL x2 -> fixed (fetch cache, Stripe guard, worker lease/retry, ES wording); parent reviewed final worker snippet and fixed lease-duration overclaim (2026-10-18)
- [x] Step 2: Register: audit dispatch + OWASP map, README, plugin.json, web-vulns pointer, SOURCES; freshness green -> target: skills/audit/SKILL.md, README.md, .claude-plugin/plugin.json, skills/web-vulns/SKILL.md, SOURCES.md
  > evidence: full check-freshness.py: All current; manifests parse and match; README count 38 matches skills dir; parent self-review of mechanical registration diff (2026-10-18)
