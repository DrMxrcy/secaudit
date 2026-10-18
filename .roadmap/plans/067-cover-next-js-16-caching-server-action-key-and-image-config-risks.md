---
id: 67
title: Cover Next.js 16 caching, Server Action key and image config risks
type: feature
version: 3.12.0
status: planned
created: 2026-10-17
---

# Plan 67: Cover Next.js 16 caching, Server Action key and image config risks
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** Next.js 16-specific checks not covered today (verified 0 hits): 
  1. Per-tenant / per-user data in `"use cache"` / `cacheComponents` / `unstable_cache`: cached function without the tenant/user id in its arguments while reading data scoped by `cookies()`/`headers()`/session outside; `unstable_cache` key array missing the tenant id; `cacheTag` shared across tenants. Generalize from better-auth-security L437-476 (currently Better-Auth-scoped) — link it.
  2. Server Action encryption key: multiple instances/replicas/containers without a shared `NEXT_SERVER_ACTIONS_ENCRYPTION_KEY` (actions fail or keys rotate per build); key committed or `NEXT_PUBLIC_`-prefixed; closed-over values in inline Server Actions are sent to the client encrypted — never close over secrets.
  3. `next.config` images: `images.dangerouslyAllowLocalIP: true`, `dangerouslyAllowSVG: true` (without `contentDispositionType: 'attachment'` + CSP), wildcard `remotePatterns` (`hostname: '**'`) → SSRF / XSS; tie to the image-pipeline CVEs.
  4. JSON-LD injection: `<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(x) }}>` without escaping `<` (`.replace(/</g, '\\u003c')`) → `</script>` breakout.
  5. `serverActions.bodySizeLimit` raised well above default on unauthenticated actions (DoS amplifier, ties to GHSA-p3m5-59mp-jv5r).
  6. `experimental.taint` + `experimental_taintObjectReference` / `experimental_taintUniqueValue`: optional defense for user/token objects reaching Client Components — note it is a runtime check, not build-time.
  7. `rewrites()`/`NextResponse.rewrite()` destinations built from request input → SSRF/open proxy.
- Verify every config key name against current Next.js 16 docs (nextjs.org/docs) before writing; skip any that no longer exists.
- **Out of scope:** version floors (plan 59).

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/auth/SKILL.md (Server Actions section: key, closures, bodySizeLimit), skills/data-access/SKILL.md or skills/multi-tenant-isolation (cache keys → if plan 62 landed, put the Next-specific cache detail in auth/api-surface and point from multi-tenant §3; keep one home), skills/web-vulns/SKILL.md (images config SSRF, JSON-LD XSS, rewrites SSRF), skills/better-auth-security/SKILL.md (pointer to general section), SOURCES.md.

## ✅ Acceptance
- **Passes when:** checks 1-7 each have a grep/config heuristic and fix; every config key verified against nextjs.org docs URLs that resolve; no duplicated cache-key content across skills (one home + pointers); freshness clean.
- **Fails if:** a documented key name is wrong for Next 16.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Server Actions key/closures/bodySizeLimit and cache-key leakage checks -> target: skills/auth/SKILL.md, skills/better-auth-security/SKILL.md, skills/multi-tenant-isolation/SKILL.md
- [ ] Step 2: images config, JSON-LD, rewrites SSRF, taint note; sources; freshness green -> target: skills/web-vulns/SKILL.md, SOURCES.md
