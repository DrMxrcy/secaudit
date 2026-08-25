---
id: 19
title: Add prisma-security skill (Prisma, Postgres RLS, pgvector)
type: feature
version: 3.5.0
status: done
created: 2026-08-24
---

# Plan 19: Add prisma-security skill (Prisma, Postgres RLS, pgvector)
> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

New `skills/prisma-security/` — the plugin covered Supabase and Convex data layers but had only
three shallow Prisma lines inside `data-access`, and nothing at all on pgvector.

The organising fact: **Prisma has no row-level security**, so every query must carry the tenant
predicate itself, and Postgres RLS underneath it is silently inert when the app connects as the
table owner — which it almost always does, because that is the role that ran the migrations.

**Out of scope:** the `$queryRawUnsafe` basics already in `data-access` (cross-referenced, not
repeated).

## 🏗️ Architectural Blueprint

- **New:** `skills/prisma-security/SKILL.md` (458 lines, 10 numbered sections + checklist).
- **Modified:** `data-access` gains `Prisma.raw()` and a pointer; `audit` gains a Tier-1 entry.
- **Verified against the PostgreSQL manual before shipping** — the research agent flagged the RLS
  owner-bypass and `set_config` semantics as asserted from memory, so both were confirmed:
  "Table owners normally bypass row security", `FORCE ROW LEVEL SECURITY`, and `is_local=true`
  scoping to the transaction.
- **Bonus finding the research missed:** referential-integrity checks always bypass RLS, so a
  unique or FK violation is an existence oracle for another tenant's rows.

## ✅ Acceptance

- **Passes when:** the skill fires on a `prisma/schema.prisma` and covers tenant scoping, the
  extension/`include` blind spot, `Prisma.raw`, over-fetching, TLS, migrations, and pgvector.
- **Passes when:** every Postgres claim traces to the PostgreSQL manual, not to model memory.
- **Fails if:** it restates `data-access`'s existing raw-SQL material.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Verify the Postgres RLS owner-bypass and `set_config` claims against
  postgresql.org -> target: manual verification
- [x] Step 2: Write the skill -> target: `skills/prisma-security/SKILL.md`
- [x] Step 3: Add `Prisma.raw()` + cross-reference to `data-access` -> target:
  `skills/data-access/SKILL.md`
- [x] Step 4: Register in the audit tiers, OWASP map, plugin keywords and `SOURCES.md`
- [x] Step 5: Verify — frontmatter valid, cross-references resolve, freshness check green
