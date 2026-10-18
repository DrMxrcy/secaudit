---
id: 65
title: Cover Drizzle write-path risks: mass assignment, unscoped writes, races
type: feature
version: 3.12.0
status: planned
created: 2026-10-17
---

# Plan 65: Cover Drizzle write-path risks: mass assignment, unscoped writes, races
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** close Drizzle write-path gaps (research 2026-10-17; drizzle-orm OSV: only GHSA-gpj5-g38j-94v9 / CVE-2026-39356, fixed 0.45.2 — floor already correct at framework-versions ~L307-311; drizzle-kit/drizzle-zod/postgres: no advisories).
- **data-access additions:**
  1. Mass assignment, Drizzle shape: `createInsertSchema(table)` / `createUpdateSchema(table)` from drizzle-zod (or `drizzle-orm/zod` in v1) without `.pick()`/`.omit()` admits every writable column (role, isAdmin, orgId, credits); request bodies spread into `.values({...body})` / `.set({...input})`. Greps: `create(Insert|Update)Schema\(\w+\)\s*[;),]` with no pick/omit nearby; `\.(values|set)\(\{?\s*\.\.\.(req\.body|body|input|data)`. Note honra-io/drizzle-best-practices teaches the unpicked pattern (types-validators.md) — name it as an anti-pattern.
  2. Unscoped writes: `db.update(t).set(...)` / `db.delete(t)` with no `.where()` hits every row; `where` without the tenant predicate (extend the existing select-only tenant example to update/delete, ORM-wide not SQLite-only).
  3. Races / check-then-act: read balance/quantity then `update` without `.for('update')` inside the same `tx`, or without a conditional `where(and(eq(id), gte(balance, n)))` + affected-row check; using outer `db` instead of `tx` inside `db.transaction(async (tx) => …)`. honra query-error-handling.md shows the racy inventory decrement — cite as anti-pattern.
  4. `sql.raw` triage by provenance: a hit is Critical only when request-derived; compile-time constants (e.g. building `CHECK (col in ('a','b'))` from a domain enum) are Low/informational — but a helper that wraps `'${v}'` without escaping is a latent footgun; GOOD: `sql.join(values.map(v => sql`${v}`), sql`, `)` or escape `'`→`''` and restrict to a literal-union type. Explain that SAST tools flag this as Critical/"easily exploitable"; the auditor must trace values.
- **api-surface §8** (DTO): relational queries `db.query.x.findMany({ with: { user: true } })` return full nested rows (passwordHash, tokens) — use `columns: { … }` allowlists at every level.
- **logging-monitoring §2:** `drizzle(client, { logger: true })` / `DefaultLogger` / custom `logQuery(query, params)` writes bound params (passwords, tokens, PII) to logs.
- **postgres-security §2:** a runtime pool connecting as the table owner / BYPASSRLS role (often the migration URL reused for "system" paths) — every query through it skips RLS; flag imports of the migration/owner URL outside migration code; require a separate least-privileged system role or explicit audited bypass.
- **Out of scope:** drizzle-kit push / RLS policy content (already covered postgres-security L73-139).

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/data-access/SKILL.md (Mass Assignment ~L299-311, tenant predicate ~L189-197, new Transactions & races subsection, sql.raw triage near ~L105-127), skills/api-surface/SKILL.md (§8), skills/logging-monitoring/SKILL.md (§2), skills/postgres-security/SKILL.md (§2 ~L141-166), SOURCES.md (orm.drizzle.team/docs/zod, /docs/rqb, /docs/goodies#logging, /docs/transactions, /docs/select#row-locking — verify each URL).

## ✅ Acceptance
- **Passes when:** each of the 7 checks has a grep heuristic and BAD/GOOD Drizzle snippet that is valid for drizzle-orm 0.45 API; cited docs URLs resolve; freshness clean.
- **Fails if:** snippets use non-existent APIs (verify `.for('update')`, `sql.join`, `createInsertSchema(...).pick` against installed docs/source), or existing Prisma content is removed.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: data-access: Drizzle mass assignment, unscoped writes, races, sql.raw provenance triage -> target: skills/data-access/SKILL.md
- [ ] Step 2: api-surface relational columns, logging-monitoring logger params, postgres-security owner-role runtime pool -> target: skills/api-surface/SKILL.md, skills/logging-monitoring/SKILL.md, skills/postgres-security/SKILL.md
- [ ] Step 3: Cite sources; freshness green -> target: SOURCES.md
