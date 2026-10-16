---
id: 47
title: Add postgres-security skill: Drizzle RLS policies, LISTEN/NOTIFY tenant leaks, advisory locks, poolers, roles and backups
type: feature
version: 3.10.0
status: active
created: 2026-10-16
---

# Plan 47: Add postgres-security skill: Drizzle RLS policies, LISTEN/NOTIFY tenant leaks, advisory locks, poolers, roles and backups
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/postgres-security/` for self-hosted Postgres used through Drizzle (and any ORM): Drizzle RLS declarations (`pgPolicy`, `.enableRLS()`, `pgRole`, `crudPolicy`), policies that exist in schema but are never migrated or are inert; app role design (NOSUPERUSER NOBYPASSRLS, non-owner, FORCE ROW LEVEL SECURITY — cross-ref `prisma-security` sections 2–3 instead of duplicating); setting tenant context in Drizzle transactions with `set_config(..., true)` and pooler transaction mode (PgBouncer) breaking session state, LISTEN and session advisory locks; LISTEN/NOTIFY: no privilege needed to LISTEN, payloads bypass RLS, channel names and payloads built from user input, payload size limit, must re-authorize before fan-out; advisory locks: `pg_advisory_xact_lock` vs session locks, key derivation collisions (hashing ids into bigint), lock-held-across-await deadlocks/DoS; SECURITY DEFINER functions with unsafe `search_path`; PG15+ `public` schema CREATE default and default privileges; network exposure (`listen_addresses`, `pg_hba.conf` `trust`, TLS `sslmode=verify-full`); backups (`pg_dump` runs as an RLS-bypassing role, dumps hold hashed tokens and ciphertext — keep encryption keys out of the dump location, encrypt and restrict backups).
- **Out of scope:** Supabase-specific RLS (stays in `database`); Prisma-specific patterns (stay in `prisma-security`); SQL injection (stays in `data-access`).

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/postgres-security/SKILL.md`
- **Files to modify:** `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator dispatches to it for projects using the covered technology.

## ✅ Acceptance
- **Passes when:** the skill fires on a Drizzle/pg/postgres.js project and gives verified checks for every covered area, with Drizzle RLS API names and Postgres behaviour quoted from the official docs.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default, version, advisory ID or provider capability is asserted that the vendor docs, RFC or OSV do not confirm; or the freshness check reports drift; or content duplicates a sibling skill instead of cross-referencing it.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Research primary sources (vendor docs, RFCs, OSV/GHSA) and write the skill; every API name, header, default and advisory ID verified live -> target: `skills/postgres-security/SKILL.md`
  > evidence: verifier reproduced on PG17.11: NOTIFY reaches role without SELECT, current_setting NULL vs '', drizzle-kit 0.31.11 push --force disables RLS, pg_dump needs BYPASSRLS; all quotes/CVEs/PgBouncer facts confirmed; polish applied, 646 lines, 31 sources 200 (2026-10-16) (2026-10-16)
- [ ] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json/marketplace.json description and keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
