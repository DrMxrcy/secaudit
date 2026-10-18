---
id: 60
title: Warn that OSV and npm audit miss vendor-only and unpublished advisories
type: feature
version: 3.12.0
status: planned
created: 2026-10-17
---

# Plan 60: Warn that OSV and npm audit miss vendor-only and unpublished advisories
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** the pack stops treating "OSV / npm audit returned nothing" as clean. Evidence from 2026-10-17: (1) Aikido reported three advisories on `undici@6.29.1` (AIKIDO-2026-54683 Medium, fixed 8.10.2; AIKIDO-2026-10369 / -10385 Low, fixed 7.23.0 / 7.24.1) while `POST api.osv.dev/v1/query` for undici 6.29.1, 7.30.1 and 8.12.2 all returned `[]` and `npm audit --omit=dev` listed nothing for undici; (2) the Next.js 2026-10-14 GHSAs were absent from OSV and the GitHub global DB for 3+ days after the vendor post.
- Guidance to add:
  - supply-chain: a subsection "An empty OSV / npm audit result is not a clean bill" — vendor-only advisory IDs (Aikido `AIKIDO-*`, Snyk `SNYK-JS-*`, Socket) that never reach OSV; disclosure lag between vendor post and GHSA/OSV ingestion; what to do (check vendor security pages/blogs for the frameworks in use; note in the report that the lookup was OSV-only; recommend a second commercial/free scanner in CI; cite `intel.aikido.dev` only if it resolves).
  - Transitive deps pinned by a parent (e.g. undici under discord.js → @discordjs/rest): `npm ls <pkg>` to show every copy; remediation via `overrides` (npm) / `resolutions` (yarn) / `pnpm.overrides`, plus re-test, because the parent may declare an exact or narrow range.
  - framework-versions + audit report wording: when a floor came from a vendor post not yet in OSV, say so.
- **Out of scope:** integrating a commercial API; changing monitor-deps.py.

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/supply-chain/SKILL.md (near "A clean `npm audit` is not evidence…" ~L178 and the live-lookup order ~L233-238), skills/framework-versions/SKILL.md (live-lookup step: vendor post check), skills/audit/SKILL.md (report caveat line), SOURCES.md.

## ✅ Acceptance
- **Passes when:** supply-chain explains vendor-only IDs and disclosure lag with the undici example (no claim beyond the facts above), gives the `npm ls` + overrides remediation with a runnable snippet, and audit's report template carries an "advisory sources consulted" caveat.
- **Passes when:** `python3 scripts/check-freshness.py` is clean.
- **Fails if:** guidance claims Aikido/Snyk data is in OSV, or cites an unverified URL.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Add vendor-only/lagging advisory subsection and transitive-override remediation -> target: skills/supply-chain/SKILL.md
- [ ] Step 2: Add vendor-post check to framework-versions lookup and source caveat to audit report; freshness green -> target: skills/framework-versions/SKILL.md, skills/audit/SKILL.md, SOURCES.md
