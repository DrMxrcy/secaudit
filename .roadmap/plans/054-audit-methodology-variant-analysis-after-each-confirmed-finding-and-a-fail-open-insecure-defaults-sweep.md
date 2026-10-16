---
id: 54
title: Audit methodology: variant analysis after each confirmed finding and a fail-open insecure-defaults sweep
type: feature
version: 3.10.0
status: active
created: 2026-10-16
---

# Plan 54: Audit methodology: variant analysis after each confirmed finding and a fail-open insecure-defaults sweep
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** two methodology additions to the `audit` orchestrator. (a) Variant analysis: after a finding is verified, characterise its root cause (the missing guard, the unsafe API, the shared helper) and sweep the codebase for siblings with grep/ripgrep (and CodeQL when available) before reporting, so one confirmed IDOR in a route handler triggers a check of every handler with the same shape; report variants grouped under the root cause. (b) Fail-open / insecure-defaults sweep: for every security setting read from env/config (secrets, allowed origins, auth toggles, rate-limit stores, verification flags, TLS options), check what the code does when it is missing, empty or malformed — deny or crash at startup, never fall back to permissive behaviour (`origin: process.env.X || '*'`, `if (secret) verify()`, `NODE_ENV !== 'production'` debug bypasses, feature flags defaulting to on).
- **Out of scope:** new domain skills; tool installation.

## 🏗️ Architectural Blueprint
- **Files to create:** none
- **Files to modify:** `skills/audit/SKILL.md`, `skills/audit/references/methodology.md`, `SOURCES.md`
- **Schema/interface changes:** none
- **Downstream impact:** every whole-app audit.

## ✅ Acceptance
- **Passes when:** the audit process names a variant-analysis step between verification and reporting, and a fail-open sweep with concrete grep heuristics and BAD/GOOD examples.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** it contradicts the existing evidence/verification rules in the audit skill.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Write the variant-analysis and fail-open sections and wire them into the audit phases -> target: `skills/audit/SKILL.md`, `skills/audit/references/methodology.md`
  > evidence: verifier PARTIAL→fixed: diff-scope exception, worker table row, no-reseed rule, Hono typing, tightened heuristics; methodology 538→318 lines; 15 rg heuristics re-run on BAD/GOOD fixtures (2026-10-16) (2026-10-16)
- [ ] Step 2: Cite sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
