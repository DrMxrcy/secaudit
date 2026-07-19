---
id: 9
title: Recon and coverage-gap phases
type: feature
version: 3.3.0
status: planned
created: 2026-07-19
---

# Plan 9: Recon and coverage-gap phases
> Type: feature · Target: v3.3.0
> Borrowed from 3stoneBrother/code-audit (recon phase + coverage evaluation).

## 🎯 Target Scope & Boundaries
- **Core objective:** Bracket the risk-ranked tiered sweep with two phases:
  1. **Reconnaissance (before the sweep):** map the attack surface first — tech stack and
     frameworks, entry points (routes, Server Actions, API handlers, webhooks, cron, public
     queries/mutations), trust boundaries, authentication/authorization mechanism, data stores, and
     third-party integrations. This makes domain selection and the risk-ranking evidence-based
     (which surfaces actually exist) instead of guessed, and directly supports "high-risk areas
     first, but all areas".
  2. **Coverage-gap self-check (after the sweep):** a completeness-critic pass that asks "what did
     I not cover?" — an entry point never traced, a domain skipped without confirming the tech is
     absent, a data flow left unfollowed — and either covers it or explicitly lists it as a known
     gap so the user sees the audit's boundaries.
- **Two analysis strategies to name in recon:** sink-driven (trace untrusted input source→sink)
  and control-driven (enumerate entry points, verify an authorization/validation control exists on
  each). These are the lenses the tiered domains apply.
- **Out of scope:** changing the domain skills themselves or the tier ordering (that's plan #5).
  This adds the bracketing phases and the two-strategy framing.

## 🏗️ Architectural Blueprint
- **Files to create:**
  - `skills/audit/references/methodology.md` — the recon checklist (what to map), the sink-driven
    vs control-driven strategies, and the coverage-gap self-check questions.
- **Files to modify:**
  - `skills/audit/SKILL.md` — add a **Reconnaissance** step before the risk-ranked tiers and a
    **Coverage check** step after the verification pass; link the methodology reference; state that
    recon findings feed the risk-ranking and scope.
- **Schema/interface changes:** Output may gain a short "Coverage & known gaps" note.
- **Downstream impact:** Orchestrator flow gains a front and back phase; tiers/verification
  unchanged in the middle.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Write `references/methodology.md` — recon/attack-surface checklist, sink-driven vs
  control-driven strategies, coverage-gap self-check questions -> target: `skills/audit/references/methodology.md`
- [ ] Step 2: Add the **Reconnaissance** step before the tiers (feeds risk-ranking + scope) and
  link the methodology reference -> target: `skills/audit/SKILL.md`
- [ ] Step 3: Add the **Coverage check** step after the verification pass and a "Coverage & known
  gaps" line to the output -> target: `skills/audit/SKILL.md`
- [ ] Step 4: Verify the new phases frame (not duplicate) the existing tiers and verification pass -> target: manual verification
