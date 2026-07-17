---
id: 5
title: Risk-ranked scoping, finding verification, and admin-surface review
type: feature
version: 3.2.0
status: planned
created: 2026-07-17
---

# Plan 5: Risk-ranked scoping, finding verification, and admin-surface review
> Type: feature · Target: v3.2.0

## 🎯 Target Scope & Boundaries
- **Core objective:** Four orchestrator/coverage upgrades that address the "blanket fan-out"
  problem and the missing admin coverage, while keeping full-app coverage:
  1. **Risk-ranked sweep** — audit domains in tiers so the highest-impact areas are examined
     first and surfaced first, instead of a flat parallel fan-out. Tier 1 (always first):
     secrets, database/RLS + Convex, auth, payments, framework CVEs. Tier 2: rate-limiting,
     web-vulns, data-access, deployment, ai-integration. Tier 3: cryptography,
     logging-monitoring, supply-chain, mobile. All tiers still run for a full audit.
  2. **Scope control** — the orchestrator accepts a target scope ("audit the admin surface",
     a path/dir subset, or a single domain) and narrows dispatch instead of fanning out every
     executor. Directly fixes the "it deployed agents we don't care about" complaint.
  3. **Adversarial verification pass** — a static review step that challenges each candidate
     finding (Is the code reachable from an entry point? Is the input actually
     attacker-controlled? Is there a compensating control?) and drops or downgrades weak ones
     before they reach the user. Findings are labelled Confirmed vs Needs-verification.
  4. **Admin / privilege-escalation review** — a new focused skill covering vertical and
     horizontal privilege escalation: admin routes enforced server-side, role checks not
     trusted from the client, admin-only mutations/actions gated, and IDOR on admin objects.
- **Out of scope:** Runtime/dynamic confirmation (that is Plan 4 — this verification pass is
  static reasoning about reachability and exploitability); changing the Critical/High/Medium/Low
  taxonomy itself.

## 🏗️ Architectural Blueprint
- **Files to create:**
  - `skills/privilege-escalation/SKILL.md` — new focused skill (auto-loads). Vertical/horizontal
    escalation, server-side role enforcement, admin route/mutation gating, admin-object IDOR,
    with before/after fixes.
- **Files to modify:**
  - `skills/audit/SKILL.md` — add a **Scope Control** section; reorder the Audit Process into
    the risk tiers above (noting all tiers run for a full sweep); add the **Verification Pass**
    to Core Instructions and the Confirmed/Needs-verification label to Output Format; add
    `privilege-escalation` to the domain list and the OWASP map (A01).
  - `README.md` — add the skill to the Skills table.
  - `SOURCES.md` — add OWASP A01 / privilege-escalation references (e.g. OWASP WSTG authorization).
- **Schema/interface changes:** Output format gains a Confirmed/Needs-verification label
  (aligns with Plan 4's Confirmed/Suspected — keep the vocabulary consistent).
- **Downstream impact:** Orchestrator dispatch becomes scope-aware and tiered; other domain
  skills unchanged.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Add a **Scope Control** section to the orchestrator — interpret "admin surface" /
  a path subset / a single domain and narrow dispatch accordingly -> target: `skills/audit/SKILL.md`
- [ ] Step 2: Reorder the Audit Process into risk tiers (Tier 1 high-risk first; all tiers run
  for a full sweep) -> target: `skills/audit/SKILL.md`
- [ ] Step 3: Add the adversarial **Verification Pass** (reachability, attacker-controllability,
  compensating controls) + Confirmed/Needs-verification labels to the output -> target: `skills/audit/SKILL.md`
- [ ] Step 4: Write `privilege-escalation/SKILL.md` (admin routes, server-side roles,
  vertical/horizontal escalation, admin IDOR) with before/after fixes -> target: `skills/privilege-escalation/SKILL.md`
- [ ] Step 5: Add `privilege-escalation` to the orchestrator domain list + OWASP map, the README
  Skills table, and `SOURCES.md` -> target: `skills/audit/SKILL.md`, `README.md`, `SOURCES.md`
- [ ] Step 6: Verify the new skill loads and a scoped request ("audit the admin surface") only
  dispatches the relevant domains -> target: manual verification
