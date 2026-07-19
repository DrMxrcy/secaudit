---
id: 10
title: Evidence-backed findings (anti-hallucination)
type: feature
version: 3.3.0
status: done
created: 2026-07-19
---

# Plan 10: Evidence-backed findings (anti-hallucination)
> Type: feature · Target: v3.3.0
> Borrowed from 3stoneBrother/code-audit (anti-hallucination protocol) + anthropics/claude-code-security-review (proven-impact filtering).

## 🎯 Target Scope & Boundaries
- **Core objective:** Tighten the verification pass so every reported finding is *evidence-backed*:
  it must cite a **verified file:line that was actually read** (not inferred), and name the concrete
  mechanism — the source→sink data flow, or the specific missing control and the entry point it
  should protect. A finding that can't be tied to real code is dropped, not downgraded. This raises
  precision and makes the report defensible, complementing the existing Confirmed / Needs
  verification labels rather than replacing them.
- **Rules to add:**
  - No speculative findings: if you did not read the code that proves it, do not report it.
  - Every finding names its evidence (file:line + the read snippet reference) and its exploit
    mechanism (the path or the missing guard).
  - "Proven impact" discipline: a finding needs a plausible impact path, not just a pattern match
    — but keep secaudit's intentional coverage (rate-limiting / denial-of-wallet stays in scope;
    do NOT adopt the upstream tools' blanket exclusion of it).
- **Out of scope:** runtime proof (that's `secaudit:dynamic-verification`); changing the severity
  taxonomy.

## 🏗️ Architectural Blueprint
- **Files to modify:**
  - `skills/audit/SKILL.md` — add the evidence requirement to the **Verification pass** (a fourth
    check: "Evidenced? cite the verified file:line + mechanism, else drop") and to the **Output
    Format** (each finding shows its evidence + mechanism). Add a one-line "no speculative findings"
    rule to Core Instructions. Reconcile vocabulary with the Confirmed / Needs-verification labels.
- **Schema/interface changes:** Findings explicitly carry an evidence reference; no structural
  change beyond wording.
- **Downstream impact:** Feeds plans #8 (chains reference evidenced findings) and #9 (coverage
  check distinguishes "not found" from "not looked at").

## 🚶 Step-by-Step Checklist
- [x] Step 1: Add the "Evidenced?" check (verified file:line + source→sink or missing-control
  mechanism; drop if unproven) to the Verification pass, plus a "no speculative findings" rule in
  Core Instructions -> target: `skills/audit/SKILL.md`
- [x] Step 2: Update the Output Format so each finding states its evidence reference and exploit
  mechanism; keep rate-limiting/denial-of-wallet in scope (no blanket exclusions) -> target: `skills/audit/SKILL.md`
- [x] Step 3: Verify the new rule reconciles with the Confirmed / Needs-verification labels and
  doesn't contradict the dynamic-verification handoff -> target: manual verification
