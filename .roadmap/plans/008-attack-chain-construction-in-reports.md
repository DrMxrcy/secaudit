---
id: 8
title: Attack-chain construction in reports
type: feature
version: 3.3.0
status: planned
created: 2026-07-19
---

# Plan 8: Attack-chain construction in reports
> Type: feature · Target: v3.3.0
> Borrowed from 3stoneBrother/code-audit (attack-chain construction).

## 🎯 Target Scope & Boundaries
- **Core objective:** Upgrade the report so the orchestrator, after collecting individual
  findings, links related ones into concrete **attack chains** — the step-by-step path an attacker
  actually takes, where several lower-severity issues combine into a high-severity outcome. A flat
  list hides this; e.g. *public signup (no email verify) → no rate limit on login → weak
  password-reset token = account takeover*, or *IDOR on `/orders/:id` → admin object reachable →
  privilege escalation*.
- **Behaviour:** add an **Attack Chains** section to the output (after the severity-grouped
  findings) that names each chain, lists the ordered steps referencing the individual findings by
  their file:line, states the end impact, and rates the chain by its *outcome* severity (a chain
  can be more severe than any single link). Only build a chain when the steps are genuinely
  connected and reachable in sequence — no speculative chains (aligns with plan #10).
- **Out of scope:** automated exploit generation or running the chain (dynamic proof is
  `secaudit:dynamic-verification`). This is analysis + reporting only.

## 🏗️ Architectural Blueprint
- **Files to modify:**
  - `skills/audit/SKILL.md` — add an "Attack chains" step to the audit process (after findings are
    gathered and verified) and an **Attack Chains** section to the Output Format, with a worked
    example and the "connected + reachable only" rule.
- **Schema/interface changes:** Output gains an Attack Chains section; individual findings keep
  their format and are referenced by the chains.
- **Downstream impact:** Reporting only. Chains reference findings that already passed the
  verification pass, so severity stays evidence-based.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Add the attack-chain construction step to the audit process (build chains from
  connected, reachable, verified findings; rate by outcome severity; no speculative chains) -> target: `skills/audit/SKILL.md`
- [ ] Step 2: Add an **Attack Chains** section to the Output Format with a worked example
  referencing findings by file:line -> target: `skills/audit/SKILL.md`
- [ ] Step 3: Verify the chain rules are consistent with the verification pass and don't
  double-count or inflate severity without a connected path -> target: manual verification
