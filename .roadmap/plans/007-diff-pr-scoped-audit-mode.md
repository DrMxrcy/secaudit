---
id: 7
title: Diff/PR-scoped audit mode
type: feature
version: 3.3.0
status: planned
created: 2026-07-19
---

# Plan 7: Diff/PR-scoped audit mode
> Type: feature · Target: v3.3.0
> Borrowed from anthropics/claude-code-security-review (diff-aware analysis).

## 🎯 Target Scope & Boundaries
- **Core objective:** Add a diff-scoped mode to the orchestrator so "audit my branch changes",
  "review this PR", or "check what I changed" reviews only the changed lines/files (with enough
  surrounding context to judge them) instead of the whole app. Fast, low-noise, and CI-friendly —
  the common case of "I just wrote this, is it safe before I push?".
- **How it scopes:** derive the change set from `git diff <base>...HEAD` (or the PR diff / staged
  changes / working tree as the user indicates). Read changed files plus the immediate context
  needed to trace a source→sink or a missing control (imports, the handler the change sits in, the
  called function). Still dispatch the risk-ranked domains — but only those touched by the diff.
- **Important nuance:** a change can be dangerous because of what it *doesn't* touch (e.g. a new
  route with no auth check). So diff mode reads the changed code but must still reason about the
  guards that *should* surround it, not only the added lines. Note when a finding needs whole-app
  context the diff can't provide.
- **Out of scope:** building an actual GitHub Action / CI integration (that's a separate product
  surface; `tooling.md` already points at CI). This is a scoping mode of the existing skill.

## 🏗️ Architectural Blueprint
- **Files to modify:**
  - `skills/audit/SKILL.md` — extend the **Scope Control** section with a "Diff / PR scope" mode:
    how to obtain the change set, how much context to pull, that domain selection follows the
    files touched, and the caveat about guards that should surround new code.
  - `skills/audit/references/tooling.md` — brief note on wiring the same review into CI on PRs
    (cross-reference the existing `/security-review` command and `anthropics/claude-code-security-review`).
- **Schema/interface changes:** None.
- **Downstream impact:** Scope Control gains a mode; risk tiers and verification pass run over the
  scoped set unchanged.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Add a "Diff / PR scope" mode to the orchestrator Scope Control (change-set
  derivation, context to pull, domain selection by touched files, the missing-guard caveat) -> target: `skills/audit/SKILL.md`
- [ ] Step 2: Add a CI-on-PR note to tooling.md cross-referencing `/security-review` and the
  Anthropic action -> target: `skills/audit/references/tooling.md`
- [ ] Step 3: Verify the mode reads coherently and doesn't contradict the whole-app scope or the
  risk-ranked tiers -> target: manual verification
