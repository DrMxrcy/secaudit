---
id: 55
title: proxy-trust grep heuristics use quoted brace globs in --include that never expand
type: bug
version: 3.10.0
status: active
created: 2026-10-16
---

# 🐛 Plan 55: proxy-trust grep heuristics use quoted brace globs in --include that never expand
> Type: bug · Target: v3.10.0

## 🔍 Symptom & Reproduction
- **Observed:**
- **Expected:**
- **Repro steps:**

## 🩺 Root Cause
- **Culprit:**
- **Why:**

## ✅ Acceptance
- **Passes when:** the repro steps above no longer reproduce the symptom
- **Passes when:** the regression test fails on the old code and passes on the fix
- **Fails if:** <previously green test or adjacent behavior breaks>

## 🛠️ Checklist
- [x] Step 1: Write a reproduction test
  > evidence: 13 brace globs expanded to repeated --include; grep count of quoted brace globs = 0 in all skills; rewritten form finds fixture a.ts (exit 0) where old form exited 1 (2026-10-16) (2026-10-16)
- [ ] Step 2: Apply the fix
- [ ] Step 3: Verify suite is green

## 🎯 Target Scope & Boundaries
- **Core objective:** `skills/proxy-trust/SKILL.md` has 13 grep heuristics with `--include='*.{js,ts,...}'`. Quoted braces are not shell-expanded and grep's `--include` glob has no brace syntax, so each one matches no file (reproduced: exit 1 on a matching `.ts`). Replace each with one `--include` per extension.
- **Out of scope:** other heuristic rewrites.

## 🏗️ Architectural Blueprint
- **Files to modify:** `skills/proxy-trust/SKILL.md`

## ✅ Acceptance
- **Passes when:** `grep -c -- "--include='\*.{" skills/*/SKILL.md` is 0 everywhere, and a rewritten heuristic finds a matching fixture file.
- **Fails if:** any heuristic's pattern changes.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Expand every quoted brace glob into repeated `--include` flags and test one against a fixture -> target: `skills/proxy-trust/SKILL.md`
