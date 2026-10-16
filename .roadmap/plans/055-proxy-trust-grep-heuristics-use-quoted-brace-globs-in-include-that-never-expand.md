---
id: 55
title: proxy-trust grep heuristics use quoted brace globs in --include that never expand
type: bug
version: 3.10.0
status: done
created: 2026-10-16
---

# 🐛 Plan 55: proxy-trust grep heuristics use quoted brace globs in --include that never expand
> Type: bug · Target: v3.10.0

## 🔍 Symptom & Reproduction
- **Observed:** 13 grep heuristics in `skills/proxy-trust/SKILL.md` used `--include='*.{js,ts,py,go}'`-style globs and matched no files.
- **Expected:** each heuristic searches the listed file types.
- **Repro steps:** create `a.ts` containing `secret`; `grep -rl --include='*.{js,ts}' secret .` exits 1.

## 🩺 Root Cause
- **Culprit:** quoted brace globs in `--include`.
- **Why:** quoting stops shell brace expansion, and grep's `--include` glob has no brace syntax, so the literal `*.{js,ts}` matches nothing.

## ✅ Acceptance
- **Passes when:** the repro steps above no longer reproduce the symptom
- **Passes when:** the regression test fails on the old code and passes on the fix
- **Fails if:** any heuristic's search pattern changes.

## 🛠️ Checklist
- [x] Step 1: Write a reproduction test
  > evidence: 13 brace globs expanded to repeated --include; grep count of quoted brace globs = 0 in all skills; rewritten form finds fixture a.ts (exit 0) where old form exited 1 (2026-10-16) (2026-10-16)
- [x] Step 2: Apply the fix
  > evidence: commit 335f7f6: 13 globs expanded into repeated --include flags (2026-10-16)
- [x] Step 3: Verify suite is green
  > evidence: grep for quoted brace globs across skills/*/SKILL.md = 0; fixture a.ts found (exit 0); check-freshness All current (2026-10-16) (2026-10-16)

