---
id: 58
title: Nuxt blog source URL now redirects to nuxt.com/updates
type: bug
version: 3.11.0
status: done
created: 2026-10-16
---

# 🐛 Plan 58: Nuxt blog source URL now redirects to nuxt.com/updates
> Type: bug · Target: v3.11.0

## 🔍 Symptom & Reproduction
- **Observed:** check-freshness reports `[link] https://nuxt.com/blog redirects (301)` (cited SOURCES.md:35).
- **Expected:** freshness check prints All current.
- **Repro steps:** `curl -sI https://nuxt.com/blog` returns 301 with `location: /updates`.

## 🩺 Root Cause
- **Culprit:** Nuxt renamed /blog to /updates; https://nuxt.com/updates returns 200.
- **Why:** upstream site restructure.

## ✅ Acceptance
- **Passes when:** the repro steps above no longer reproduce the symptom
- **Passes when:** the regression test fails on the old code and passes on the fix
- **Fails if:** any other freshness check regresses.

## 🛠️ Checklist
- [x] Step 1: Write a reproduction test
  > evidence: freshness flags nuxt.com/blog 301; curl -sI shows location: /updates (2026-10-16)
- [x] Step 2: Apply the fix
  > evidence: SOURCES.md:35 now https://nuxt.com/updates (200) (2026-10-16)
- [x] Step 3: Verify suite is green
  > evidence: check-freshness: All current. Checks run: cves, eol, fixclaims, kev, links, manifests, versions (2026-10-16)
