---
id: 56
title: TanStack npm compromise postmortem link moved to old.tanstack.com
type: bug
version: 3.11.0
status: done
created: 2026-10-16
---

# 🐛 Plan 56: TanStack npm compromise postmortem link moved to old.tanstack.com
> Type: bug · Target: v3.11.0

## 🔍 Symptom & Reproduction
- **Observed:** `python3 scripts/check-freshness.py` reports `[link] https://tanstack.com/blog/npm-supply-chain-compromise-postmortem dead`; curl returns 404 (3/3 tries).
- **Expected:** freshness check reports "All current".
- **Repro steps:** `curl -sL -o /dev/null -w '%{http_code}' https://tanstack.com/blog/npm-supply-chain-compromise-postmortem` prints 404.

## 🩺 Root Cause
- **Culprit:** TanStack moved the postmortem; same article now lives at https://old.tanstack.com/blog/npm-supply-chain-compromise-postmortem (200, covers pull_request_target, cache poisoning, OIDC).
- **Why:** upstream site restructure; cited in SOURCES.md:531 and skills/ci-cd-security/SKILL.md:718.

## ✅ Acceptance
- **Passes when:** the repro steps above no longer reproduce the symptom
- **Passes when:** the regression test fails on the old code and passes on the fix
- **Fails if:** any other freshness check (cves, eol, fixclaims, kev, manifests, versions) regresses.

## 🛠️ Checklist
- [x] Step 1: Write a reproduction test
  > evidence: freshness check flags link dead; curl 404 x3 on tanstack.com URL; old.tanstack.com URL returns 200 with matching content (2026-10-16)
- [x] Step 2: Apply the fix
  > evidence: replaced URL in SOURCES.md:531 and skills/ci-cd-security/SKILL.md:718 (2026-10-16)
- [x] Step 3: Verify suite is green
  > evidence: check-freshness: All current. Checks run: cves, eol, fixclaims, kev, links, manifests, versions (2026-10-16)
