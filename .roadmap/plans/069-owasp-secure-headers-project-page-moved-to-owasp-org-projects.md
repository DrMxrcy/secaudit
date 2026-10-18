---
id: 69
title: OWASP Secure Headers project page moved to owasp.org/projects
type: bug
version: 3.12.0
status: done
created: 2026-10-18
---

# 🐛 Plan 69: OWASP Secure Headers project page moved to owasp.org/projects
> Type: bug · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** the freshness `links` check reports https://owasp.github.io/www-project-secure-headers/ dead (404, 2026-10-18). OWASP moved the project to https://owasp.org/projects/secure-headers-project (200, no redirect; title "OWASP Secure Headers Project | OWASP Foundation"). Replace the citation in skills/deployment/SKILL.md and SOURCES.md.
- **Out of scope:** any other deployment content (plan 66 rewrites the headers section).

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/deployment/SKILL.md, SOURCES.md

## ✅ Acceptance
- **Passes when:** `python3 -I scripts/check-freshness.py` prints "All current".
- **Fails if:** anything other than the URL changes.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Replace the dead Secure Headers URL in both files; freshness green -> target: skills/deployment/SKILL.md, SOURCES.md
  > evidence: check-freshness.py: All current; new URL 200 without redirect; diff is the URL only (2 lines) (2026-10-18)
