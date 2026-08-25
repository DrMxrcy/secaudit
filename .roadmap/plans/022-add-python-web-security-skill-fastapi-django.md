---
id: 22
title: Add python-web-security skill (FastAPI, Django)
type: feature
version: 3.5.0
status: done
created: 2026-08-24
---

# Plan 22: Add python-web-security skill (FastAPI, Django)
> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

New `skills/python-web-security/` — the plugin was almost entirely JS/TS; Python appeared only as
`requirements.txt` in one description and a bare `pip-audit` command.

Covers the *framework-shaped* gaps (FastAPI, Django, `requests`). Language-level sinks went into
the existing skills instead — see plan 24 — so Python sits beside its JS counterpart rather than
in a parallel silo.

**Out of scope:** pickle/eval/SQLAlchemy/PyPI, all handled by plan 24.

## 🏗️ Architectural Blueprint

- **New:** `skills/python-web-security/SKILL.md` (308 lines, 5 sections + detection quick pass).
- **Modified:** `audit` Tier 3 entry keyed on `pyproject.toml` / `requirements.txt` / `manage.py`.
- Every finding was verified by execution against a real venv rather than asserted, which
  produced the item worth the whole skill: **`manage.py check --deploy` does NOT catch
  `ALLOWED_HOSTS=['*']`**. Run with DEBUG=False, a strong key and full security middleware, it
  reports "System check identified no issues" — so host-header poisoning passes Django's own
  checker silently and a grep is mandatory.

## ✅ Acceptance

- **Passes when:** each section carries the observed status code or response body from a real
  run, not a described expectation.
- **Fails if:** it duplicates the language-level sinks owned by plan 24.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write the skill, verifying each claim by execution -> target:
  `skills/python-web-security/SKILL.md`
- [x] Step 2: Register in the audit tiers with the Python stack markers
- [x] Step 3: Add sources and plugin keywords
- [x] Step 4: Verify — frontmatter valid, cross-references resolve, freshness green
