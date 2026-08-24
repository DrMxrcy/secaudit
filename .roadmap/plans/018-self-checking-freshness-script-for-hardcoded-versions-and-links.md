---
id: 18
title: Self-checking freshness script for hardcoded versions and links
type: feature
version: 3.5.0
status: done
created: 2026-08-21
---

# ✨ Plan 18: Self-checking freshness script for hardcoded versions and links

> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

v3.4.0 fixed four wrong CVE fix-versions, a whole OWASP renumbering, and five rotten URLs. Every
one of those defects had the same shape: **a fact was correct when written and silently stopped
being correct.** Fixing them by hand does not stop it recurring — the file re-rots the moment an
advisory lands.

### How fast does it actually rot? (measured, not guessed)

Queried from OSV on 2026-08-21, `next` advisory publication dates since 2025-08:

- **64** advisories total for `next`; **31** published since 2026-01 alone.
- **Median gap between advisory days: 31 days.** Longest quiet stretch: 96 days. Shortest: 1 day.
- Bursty, not steady: 13 advisories in 2026-05, 9 in 2026-07, zero in 2026-02 and 2026-06.
- The most recent advisory was **2026-07-22 — 30 days before this measurement**, i.e. exactly at
  the median. The floors written in v3.4.0 are already at their expected half-life.

So a hardcoded "clean floor" for a fast-moving framework has a useful life measured in **weeks**.
Other ecosystems are far slower (`express`: zero advisories in the last 12 months), so a single
cadence over-checks some packages and under-checks others — the check must be cheap enough to run
often regardless.

**Conclusion: monthly, automated.** Manual re-verification at that cadence will not happen
reliably, so it has to be a script.

### Scope

A `scripts/check-freshness.py` that re-derives, from live sources, every perishable fact the
skills assert, and exits non-zero when reality has moved:

1. **Version floors** — every `pkg@x.y.z` presented as a safe target must return zero advisories
   from OSV. This is the check that would have caught `next@15.5.7` and `express@4.19.0`.
2. **CVE fix-versions** — every `CVE-…`/`GHSA-…` cited with a fixed version must match that
   advisory's actual `fixed` events. This is the check that would have caught Express 4.19.0 and
   the React sibling-CVE defect.
3. **Links** — every URL returns 200 without a redirect, minus a documented allowlist of false
   positives (`w3.org/TR/webauthn-2` 403s to a browser UA; `api.osv.dev` is POST-only).
4. **KEV drift** — report any cited CVE that has since been added to the CISA KEV catalog, since
   that changes its severity to Critical.

**Out of scope:** auto-editing the skills. The script reports; a human decides. Silent
auto-correction of security guidance is a worse failure mode than staleness.

## 🏗️ Architectural Blueprint

- **New file:** `scripts/check-freshness.py` — stdlib only (`urllib`, `json`, `re`), no
  dependencies to install or keep patched. Takes `--json` for machine output and
  `--only links|versions|cves|kev` to run one class.
- **New file:** `.github/workflows/freshness.yml` — monthly cron plus manual dispatch, opening
  an issue on failure. Monthly matches the measured median.
- **Modified:** `CONTRIBUTING.md` — document the script and the cadence rationale.
- **Extraction strategy:** parse the markdown for `pkg@version` patterns and advisory IDs rather
  than maintaining a parallel manifest — a manifest would itself go stale, which is the bug.
- **Failure mode to avoid:** false positives train people to ignore the check. Placeholders
  (`TARGET`, `myapp.com`, `<project-id>`, `GHSA-xxxx-xxxx-xxxx`) must be excluded by design, and
  the allowlist must be explicit and commented.

## ✅ Acceptance

- Running it today on a clean tree exits 0.
- Reverting any single v3.4.0 fix makes it exit non-zero and name the file and the fact.
- No network dependency beyond OSV, the CISA KEV feed, and the cited hosts themselves.
- Runtime under ~2 minutes so it is cheap to run before any release.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write `scripts/check-freshness.py` with the four checks, placeholder exclusion, an
  explicit false-positive allowlist, and `--json` / `--only` flags -> target:
  `scripts/check-freshness.py`
- [x] Step 2: Verify it exits 0 on the current tree -> target: manual verification
- [x] Step 3: Prove it catches real regressions — temporarily reintroduce each of the four
  v3.4.0 defects (Express 4.19.0, the React sibling versions, a dead URL, a rotted floor) and
  confirm each is reported, then revert -> target: manual verification
- [x] Step 4: Add the monthly GitHub Actions workflow with issue-on-failure and manual dispatch
  -> target: `.github/workflows/freshness.yml`
- [x] Step 5: Document the script and the measured cadence rationale in `CONTRIBUTING.md`
  -> target: `CONTRIBUTING.md`
- [x] Step 6: Note in `framework-versions` that its hardcoded floors are machine-checked monthly
  and that the live lookup remains authoritative -> target: `skills/framework-versions/SKILL.md`
