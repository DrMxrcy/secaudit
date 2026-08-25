---
id: 26
title: Add coverage for Nuxt, React Router, Vite and Node.js
type: feature
version: 3.6.0
status: done
created: 2026-08-24
---

# ✨ Plan 26: Add coverage for Nuxt, React Router, Vite and Node.js

> Type: feature · Target: v3.6.0

## 🎯 Target Scope & Boundaries

`framework-versions` covers Next.js/React, Express, Astro and Vue 2. Three widely-used frameworks
with large, active advisory sets are absent entirely, and one of them (Vite) is already cited
elsewhere in the plugin for a CISA KEV entry without having an entry of its own.

Verified against OSV on 2026-08-24:

| Package | Total advisories | Published in 2026 | Clean floor (verified 0 open) |
|---|---|---|---|
| `nuxt` | 21 | **16** | **`4.5.1`** (4.4.7 still has 7; 4.4.6 has 11) |
| `react-router` | 20 | **18** | **`7.18.2`** or `8.3.0` (7.18.0 still has 1) |
| `vite` | 22 | 6 | **`7.3.5`** or `8.0.16` (8.0.5 has 2) |

The 2026 concentration is the point: Nuxt published 16 of its 21 advisories this year, React
Router 18 of 20. These are not dormant entries — they are where the current damage is.

Representative issues to name (verified present in OSV):

- **Nuxt** — `CVE-2026-71320` server-side RCE via runtime template injection in Server Island
  props; `CVE-2026-71318` unauthorized component instantiation via Server Island props;
  `CVE-2026-71321` unauthenticated CPU exhaustion parsing/hashing island payloads;
  `CVE-2026-72744` dev server discloses project root and workspace UUID.
- **React Router / Remix** — `CVE-2026-53668` open redirect leading to XSS; `CVE-2026-53669`
  open redirect via backslash in `<Link>`/`useNavigate`; `CVE-2026-55685` unauthenticated DoS via
  inefficient route matching; `CVE-2026-22030` and `CVE-2026-53663` CSRF in action/document
  request processing; `GHSA-qwww-vcr4-c8h2` RSC-mode CSRF bypass. Note `@remix-run/*` packages
  carry the same React Router advisories, so a Remix app is in scope under a different name.
- **Vite** — `CVE-2026-53571` `server.fs.deny` bypass on Windows alternate paths;
  `CVE-2026-39365` path traversal in optimized-deps `.map` handling. This sits alongside the
  already-documented KEV entry `CVE-2025-31125` and its siblings `CVE-2025-32395` /
  `CVE-2025-46565` — `server.fs.deny` is a repeat-offender control, which is the finding.

## ⚠️ Node.js — deliberately no version numbers

OSV does not index the Node.js **runtime** the way it indexes npm packages: an
`{"ecosystem":"Node.js"}` query returns HTTP 400, and `{"ecosystem":"npm","name":"node"}` returns
zero. So `scripts/check-freshness.py` **cannot verify a hardcoded Node version**, and anything
written here would be an unverifiable claim that quietly rots — precisely the defect class v3.4.0
and plan 25 exist to eliminate.

Node.js is therefore covered **without naming versions**: point at `node --version`, the official
security-release feed, and `npm audit`'s engine warnings. Better a check the reader performs than
a number the tooling cannot police.

**Out of scope:** a per-framework skill for any of these. They are version-table entries, not
new domains — none has enough non-version-specific guidance to justify its own file.

## 🏗️ Architectural Blueprint

- **Modified:** `skills/framework-versions/SKILL.md` — extend `## Other ecosystems` with entries
  for Nuxt, React Router/Remix and Vite, and add a short Node.js runtime note.
- **Modified:** `SOURCES.md` — advisory URLs plus the Node.js security-release feed.
- **Framing:** each entry states the patch line *and* a currently-clean floor, following the
  distinction plan 12 introduced, so the freshness checker can police them.
- **Constraint:** every version named must pass `scripts/check-freshness.py --only versions` and
  `--only fixclaims`.

## ✅ Acceptance

- Each named clean floor returns zero advisories from OSV at build time.
- No Node.js version number is hardcoded anywhere in the entry.
- `python3 scripts/check-freshness.py` exits 0 afterwards.
- `@remix-run/*` is explicitly named so a Remix project matches.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Add Nuxt, React Router/Remix and Vite entries with patch lines and verified clean
  floors -> target: `skills/framework-versions/SKILL.md`
- [x] Step 2: Add the Node.js runtime note with no hardcoded versions, explaining that the
  runtime is not OSV-indexed and must be checked against the official feed -> target:
  `skills/framework-versions/SKILL.md`
- [x] Step 3: Add advisory and Node.js security-feed URLs -> target: `SOURCES.md`
- [x] Step 4: Verify — every named floor returns zero on OSV, and the full freshness check exits
  0 -> target: manual verification
