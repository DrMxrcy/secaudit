---
id: 59
title: Raise Next.js and React floors for the October 14 2026 advisories
type: feature
version: 3.12.0
status: planned
created: 2026-10-17
---

# Plan 59: Raise Next.js and React floors for the October 14 2026 advisories
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** framework-versions reflects the Next.js out-of-band release of 2026-10-14 (vendor post: https://nextjs.org/blog/nextjs-security-update-october-14-2026). Facts verified from the post + npm publish times:
  - `GHSA-673q-mjm6-r5xr` (React upstream `GHSA-xqc2-xf4c-x3h3`) — Critical unauthenticated RCE: App Router + Cache Components when a `use cache` function returns multiple typed arrays (RSC/Flight serialization). No workaround; upgrade even with no such functions.
  - `CVE-2026-96889` / `GHSA-2464-fhr4-w9xw` — Critical unauthenticated RCE in Image Optimization on SVG input via sharp/libvips → librsvg use-after-free (`RUSTSEC-2026-0305`); **glibc Linux only** (Alpine/musl not affected). Workaround/second condition: resolved `sharp >= 0.35.5`. `next@15.5.28` accepts `sharp "^0.34.3 || ^0.35.5"`, so check the *resolved* sharp / `@img/sharp-libvips-*` in the lockfile, not just next.
  - `GHSA-p3m5-59mp-jv5r` (React upstream `GHSA-h3gv-c5rc-p453`) — High DoS (CPU exhaustion) in Server Action request parsing; App Router with ≥1 Server Action; Pages Router unaffected.
  - Fixed: `next` **15.5.28** / **16.4.1** (16.4.2 latest). **No 16.3.x fix** — 16.3.8 (old floor) and 16.4.0 are vulnerable. React `react-server-dom-*` 19.0.9 / 19.1.10 / 19.2.9 / 19.3.1 published 2026-10-14 16:49–16:55Z — new React floor 19.2.9 (or 19.3.1); state that ranges are pending the published advisory.
  - As of 2026-10-17 none of the five GHSAs resolves on OSV or `gh api /advisories/` (only RUSTSEC-2026-0305 does).
- **freshness script:** `check_advisories` reports any cited GHSA/CVE that 404s on OSV as drift. Add a small, dated `PENDING_OSV` dict in `scripts/check-freshness.py` (id → (vendor URL, date added)); a pending id that 404s prints a stderr warning, not drift; once it resolves on OSV, or the entry is >30 days old, report drift ("remove from PENDING_OSV" / "still not on OSV after 30 days — re-verify").
- **Out of scope:** the broader "OSV is not complete" guidance (plan 60); Next 16 config checks (plan 67).

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/framework-versions/SKILL.md (Next.js floors ~L131-132; new 2026-10-14 bullet after the 2026-09-30/10-07 block; shared image pipeline section ~L378-390 adds SVG/librsvg + glibc-only + resolved-sharp step; sources), skills/audit/SKILL.md (~L569 example `"next": "15.5.27"` → a now-vulnerable example consistent with new floor), skills/auth/SKILL.md (~L57 Server Actions: one line that the action surface is DoS-reachable pre-auth so the version matters), SOURCES.md, scripts/check-freshness.py.
- **Downstream impact:** freshness `fixclaims`/`versions` checks parse the new lines.

## ✅ Acceptance
- **Passes when:** framework-versions states floors `next@15.5.28` / `next@16.4.1` and `react-server-dom-*@19.2.9`, says 16.3.x gets no fix, lists all three advisories with the IDs above, the glibc-only and resolved-sharp caveats, and cites the vendor post.
- **Passes when:** `python3 scripts/check-freshness.py` exits clean (pending IDs appear only as warnings) and a unit self-check (assert-based `__main__` or small test) proves PENDING_OSV: 404+fresh → warning, 404+>30d → drift, resolves → drift.
- **Fails if:** any claim disagrees with the vendor post, or older advisory bullets are altered beyond the floor line.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Add PENDING_OSV allowance with expiry + self-check to the freshness script -> target: scripts/check-freshness.py
- [ ] Step 2: Update Next.js/React floors, add 2026-10-14 advisory bullet and image-pipeline SVG/glibc/sharp caveats -> target: skills/framework-versions/SKILL.md
- [ ] Step 3: Sync audit example and auth Server Action DoS line; cite sources; freshness green -> target: skills/audit/SKILL.md, skills/auth/SKILL.md, SOURCES.md
