---
id: 75
title: Add pwn.watch as an optional live-incident source in monitor-deps.py
type: feature
version: 3.14.0
status: done
created: 2026-10-23
---

# Plan 75: Add pwn.watch as an optional live-incident source in monitor-deps.py
> Type: feature · Target: v3.14.0

## 🎯 Target Scope & Boundaries
- **Core objective:** OSV misses exactly what hurt this month — language runtimes (PHP2Shell, Node2Shell) and vendor-only advisories that land days before OSV ingests them. Add an opt-in `--pwnwatch` flag to `scripts/monitor-deps.py` that: maps detected ecosystems/runtimes to pwn.watch tags (package-lock -> node, npm; uv.lock/requirements -> python, pypi; composer.json/.lock -> php; Dockerfile -> docker; `.github/workflows` -> github-actions); fetches `https://pwn.watch/t/<tag>.json` with `If-None-Match` from a small state file (default `.secaudit/pwnwatch-state.json`, overridable) and stops on 304; keeps incidents with status live and category patch or supply-chain; best-effort matches the incident's package names/`affectedVersions` text against the lockfile versions and the detected runtime version; reports each hit with patchStatus (partial/unpatched ranked urgent), fixed versions, and the vendor advisory from `sources` (pwn.watch link secondary). Unmatched live criticals for a detected tag are listed as "check manually", one line each. Stdlib only, like the rest of the script.
- **Respect the feed's rules:** no polling loop inside the script; document that a scheduled run should be hourly at most; send the ETag; set a descriptive User-Agent.
- **Out of scope:** replacing OSV; a daemon/cron installer; breach-category alerts.

## 🏗️ Architectural Blueprint
- **Files to modify:** scripts/monitor-deps.py (flag, tag mapping, fetch with ETag cache, matcher, report + --json fields, exit code honours --fail-on), skills/supply-chain/SKILL.md or framework-versions/references/live-advisory-lookup.md (document pwn.watch as a tracker for runtime/vendor-only gaps), SOURCES.md, README.md (flag)
- **Schema/interface changes:** new `pwnwatch` array in `--json` output; new optional state file
- **Downstream impact:** default behaviour (no flag) unchanged

## ✅ Acceptance
- **Passes when:** without the flag, output is byte-identical to before on a fixture; with the flag, against a fixture lockfile with next 16.4.0 the Next.js October incident is reported with the GitHub advisory link and fixed 16.4.1; a second run sends If-None-Match and handles 304; a network failure on pwn.watch degrades to a warning, not exit 2; python3 -m py_compile passes.
- **Fails if:** the script polls in a loop, drops the vendor link, or makes pwn.watch mandatory.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Tag mapping, ETag-cached fetch and incident filter behind --pwnwatch -> target: scripts/monitor-deps.py
  > evidence: unittest discover -s scripts/tests: 50 tests OK; live run (temp state, XDG override): next 16.4.0 AFFECTED w/ GitHub advisory link, state 0600; 304 path tested w/ cached list; py_compile OK; no-flag output byte-identical (cmp.sh 40/40); verifier: REFUTED then REFUTED, loop cap spent, parent verified fix round 2 (2026-10-23)
- [x] Step 2: Version matcher, report/JSON output, fail-on wiring; fixture tests (match, 304, offline) -> target: scripts/monitor-deps.py
  > evidence: single not-affected choke point (_pw_candidate/_pw_conclude, 1 verdict literal); reviewer repro scripts p1,p2,p4,p7,p9 now 0 not-affected; seeded differential test in suite; sanitiser test OK; fuzz leftovers = 'only' suffix + bounded '>=X, <Y' reads (kept, documented) (2026-10-23)
- [x] Step 3: Document the flag and pwn.watch's role as a tracker -> target: README.md, skills/framework-versions/references/live-advisory-lookup.md, SOURCES.md
  > evidence: README flag lines, docs/monitoring.md --pwnwatch section, live-advisory-lookup.md tracker section, SOURCES.md; freshness --self-check OK, --only manifests/links current (2026-10-23)
