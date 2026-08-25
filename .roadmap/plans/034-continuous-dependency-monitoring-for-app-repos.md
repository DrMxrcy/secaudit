---
id: 34
title: Continuous dependency monitoring for app repos
type: feature
version: 3.8.0
status: done
created: 2026-08-25
---

# ✨ Plan 34: Continuous dependency monitoring for app repos

> Type: feature · Target: v3.8.0

## 🎯 Target Scope & Boundaries

Everything built through v3.7.0 watches **this repo**. `check-freshness.py` keeps the skills'
own citations honest, and an audit reads an app on demand. Nothing watches an app *between*
audits — if Nuxt ships an RCE tomorrow, no app hears about it until someone runs a sweep.

### What this is NOT, and why it still earns its place

Dependabot and `osv-scanner` already report vulnerable dependencies, and this must not pretend to
replace them. What they do not do is **tell you which ones matter today**:

- Dependabot opens a PR per advisory. Forty open PRs is not a priority order, and the well-known
  outcome is that they get batch-merged or ignored.
- `osv-scanner` reports advisories. It does not carry EPSS, so a CVSS-Critical open redirect at
  0.8% exploitation probability looks identical to a pre-auth RCE at 99.8%.
- Neither knows the **runtime** is end-of-life, because no advisory database indexes runtimes.

So the honest scope is a **prioritisation layer**, not another scanner: take the app's own
dependency set, and answer *which of these is being exploited right now, and is the runtime even
receiving patches*. That is the same KEV → EPSS → CVSS → EOL rule v3.7.0 put into the audit
severity model, applied continuously instead of only when someone remembers to ask.

### Scope

- `scripts/monitor-deps.py` — reads an app's dependency set, batches it through OSV, enriches
  with EPSS and CISA KEV, and separately checks runtime EOL. Stdlib only, no install step.
- A **reusable** GitHub workflow (`workflow_call`) an app repo references in ~10 lines, plus the
  scheduled caller for this repo's own dogfooding.
- Output ranked so the top of the report is the thing to do first, and an issue opened only when
  something crosses a threshold worth waking someone for.

**Lockfile support:** `package-lock.json` (v2/v3 `packages` map) and `uv.lock` / `requirements.txt`
with `==` pins — all parseable from stdlib (`json`, `tomllib`). `yarn.lock` and `pnpm-lock.yaml`
use bespoke formats; rather than half-parse them and silently miss packages, detect and tell the
user to run `osv-scanner` instead. **A partial parse that reports "no findings" is the failure
mode this whole project exists to prevent.**

**Out of scope:** opening fix PRs (Dependabot's job), replacing `osv-scanner`, scanning private
registries, and any write to the app's code.

## ⚠️ Design rules carried forward

Every rule the freshness work paid for applies here, because the failure modes are identical:

- **Transient is not a finding.** Retry 429/5xx; never let "could not reach OSV" render as "no
  vulnerabilities". A monitor that fails open is worse than none.
- **Never auto-fix.** Report and rank; a human decides.
- **No wallpaper.** Only open an issue when the threshold is crossed, and update the existing
  issue rather than opening a new one each run.
- **Say what was not checked.** An unparseable lockfile is reported loudly, never skipped
  quietly.

Supply-chain note, since this ships a workflow that app repos will run: the reusable workflow
must be referenced **pinned**, and the docs must say so. Telling people to reference `@main` from
a security tool would contradict `secaudit:supply-chain`.

## 🏗️ Architectural Blueprint

- **New:** `scripts/monitor-deps.py` — `--path`, `--json`, `--min-epss`, `--fail-on`.
- **New:** `.github/workflows/dependency-monitor.yml` — `workflow_call` + `workflow_dispatch`,
  weekly schedule for this repo.
- **New:** `docs/monitoring.md` — the ~10-line snippet an app repo adds, with SHA pinning.
- **Modified:** `framework-versions` and `audit` point at it as the between-audits answer;
  `README.md`; `SOURCES.md`.
- **Reuse:** the OSV/EPSS/KEV/EOL helpers already proven in `check-freshness.py`.

## ✅ Acceptance

- Correctly parses a real `package-lock.json` and reports known-vulnerable packages in it.
- Ranks KEV first, then EPSS descending; an EOL runtime is surfaced at the top regardless.
- A dependency file it cannot parse is reported as unchecked, never as clean.
- Exits 0 with nothing above threshold; non-zero when something is.
- Dogfooded: runs against this repo in CI and passes.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write `scripts/monitor-deps.py` — lockfile parsing, OSV batch, EPSS + KEV
  enrichment, runtime EOL, ranked output -> target: `scripts/monitor-deps.py`
- [x] Step 2: Prove it on a real vulnerable dependency set (fixture with a known-bad pin) and on
  an unparseable lockfile -> target: manual verification
- [x] Step 3: Add the reusable workflow with issue-open/update on threshold -> target:
  `.github/workflows/dependency-monitor.yml`
- [x] Step 4: Write the app-repo setup doc with SHA-pinned reference -> target:
  `docs/monitoring.md`
- [x] Step 5: Cross-reference from `framework-versions`, `audit` and `README.md`
- [x] Step 6: Verify — dogfood run green in CI, freshness check still green -> target: manual
  verification
