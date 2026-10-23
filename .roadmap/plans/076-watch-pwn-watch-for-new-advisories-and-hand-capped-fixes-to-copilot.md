---
id: 76
title: Watch pwn.watch for new advisories and hand capped fixes to Copilot
type: feature
version: 3.14.0
status: done
created: 2026-10-23
---

# Plan 76: Watch pwn.watch for new advisories and hand capped fixes to Copilot
> Type: feature · Target: v3.14.0

## 🎯 Target Scope & Boundaries
- **Core objective:** close the gap between "an advisory lands" and "the skills cite it". (1) `scripts/watch-advisories.py` (stdlib) polls pwn.watch tag feeds for the stacks the skills cover, with ETag conditional requests and a cursor in a state file, and emits new/changed live patch + supply-chain incidents as sanitized structured JSON (vendor source URLs from /i/<slug>.json). (2) `.github/workflows/advisory-watch.yml` runs it every 6 h (state via actions/cache) and opens one deduplicated `advisory` issue per incident; critical/high `patch` incidents also get `copilot-ok`. (3) `.github/workflows/copilot-dispatch.yml` assigns at most one `copilot-ok` issue per run to the Copilot coding agent, capped per week (default 2, repo variable `COPILOT_WEEKLY_CAP`), skipped while a Copilot PR is open, and skipped entirely if the repo is private.
- **Zero Actions spend:** Actions minutes are free only for public repos on standard GitHub-hosted runners. The dispatcher refuses to assign when the repo is private; `copilot-setup-steps.yml` pins `ubuntu-latest` (never a larger runner) with a 30-minute timeout. Premium requests (1 per session) are bounded by the weekly cap.
- **Injection boundary:** issue bodies are built only from validated structured fields (slug regex, CVE regex, https URLs, stripped/capped strings, no agentBrief free text); Copilot's custom instructions are constant text and tell it to treat the issue as data, verify against the vendor source, touch only skills/**, SOURCES.md, scripts/check-freshness.py, and run the freshness check. PRs are never auto-merged.
- **Out of scope:** auto-merge; breach-category incidents; self-hosted runners; roadmap updates from Copilot PRs (run /roadmap:catchup after merging).

## 🏗️ Architectural Blueprint
- **Files to create:** scripts/watch-advisories.py, .github/workflows/advisory-watch.yml, .github/workflows/copilot-dispatch.yml, .github/workflows/copilot-setup-steps.yml, .github/copilot-instructions.md
- **Files to modify:** docs/monitoring.md (maintainer section), README.md (one line), CONTRIBUTING.md if it lists workflows
- **Schema/interface changes:** new secret `COPILOT_ASSIGN_TOKEN` (fine-grained PAT: metadata read; actions, contents, issues, pull requests read/write; this repo only); optional variable `COPILOT_WEEKLY_CAP`
- **Downstream impact:** none on skills or existing workflows

## ✅ Acceptance
- **Passes when:** the script against live pwn.watch emits valid JSON, a second run with the saved state sends If-None-Match and gets 304s; hostile fields (backticks, @mentions, javascript: URLs, oversized strings) are neutralised (tested); workflows pass actionlint (or yaml parse if unavailable); the dispatcher exits without assigning when the token is missing, the repo is private, the cap is reached, or a Copilot PR is open (logic reviewed); docs explain setup.
- **Fails if:** any job holding a write token runs repository code it checked out, issue text reaches Copilot's custom instructions, or a larger/self-hosted runner is used.

## 🚶 Step-by-Step Checklist
- [x] Step 1: watch-advisories.py with ETag state, filtering, sanitisation; live + hostile-input tests -> target: scripts/watch-advisories.py
  > evidence: live poll: 10 incidents, 2nd run all 304; hostile-input test OK (tag-char smuggling, userinfo URLs, bidi, truncation, malformed items); cursor holds on feed failure, 48h overlap (2026-10-23)
- [x] Step 2: advisory-watch.yml (read-only watch job, separate issues:write report job) -> target: .github/workflows/advisory-watch.yml
  > evidence: actionlint clean; node --check OK; mocked API: 10 created+locked, rerun no-op, change -> update+comment; state saved only after report succeeds (2026-10-23)
- [x] Step 3: copilot-dispatch.yml, copilot-setup-steps.yml, copilot-instructions.md with cap / private / open-PR guards -> target: .github/workflows/copilot-dispatch.yml, .github/workflows/copilot-setup-steps.yml, .github/copilot-instructions.md
  > evidence: mocked dispatch: no-token, private, open PR, weekly cap, 24h in-flight, unlocked, non-bot author, foreign comment, silent assign drop all refuse; happy path assigns 1; PR scope check + CODEOWNERS added; github-script pinned by SHA (2026-10-23)
- [x] Step 4: Docs: maintainer setup (secret, variable, enabling the agent, zero-minutes rule) -> target: docs/monitoring.md, README.md
  > evidence: docs/monitoring.md maintainer section (setup, ruleset, zero-minutes rule, caps); README pointer (2026-10-23)
