---
id: 15
title: Add ChainDrop npm worm and no-CVE detection to supply-chain
type: feature
version: 3.4.0
status: done
created: 2026-08-21
---

# ✨ Plan 15: Add ChainDrop npm worm and no-CVE detection to supply-chain

> Type: feature · Target: v3.4.0

## 🎯 Target Scope & Boundaries

`skills/supply-chain/SKILL.md` currently frames dependency risk as *hallucinated packages* plus
*known vulnerabilities you can scan for*. Its entire detection story is tool-based: `npm audit`,
`audit-ci`, `lockfile-lint`, `pip-audit`, OSV.dev.

**That story has a hole, and a 2026 incident demonstrates it.** The CHAINDROP / Shai-Hulud
campaign compromised a legitimate, popular, correctly-spelled package — and because **no CVE was
assigned**, `npm audit` and OSV had nothing to report. Every tool the skill recommends would have
returned clean while the worm was live.

Verified against two independent primary sources (Elastic Security Labs and Wiz, both fetched
2026-08-21). Facts both sources agree on:

- **Date:** 2026-08-04.
- **Scope:** "over 400 unique npm packages" compromised, in the `keyv` / `cacheable` ecosystem.
- **Delivery:** a **`preinstall`** hook — Elastic notes it "will run arbitrary commands before a
  package is installed, requiring no further interaction from the victim".
- **Payload:** credential harvester scanning "over 300 unique patterns" — cloud (AWS/GCP/Azure),
  GitHub tokens, SSH keys, Kubernetes tokens, npm tokens, and AI tooling credentials
  (Anthropic/Claude, OpenAI, Cursor, Gemini). Wiz adds attempted IDE persistence via Claude Code
  hooks and VS Code `tasks.json`.
- **Self-propagation:** on finding an npm token with publish rights, it enumerates every package
  the victim can publish to and injects itself, bumping the patch version.
- **No CVE assigned.** Neither source mentions one.

### Deliberately excluded — could not be verified

The originating research report claimed the malicious versions **carried valid GitHub Actions
provenance**, and gave figures of **2,234 poisoned versions** and **>2B monthly installs**.
Neither primary source states any of these — both explicitly do not discuss provenance or
attestations, and neither gives a version count. These claims are **omitted**. The entry rests
only on what two sources independently confirm.

**Out of scope:** Python/PyPI supply-chain differences (a separate item), and any change to the
slopsquatting section's existing research citations.

## 🏗️ Architectural Blueprint

- **Files to modify:**
  - `skills/supply-chain/SKILL.md` — a new section after `Dependency Auditing`, since that is
    exactly the section whose advice the incident undercuts. Placing it there makes it read as a
    limitation of the tools just recommended, not as trivia.
  - `SOURCES.md` — the two incident write-ups.
- **Framing:** the point is not "know about this one worm". It is that **a clean `npm audit` is
  not evidence of a clean dependency tree** — scanners are lagging indicators keyed on published
  advisories, and a compromise of a legitimate package produces no advisory until someone files
  one. The actionable controls are the ones that hold with no CVE in existence: disable install
  scripts, pin exactly, and prefer a lockfile install that cannot silently take a new version.
- **Downstream impact:** audits gain a check that does not depend on advisory databases having
  caught up.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Add the "scanners are lagging indicators" section after `Dependency Auditing`, with
  CHAINDROP as the worked example and only the two-source-verified facts -> target:
  `skills/supply-chain/SKILL.md`
- [x] Step 2: Add the concrete no-CVE-required controls — `--ignore-scripts`, exact pinning,
  `npm ci`, and lockfile review of `resolved`/`integrity` churn -> target:
  `skills/supply-chain/SKILL.md`
- [x] Step 3: Extend the `Red Flags` list with the signals this class of attack produces (a
  sudden patch bump on a transitive dependency, a lifecycle hook appearing where there was none)
  -> target: `skills/supply-chain/SKILL.md`
- [x] Step 4: Add both incident write-ups to `SOURCES.md` -> target: `SOURCES.md`
- [x] Step 5: Verify — no unverified claim (provenance, version counts, install counts) appears
  in the text, and both new URLs return 200 -> target: manual verification
