---
id: 38
title: Add ci-cd-security skill: GitHub Actions pwn-requests, SHA pinning, permissions, run: injection, keyless cosign
type: feature
version: 3.9.0
status: planned
created: 2026-09-15
---

# Plan 38: Add ci-cd-security skill: GitHub Actions pwn-requests, SHA pinning, permissions, run: injection, keyless cosign
> Type: feature · Target: v3.9.0
> Spec: [notes](../notes/2026-09-15-coverage-gap-research.md)

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/ci-cd-security/` covering GitHub Actions as attack surface: pwn requests (`pull_request_target` / `workflow_run` + checkout of PR head), expression injection into `run:` (`${{ github.event.issue.title }}` etc.), unpinned third-party actions (tag vs commit SHA; tj-actions/changed-files Mar 2025, AsyncAPI Jul 2026, TanStack May 2026), missing top-level `permissions:` (default write token), secrets exposed to forks and in logs, self-hosted runner risks, artifact/cache poisoning, OIDC trust policies for cloud deploys, and verifying signed artifacts (cosign keyless identity pinning). Include grep heuristics and before/after YAML.
- **Out of scope:** GitLab CI / CircleCI specifics beyond a one-line mapping; npm-package supply chain (stays in `supply-chain`).

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/ci-cd-security/SKILL.md`.
- **Files to modify:** `skills/audit/SKILL.md` (new Tier 2 item, A03/A08 map rows), `skills/supply-chain/SKILL.md` (cross-ref), `README.md`, `.claude-plugin/plugin.json`, `SOURCES.md`.
- **Downstream impact:** audit fires this skill when `.github/workflows/*.yml` exists.

## ✅ Acceptance
- **Passes when:** the skill fires on any repo with `.github/workflows/` and covers pwn requests, expression injection, action pinning, token permissions, secrets/fork exposure, and artifact verification, each with a detection pattern and a fixed example.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** a version, advisory ID or provider capability is asserted that OSV or the provider's docs do not confirm; or the freshness check reports drift.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Write the skill, verifying every advisory ID, fixed version and provider claim against OSV / live docs -> target: `skills/ci-cd-security/SKILL.md`
- [ ] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json description/keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
