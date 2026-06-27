---
id: 2
title: Comprehensive coverage and cited sources
type: feature
version: 3.1.0
status: planned
created: 2026-06-27
---

# Plan 2: Comprehensive coverage and cited sources
> Type: feature · Target: v3.1.0

**Spec:** [docs/superpowers/specs/2026-06-27-vibe-security-v3.1-comprehensive-sourced-design.md](../../docs/superpowers/specs/2026-06-27-vibe-security-v3.1-comprehensive-sourced-design.md)

## 🎯 Target Scope & Boundaries
- **Core objective:** Make the plugin comprehensive and verifiable. Fact-check every existing
  skill, add cited primary sources throughout, and close the OWASP Top 10 gaps with three new
  skills (`web-vulns`, `cryptography`, `logging-monitoring`) plus `auth` hardening.
- **Out of scope:** No change to v3.0 packaging/dispatch architecture. No infra/container/GraphQL/
  WebSocket depth (Idea Incubator). No multi-platform, upstream PRs, agents/hooks/test-harness.

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/web-vulns/SKILL.md`, `skills/cryptography/SKILL.md`,
  `skills/logging-monitoring/SKILL.md`, `SOURCES.md` (repo root)
- **Files to modify:** all 14 existing `skills/*/SKILL.md` (verification + `## Sources`),
  `skills/audit/SKILL.md` (dispatch + OWASP map), `skills/auth/SKILL.md` (hardening),
  `skills/deployment/SKILL.md` (clickjacking), `README.md` (skill list + version), manifests (3.1.0)
- **Schema/interface changes:** Every skill gains a `## Sources` section. Three new namespaced
  skills (`vibe-security:web-vulns`, `:cryptography`, `:logging-monitoring`).
- **Downstream impact:** None breaking — purely additive over v3.0. Plugin grows 14 -> 17 skills.

## 🚶 Step-by-Step Checklist

### Phase A — Verification pass (fact-check existing skills)
- [ ] Step 1: Research-verify the 9 fresh-researched skills' claims still current (framework-versions CVEs, Supabase keys, Convex, Expo, RN, supply-chain, ai-integration) -> target: verification log; fixes applied
- [ ] Step 2: Independently verify the 5 carried-over skills (auth, payments, rate-limiting, deployment, data-access) against current primary sources -> target: verification log; fixes applied

### Phase B — Sourcing
- [ ] Step 3: Add a `## Sources` section to all 14 existing skills with primary-source URLs -> target: every existing SKILL.md has Sources
- [ ] Step 4: Create root `SOURCES.md` index grouping all cited sources by skill/topic -> target: file exists, links resolve

### Phase C — New skill: web-vulns
- [ ] Step 5: `skills/web-vulns/SKILL.md` — XSS, SSRF, file upload + path traversal, IDOR, with When-to-Use, before/after fixes, and Sources -> target: covers all four, cited
- [ ] Step 6: Consolidate open-redirect cross-references into web-vulns and link from database/auth/expo/rn -> target: single canonical treatment

### Phase D — New skill: cryptography
- [ ] Step 7: `skills/cryptography/SKILL.md` — password hashing, CSPRNG, weak algorithms, JWT alg confusion (cross-link auth), encryption-at-rest, with Sources -> target: covers A02, cited

### Phase E — New skill: logging-monitoring
- [ ] Step 8: `skills/logging-monitoring/SKILL.md` — error info disclosure, secrets/PII in logs, audit logging, insecure deserialization + command injection, with Sources -> target: covers A09/A08/A03, cited

### Phase F — auth hardening + deployment fold-in
- [ ] Step 9: Expand `skills/auth/SKILL.md` — cookie flags, CSRF (incl. Server Actions), passkeys/WebAuthn, session fixation, account enumeration, with Sources -> target: A07 fully covered
- [ ] Step 10: Add clickjacking (X-Frame-Options / CSP frame-ancestors) to `skills/deployment/SKILL.md` -> target: clickjacking covered

### Phase G — Orchestrator + release
- [ ] Step 11: Update `skills/audit/SKILL.md` — add web-vulns/cryptography/logging-monitoring to dispatch + embed OWASP Top 10 mapping -> target: all 16 domains referenced
- [ ] Step 12: Update README (skill list 14 -> 17, OWASP coverage note) and bump manifests to 3.1.0 -> target: consistent version, accurate list
- [ ] Step 13: Final pass — `claude plugin validate` passes, every SKILL.md has frontmatter + When-to-Use + Sources, README em-dash-free -> target: clean
