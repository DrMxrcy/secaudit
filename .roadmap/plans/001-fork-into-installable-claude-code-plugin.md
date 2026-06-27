---
id: 1
title: Fork into installable Claude Code plugin
type: feature
version: 3.0.0
status: done
created: 2026-06-27
---

# Plan 1: Fork into installable Claude Code plugin
> Type: feature · Target: v3.0.0

**Spec:** [docs/superpowers/specs/2026-06-27-vibe-security-plugin-design.md](../../docs/superpowers/specs/2026-06-27-vibe-security-plugin-design.md)

## 🎯 Target Scope & Boundaries
- **Core objective:** Restructure the single monolithic `vibe-security` skill into an
  installable Claude Code plugin: one orchestrator skill (`audit`) plus 13 focused domain
  skills with precise, non-overlapping triggers. Refresh content against verified 2025-2026
  sources and add dedicated Expo, React Native, and Convex security coverage.
- **Out of scope:** No upstream PRs to expo/skills or convex-agent-plugins (our plugin only).
  Claude Code only — no `.codex-plugin` / `.cursor-plugin`. No sub-agents, hooks, or test
  harness in this version. No new vulnerability *domains* beyond those in the current skill
  plus the Convex/Expo/RN splits.

## 🏗️ Architectural Blueprint
- **Files to create:**
  - `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`
  - `skills/audit/SKILL.md` (orchestrator)
  - `skills/<domain>/SKILL.md` ×13: framework-versions, secrets, database, convex-security,
    auth, rate-limiting, payments, supply-chain, react-native-security, expo-security,
    ai-integration, deployment, data-access
  - `references/` subfolders for large skills (database, react-native-security,
    ai-integration, audit) as needed
- **Files to modify:** `README.md` (plugin install + skill list), root version → 3.0.0
- **Files to delete:** `vibe-security/` (old monolithic skill folder) after migration
- **Schema/interface changes:** Frontmatter convention changes from nested `metadata:` block
  to flat `name`/`description`/`version`/`license` (Expo style). Skill invocation becomes
  namespaced `vibe-security:<domain>`.
- **Downstream impact:** Existing users who copied the `vibe-security/` folder must re-install
  via the plugin marketplace. Documented as a v3 breaking change in README.

## 🚶 Step-by-Step Checklist

### Phase A — Plugin scaffold
- [x] Step 1: Create `.claude-plugin/plugin.json` (name "vibe-security", version 3.0.0, author, description) -> target: valid JSON, `name`/`version` present
- [x] Step 2: Create `.claude-plugin/marketplace.json` referencing the plugin -> target: installable layout valid against Claude Code plugin schema

### Phase B — Orchestrator
- [x] Step 3: Create `skills/audit/SKILL.md` from old SKILL.md, trimmed to cross-cutting layer (core principle, audit process, severity model, output format, tooling) + dispatch instructions to `vibe-security:<domain>` skills -> target: no detection patterns duplicated from domain skills; references all 13 domains

### Phase C — Migrate existing domain skills (flat frontmatter + When to Use)
- [x] Step 4: `skills/framework-versions/SKILL.md` from `framework-versions.md` -> target: builds, trigger-rich description, When-to-Use section
- [x] Step 5: `skills/secrets/SKILL.md` from `secrets-and-env.md` -> target: same shape
- [x] Step 6: `skills/database/SKILL.md` from `database-security.md` minus Convex -> target: Convex content removed, Supabase/Firebase/SQL/ORM retained
- [x] Step 7: `skills/auth/SKILL.md` from `authentication.md` -> target: same shape; cross-links rate-limiting
- [x] Step 8: `skills/rate-limiting/SKILL.md` from `rate-limiting.md` -> target: same shape
- [x] Step 9: `skills/payments/SKILL.md` from `payments.md` -> target: same shape
- [x] Step 10: `skills/supply-chain/SKILL.md` from `supply-chain.md` -> target: same shape
- [x] Step 11: `skills/ai-integration/SKILL.md` from `ai-integration.md` -> target: same shape
- [x] Step 12: `skills/deployment/SKILL.md` from `deployment.md` -> target: same shape
- [x] Step 13: `skills/data-access/SKILL.md` from `data-access.md` -> target: same shape

### Phase D — New & split skills
- [x] Step 14: `skills/convex-security/SKILL.md` (NEW) — public vs internal fns, arg validators, ctx.auth not args, cron/httpAction, file storage, convex-helpers/eslint -> target: covers the 10 findings from spec
- [x] Step 15: `skills/react-native-security/SKILL.md` refocused from `mobile.md` — keychain, bundle secrets, deep links, WebView, ATS, native bridge -> target: no Expo/EAS-specific content
- [x] Step 16: `skills/expo-security/SKILL.md` (NEW) — EXPO_PUBLIC_ inlining, EAS secrets, expo-secure-store, OTA code signing, app config, config plugins, +api proxy -> target: covers the 9 Expo findings from spec

### Phase E — Research-verified content updates
- [x] Step 17: Fix CVE in framework-versions: CVE-2025-66478 (rejected) -> canonical CVE-2025-55182 (React2Shell, CVSS 10.0); add CVE-2025-29927 (Next.js middleware bypass) cross-linked to auth -> target: no rejected CVE cited as primary
- [x] Step 18: Update secrets/database with Supabase publishable/secret key model (legacy anon/service_role deprecation) -> target: new key formats documented
- [x] Step 19: Update supply-chain with slopsquatting stats (USENIX 2025) and verify-before-install workflow -> target: cited stat + workflow present
- [x] Step 20: Update ai-integration with OWASP LLM Top 10 2025 + MCP risks (tool poisoning, over-permissioned scopes, token passthrough) -> target: MCP section present

### Phase F — Retire old structure & release
- [x] Step 21: Delete `vibe-security/` folder -> target: `git status` shows removal; no references to old path remain
- [x] Step 22: Update `README.md` (plugin install instructions, full skill list, v3 breaking-change note) -> target: install command documented
- [x] Step 23: Bump version to 3.0.0 across plugin.json and any skill frontmatter -> target: consistent version everywhere
- [x] Step 24: Final pass — verify README is em-dash-free (repo convention applies to user-facing copy only), every SKILL.md has valid frontmatter + When-to-Use section, and `claude plugin validate` passes -> target: clean
