---
id: 11
title: Cross-reference official Convex/Expo build skills
type: feature
version: 3.3.1
status: done
created: 2026-07-20
---

# Plan 11: Cross-reference official Convex/Expo build skills
> Type: feature · Target: v3.3.1

## 🎯 Target Scope & Boundaries
- **Core objective:** Make `convex-security` and `expo-security` *point at* the official vendor
  agent-skills (`get-convex/agent-skills`, `expo/skills`) so the agent defers to them for building
  correctly, while secaudit stays the auditor. Also cite the vendor's own security guidance and add
  the one relevant control each skill is missing. Cross-reference only — no files copied, no
  submodules, no README "companions" section (explicitly out of scope per the chosen direction).
- **What to add:**
  - `convex-security`: a short "Building Convex correctly" note pointing to `get-convex/agent-skills`
    (this skill audits the result). Add **scoped deploy keys** as a control worth confirming (a
    Convex deploy key can be scoped to a single deployment, limiting an agent's blast radius) —
    currently uncovered. Cite the Convex production/security docs.
  - `expo-security`: a short "Building Expo correctly" note pointing to `expo/skills`. EAS secrets
    and env vars are already covered, so no new control needed — just the pointer and a source.
- **Out of scope:** bundling/copying the official skills, git submodules, a README recommended-
  companions section, and any change to the other 16 skills.

## 🏗️ Architectural Blueprint
- **Files to modify:**
  - `skills/convex-security/SKILL.md` — add the build-skill pointer (near the intro or a short
    "See also / building" note) and a brief scoped-deploy-keys check; link the source.
  - `skills/expo-security/SKILL.md` — add the build-skill pointer note; link the source.
  - `SOURCES.md` — add the vendor security-doc URLs under the Convex and Expo sections.
- **Schema/interface changes:** None. Content-only.
- **Downstream impact:** When auditing a Convex/Expo app, the agent recommends the official build
  skills and checks one more vendor-recommended control. No behavior change elsewhere.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Add to `convex-security` the official-build-skill pointer + a scoped-deploy-keys check,
  with a source link -> target: `skills/convex-security/SKILL.md`
- [x] Step 2: Add to `expo-security` the official-build-skill pointer, with a source link -> target: `skills/expo-security/SKILL.md`
- [x] Step 3: Add the vendor security-doc URLs to the Convex and Expo sections of `SOURCES.md` -> target: `SOURCES.md`
- [x] Step 4: Verify the pointers use plain references (not copied content), links resolve, and
  nothing bundles or submodules the official skills -> target: manual verification
