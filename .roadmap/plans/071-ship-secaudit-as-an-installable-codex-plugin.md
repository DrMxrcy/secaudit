---
id: 71
title: Ship secaudit as an installable Codex plugin
type: feature
version: 3.13.0
status: done
created: 2026-10-20
---

# Plan 71: Ship secaudit as an installable Codex plugin
> Type: feature · Target: v3.13.0

## 🎯 Target Scope & Boundaries
- **Core objective:** the same repo installs in Codex CLI (0.163) via its plugin marketplace: `codex plugin marketplace add DrMxrcy/secaudit` then `codex plugin add secaudit@secaudit`. Codex format (from the openai-curated marketplace + plugin-creator spec): `<plugin>/.codex-plugin/plugin.json` with `"skills": "./skills/"` and an `interface` block; marketplace index at `<repo>/.agents/plugins/marketplace.json` with `{name, interface.displayName, plugins:[{name, source:{source:"local", path}, policy:{installation, authentication}, category}]}`. The plugin root is the repo root, so the existing `skills/` are shared — no copy.
- **Keep in sync:** `scripts/check-freshness.py` manifest check also compares `.codex-plugin/plugin.json` version/description/keywords with `.claude-plugin/plugin.json`.
- **Out of scope:** Codex-specific skill rewrites; publishing to the openai-curated marketplace.

## 🏗️ Architectural Blueprint
- **Files to create:** .codex-plugin/plugin.json, .agents/plugins/marketplace.json
- **Files to modify:** scripts/check-freshness.py (manifest check), README.md (Codex install), CONTRIBUTING.md if it documents release steps

## ✅ Acceptance
- **Passes when:** `codex plugin marketplace add <repo>` + `codex plugin list` shows secaudit; `codex plugin add secaudit@secaudit` installs it; Codex lists the skills; freshness "All current" and its self-check passes; the manifest check fails if the Codex manifest's version drifts (tested).
- **Fails if:** the Claude plugin install changes or skills are duplicated.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Add Codex manifest + marketplace index, verify install with the codex CLI -> target: .codex-plugin/plugin.json, .agents/plugins/marketplace.json
  > evidence: codex-cli 0.163: marketplace add <repo> lists secaudit@secaudit; codex plugin add installed + enabled v3.12.1 with 39 skill dirs; plugin root './' (repo root) accepted (2026-10-20)
- [x] Step 2: Sync check in freshness manifest check, README install instructions; freshness green -> target: scripts/check-freshness.py, README.md
  > evidence: manifest check compares .codex-plugin version/description/keywords; drift test (version 9.9.9) flagged, restored -> All current; --self-check OK; README Codex install section (2026-10-20)
