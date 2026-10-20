---
id: 70
title: Shorten the plugin description so the plugin manager stays usable
type: chore
version: 3.12.1
status: done
created: 2026-10-20
---

# Plan 70: Shorten the plugin description so the plugin manager stays usable
> Type: chore · Target: v3.12.1

## 🎯 Target Scope & Boundaries
- **Core objective:** the plugin description in `.claude-plugin/plugin.json` and the matching `plugins[0].description` in `.claude-plugin/marketplace.json` is 2,497 characters; Claude Code's `/plugin` Installed view prints it in full, pushing the Update/Disable actions off-screen. Replace it with a one- or two-sentence summary (≤ 300 chars). Keywords (137) stay as-is and carry discovery.
- **Out of scope:** skill frontmatter descriptions (those drive skill triggering).

## 🏗️ Architectural Blueprint
- **Files to modify:** .claude-plugin/plugin.json, .claude-plugin/marketplace.json (version → 3.12.1 in both so `claude plugin update` picks it up).

## ✅ Acceptance
- **Passes when:** both descriptions are identical and ≤ 300 chars; both manifests parse; `python3 -I scripts/check-freshness.py` prints "All current" (manifest check requires the two to match).
- **Fails if:** keywords or skill files change.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Replace the description in both manifests, bump version to 3.12.1; freshness green -> target: .claude-plugin/plugin.json, .claude-plugin/marketplace.json
  > evidence: description 2497 -> 243 chars, identical in both manifests; version 3.12.1; check-freshness.py: All current (manifests check passes) (2026-10-20)
