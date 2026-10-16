---
id: 48
title: Add discord-bot-security skill: bot tokens, intents, command permissions, role-sync hierarchy, allowedMentions, Discord OAuth identity
type: feature
version: 3.10.0
status: planned
created: 2026-10-16
---

# Plan 48: Add discord-bot-security skill: bot tokens, intents, command permissions, role-sync hierarchy, allowedMentions, Discord OAuth identity
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/discord-bot-security/` for discord.js v14 bots and Discord-OAuth-only apps: bot token handling (token = full bot takeover; never in client code, logs or repos; reset procedure; GitHub secret scanning partnership); privileged gateway intents requested minimally; slash command authorization (`default_member_permissions` is only a default that guild admins can override, so re-check `interaction.memberPermissions` / app-level roles server-side; `setDMPermission`/contexts); role-sync logic that can grant a role above the requesting user's own, or a role carrying Administrator/ManageGuild, and the bot's own role-hierarchy position; `allowedMentions` to stop @everyone/role-ping injection from user-supplied content; untrusted content in embeds/DMs (phishing links, markdown masking); interaction vs HTTP-interactions endpoints (signature verification hand-off to `webhook-security`); rate-limit/429 handling and DM spam abuse; Discord OAuth: `state`, minimal scopes, identity keyed on the snowflake user id not username/email, `verified` email flag, token storage and revocation; Discord webhook URLs as bearer secrets.
- **Out of scope:** inbound interaction/webhook signature verification mechanics (in `webhook-security`); generic OAuth flow mechanics (in `oauth-oidc-security`).

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/discord-bot-security/SKILL.md`
- **Files to modify:** `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator dispatches to it for projects using the covered technology.

## ✅ Acceptance
- **Passes when:** the skill fires on a discord.js/Discord OAuth project and gives verified checks and fixes for each covered area with discord.js v14 API names and Discord developer-docs behaviour quoted exactly.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default, version, advisory ID or provider capability is asserted that the vendor docs, RFC or OSV do not confirm; or the freshness check reports drift; or content duplicates a sibling skill instead of cross-referencing it.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Research primary sources (vendor docs, RFCs, OSV/GHSA) and write the skill; every API name, header, default and advisory ID verified live -> target: `skills/discord-bot-security/SKILL.md`
- [ ] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json/marketplace.json description and keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
