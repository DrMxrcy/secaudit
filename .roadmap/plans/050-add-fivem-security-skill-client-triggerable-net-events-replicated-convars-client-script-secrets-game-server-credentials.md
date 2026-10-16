---
id: 50
title: Add fivem-security skill: client-triggerable net events, replicated convars, client-script secrets, game-server credentials
type: feature
version: 3.10.0
status: done
created: 2026-10-16
---

# Plan 50: Add fivem-security skill: client-triggerable net events, replicated convars, client-script secrets, game-server credentials
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/fivem-security/` for FiveM (CitizenFX) resources and the web/API services a FiveM server talks to: net events registered with `RegisterNetEvent` are triggerable by any connected client with arbitrary arguments, so server handlers must authorize on `source` and validate every argument (classic money/item/admin-event exploits); `setr` replicated convars vs `set` (replicated convars are readable by clients); `client_script`/`shared_script` files are downloaded to players so anything in them (API keys, webhook URLs, endpoints) is public; server-to-web credentials: `PerformHttpRequest` with a per-server, community-scoped API key held server-side only; the web API treating the game server as semi-trusted (validate player identifiers server-side via `GetPlayerIdentifiers`, never accept identifiers asserted by a client event); exposed `sv_licenseKey`, RCON (`rcon_password`) and txAdmin panel exposure; NUI callbacks (`RegisterNUICallback`) as client-controlled input; state bags (`Entity(...).state`, client-writable unless replicated from server); rate limiting chatty events.
- **Out of scope:** Lua/JS coding style; anti-cheat products.

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/fivem-security/SKILL.md`
- **Files to modify:** `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator dispatches to it for projects using the covered technology.

## ✅ Acceptance
- **Passes when:** the skill fires on a FiveM resource (`fxmanifest.lua`) or a service consumed by one and gives verified checks and fixes with CitizenFX native/function names quoted exactly as docs.fivem.net states.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default, version, advisory ID or provider capability is asserted that the vendor docs, RFC or OSV do not confirm; or the freshness check reports drift; or content duplicates a sibling skill instead of cross-referencing it.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Research primary sources (vendor docs, RFCs, OSV/GHSA) and write the skill; every API name, header, default and advisory ID verified live -> target: `skills/fivem-security/SKILL.md`
  > evidence: verifier PARTIAL→fixed: false 'no rate limiter' claim replaced with documented netEvent/stateBag token buckets, setr sv_stateBagStrictMode (12739+), ACL/ip/attribution wording, Lua/Hono code fixes; trimmed to 584 lines; links all current (2026-10-16) (2026-10-16)
- [x] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json/marketplace.json description and keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
  > evidence: registered in audit tiers (31 static tiers) + OWASP 2025 and API Top 10 map, README table, plugin.json/marketplace.json (manifest check clean), sibling cross-refs; SOURCES.md merged; python3 scripts/check-freshness.py: All current (cves, eol, fixclaims, kev, links, manifests, versions) (2026-10-16) (2026-10-16)
- [x] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
  > evidence: registered in audit tiers (31 static tiers) + OWASP 2025 and API Top 10 map, README table, plugin.json/marketplace.json (manifest check clean), sibling cross-refs; SOURCES.md merged; python3 scripts/check-freshness.py: All current (cves, eol, fixclaims, kev, links, manifests, versions) (2026-10-16) (2026-10-16)
