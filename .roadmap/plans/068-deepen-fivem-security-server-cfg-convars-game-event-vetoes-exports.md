---
id: 68
title: Deepen fivem-security: server.cfg convars, game-event vetoes, exports
type: feature
version: 3.12.0
status: active
created: 2026-10-17
---

# Plan 68: Deepen fivem-security: server.cfg convars, game-event vetoes, exports
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** close the gaps between skills/fivem-security/SKILL.md and the official Cfx.re guidance (https://docs.fivem.net/docs/developers/server-security/, source citizenfx/fivem-docs content/docs/developers/server-security.md) plus the server-commands reference (https://docs.fivem.net/docs/server-manual/server-commands/). Research 2026-10-17; §5-§10 (NUI, PerformHttpRequest, setr secrets, identifiers) already match the docs — do not rewrite them.
- **Additions, priority order:**
  1. §11 → a grep-table "server.cfg hardening checklist" with exact lines: `sv_pureLevel` (missing/0 = flag; 1 or 2 blocks modified client files); `sv_enableNetworkedSounds` / `sv_enableNetworkedScriptEntityStates` (default true; recommend false unless needed) and `sv_enableNetworkedPhoneExplosions` (default false; true = abuse vector); `sv_netEventReassembly*` incl. `UnlimitedPendingEvents` (per-client memory DoS); `steam_webApiKey` is a secret (link §5 / secaudit:secrets); `sv_devMode` must not be on in production; `sv_filterRequestControlSettleTimer` (modes 1/3); `rateLimiter_*` list incl. netCommand / stateBagFlood / stateBagSize, flag raised values; Cfx anti-cheat convars `sv_kick_players_cnl_timeout_sec`, `sv_kick_players_cnl_update_rate_sec`, `sv_kick_players_cnl_consecutive_failures`, `sv_pure_verify_client_settings`, `sv_authMaxVariance`, `sv_authMinTrust` as "do not weaken defaults" (on by default from build 8450 per the docs); `sv_disableClientReplays` optional (breaks Rockstar Editor); `rcon_password` unset = RCon disabled, UDP. Every convar name + default verified against the server-commands page before writing.
  2. New section "Server-side vetoes: game events and entity creation": `explosionEvent` (OneSync, build 1543+; cookbook https://docs.fivem.net/docs/cookbook/2019/08/19/onesync-intercepting-game-events-such-as-explosions/) with `CancelEvent()`; `entityCreating` + `GetEntityModel` veto; allowlist for model names passed to server `CreateVehicle*`/`CreateObject*`/`CreatePed` from net events. Other native events (`weaponDamageEvent`, `startProjectileEvent`, `removeAllWeaponsEvent`, `ptFxEvent`) only if verified in official docs; otherwise label as community-reported. Absence of handlers is advisory, not a finding.
  3. §1 addition: sensitive `exports(...)` are callable by any server resource — check the caller; `GetInvokingResource()` is nil for net events, so it is not player auth (verify in docs). ACE: flag broad `add_ace group.admin command allow` / `add_principal identifier.* group.admin` in committed cfg, and admin events that compare identifier lists in Lua instead of `IsPlayerAceAllowed`.
  4. §3: one-line warning that the official page's "good" job example has a bug (undefined `ped`; `source` read inside a thread) — copy the pattern, not the code.
  5. Sources: official pages used, https://github.com/TheIndra55/secure-resource-examples (read it first; cite only if relevant). The third-party FiveAI skills catalogue (https://usefiveai.vercel.app/skills) is low-credibility — do not cite as authority.
- **Extension (research 2026-10-18, pyth3rex.github.io 2026-03-24 / 2026-03-26 + official docs):**
  6. HTTP surface: `sv_requestParanoia` row in the §11 table (levels per server-commands docs; ≥2 makes info/dynamic/players.json return "Nope." — trade-off: breaks browser/server-list tooling); an HTTP probe block for `/info.json`, `/players.json`, `/dynamic.json` on the game port checking for `sets` secrets in `vars`, internal resource names, and player identifiers/IPs when `sv_endpointPrivacy` is off (label leak details "verify on a live server" unless confirmed in docs); new `SetHttpHandler` subsection — resource routes are reachable unauthenticated at `http://HOST:30120/<resource>/<path>`; require a constant-time token check against a secret convar, body-size cap, and no `ExecuteCommand`/`PerformHttpRequest` reachable from an unauthenticated route. Verify `SetHttpHandler` docs URL before citing.
  7. NUI hardening in §8: player-writable DB fields (item metadata, evidence notes, vehicle descriptions, report/ticket text) reaching `innerHTML`/`v-html` = stored XSS that fires per viewer, incl. blind XSS in staff report queues; generic NUI callback pass-through that routes to other resources' callbacks/exports by client-supplied name (one XSS reaches every resource); CSP `<meta http-equiv="Content-Security-Policy">` on `ui_page` HTML (missing = advisory). Keep `window.invokeNative` / CEF debug-port OS-escape claims out or explicitly marked unverified research.
  8. Optional one-liners in §3: log/flag default-deny rejections and per-account transfer caps / fan-in anomalies; two-party events check `src ~= target` and target existence.
  - Do not cite supercraft.host, space-node.net (wrong convar advice, e.g. sv_enforceGameBuild described as disabling native calls) or londonstudios.net (unreadable). Cite pyth3rex posts as supporting references only.
- **Out of scope:** web API / Discord sections; framework-specific ESX/QBCore content.

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/fivem-security/SKILL.md, SOURCES.md.

## ✅ Acceptance
- **Passes when:** every convar named has its exact name and default verified against docs.fivem.net (cite page); each check has a runnable grep against server.cfg or resources/; new vetoes section has Lua BAD/GOOD snippets valid for FiveM server Lua; freshness clean (all new URLs 200 without redirect).
- **Fails if:** a convar name/default is wrong, a third-party claim is presented as official, or §5-§10 are rewritten.

## 🚶 Step-by-Step Checklist
- [x] Step 1: server.cfg hardening grep table in §11 -> target: skills/fivem-security/SKILL.md
  > evidence: check-freshness.py: All current; every convar/default verified vs citizenfx/fivem-docs source; exec-order last-wins walker tested on 9 fixtures bash+zsh incl. cycle (terminates), CRLF, BOM, ; joins, quoted names; spec MET; quality PARTIAL x2 -> fixed (loop cap reached; parent re-ran cycle/override fixtures on the extracted script) (2026-10-18)
- [x] Step 2: game-event / entity-creation vetoes section, exports + ACE additions in §1, §3 example warning; sources; freshness green -> target: skills/fivem-security/SKILL.md, SOURCES.md
  > evidence: check-freshness.py: All current; claims verified vs citizenfx/fivem master (event args, routeEvent cancel, entityCreating, POPTYPE, GetInvokingResource, ACE, docs example cfg); greps tested on 2 fixtures bash+zsh; Lua parsed; spec MET; quality PARTIAL -> fixed entityCreating pop-type bypass + 5 grep gaps -> CONFIRMED; parent fixed relaxed-lockdown overclaim (2026-10-18)
- [x] Step 3: HTTP surface — sv_requestParanoia row, info/players/dynamic.json probe block, SetHttpHandler subsection; sources; freshness green -> target: skills/fivem-security/SKILL.md, SOURCES.md
  > evidence: check-freshness.py: All current; d52296e (sv_endpointPrivacy removed 2026-07-08), sv_requestParanoia, info/dynamic/players.json fields, SetHttpHandler API + limiter, bodyless-POST behaviour all verified vs citizenfx/fivem source; walker no regressions; spec MET; quality PARTIAL x2 -> fixed; parent applied last 2 nits (digit-only Content-Length, HTTP/2 note) and re-parsed §13 Lua (2026-10-18)
- [ ] Step 4: NUI hardening — DB fields to innerHTML incl. blind XSS in staff UIs, cross-resource callback pass-through, CSP on ui_page; §3 one-liners; sources; freshness green -> target: skills/fivem-security/SKILL.md, SOURCES.md
