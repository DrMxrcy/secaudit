---
name: fivem-security
description: Audits FiveM (CitizenFX / Cfx.re) server resources (Lua/JS) and the web APIs a FiveM server calls. Covers `RegisterNetEvent` handlers any client can trigger with arbitrary arguments (authorize on `source`, never on an id/identifier argument), server-only events wrongly networked, files `fxmanifest.lua` ships to players, `setr`/`sets` convars, committed `server.cfg` secrets, client-writable state bags, NUI callbacks and XSS, `PerformHttpRequest` keys, txAdmin exposure, `server.cfg` hardening convars, OneSync game-event and `entityCreating` vetoes, privileged `exports` and ACE grants, and the game-facing API (per-community key scoping, cross-community IDOR, idempotent retries). Use whenever the project has `fxmanifest.lua`, `server.cfg`, Lua/JS calling `RegisterNetEvent`/`TriggerServerEvent`/`PerformHttpRequest`, or an API called by a FiveM game server. Hand-offs: secaudit:secrets, secaudit:rate-limiting, secaudit:realtime-security, secaudit:discord-bot-security, secaudit:web-vulns.
license: MIT
---

# FiveM Security (Resources, Server Config, and the Game-Facing API)

A FiveM server is two programs that look like one: server scripts on a machine you control, and
client scripts on every player's PC — a machine the player controls, with cheat tooling attached.
Cfx.re's own security guide states the threat: *"Cheats can allow the client to trigger events in
any context"* — client to server via `TriggerServerEvent`, and client resource to client resource
via `TriggerEvent`. A server handler registered as a net event is an RPC endpoint with no
authentication beyond "is connected", and every argument is whatever the cheater typed.

The recurring AI-codegen failures: (1) a handler that trusts the price, item, target player id, or
`isAdmin` flag the honest client sent in playtesting, so a cheater replays it with
`price = -1000000` or any target; (2) a secret shipped to every player — an API key or Discord
webhook URL in a `client_script`, a `shared_script` config, a NUI page, or a `setr` convar; (3) a
game-facing web API that scopes data by an id in the URL instead of by the API key, so one
community's key reads another's events.

Findings map to OWASP **A01:2025** (unauthorized net events, cross-community IDOR), **A02:2025**
(replicated convars, committed `server.cfg`, exposed txAdmin/RCON), **A05:2025** (XSS in NUI pages),
**A06:2025** (client-authoritative game logic), and **A07:2025** (game-server API keys, identity
taken from event arguments).

## When to Use

- The repo has `fxmanifest.lua` (or legacy `__resource.lua`), `server.cfg`, or a `resources/` tree.
- Writing or reviewing `RegisterNetEvent`/`onNet` handlers, `TriggerServerEvent`/`emitNet` calls,
  NUI callbacks, state bag writes, or `PerformHttpRequest`.
- Reviewing an HTTP API (Hono, Express, Next.js) whose callers are FiveM game servers, including
  SSE/long-poll event streams; configuring convars, ACEs, txAdmin, RCON, or OneSync.

Review grep heuristics:

```bash
# Every networked server event is a public endpoint; audit each handler body
grep -rnE "RegisterNetEvent|onNet\(" --include='*.lua' --include='*.js' resources/
# Handlers taking a player id / identifier / amount from the client instead of using `source`
grep -rnE "RegisterNetEvent\([^,]+,\s*function\s*\((target|player|id|identifier|license|amount|price|money|count)" \
  --include='*.lua' resources/
# Secrets in files that may ship to players; confirm against each fxmanifest.lua
grep -rniE "api[_-]?key|secret|token|bearer|discord(app)?\.com/api/webhooks|Authorization" \
  --include='*.lua' --include='*.js' --include='*.html' --include='*.json' resources/
# Replicated/public convars that look like secrets; committed server.cfg credentials
grep -rniE "^\s*(setr|sets)\s+\S*(key|token|secret|webhook|pass)" --include='*.cfg' .
grep -rnE "sv_licenseKey|rcon_password|mysql_connection_string" --include='*.cfg' .
git ls-files | grep -E '(^|/)server\.cfg$'
# Outbound HTTP, NUI callbacks, and NUI pages rendering HTML
grep -rnE "PerformHttpRequest|RegisterNuiCallback|RegisterNUICallback" --include='*.lua' --include='*.js' resources/
grep -rnE "innerHTML|insertAdjacentHTML|\.html\(|dangerouslySetInnerHTML|v-html" resources/ --include='*.html' --include='*.js'
```

## 1. Net Events Are a Public API — Authorize on `source`, Never on Arguments

**What to look for.** Every `RegisterNetEvent('name', handler)` on the server (or `onNet` in JS).
The reference says it *"Marks the event safe for network use"*; the listening-for-events page says
registration is what lets *"a server event from a client-side script"* reach it; the server-security
guide says cheats trigger events *"in any context"*. Treat each one as callable by any connected
client, any number of times, with any arguments. The event name is not a secret: the client
scripts that call it are downloaded to every player (§4).

The server sets the `source` global to the calling player — the one value in a net event the
client does not supply. The docs add: *"the source is only guaranteed to be valid for the initial
event call. Calling Wait in Lua or awaiting something in JS will cause the global source to be set
back to default."* Copy it into a local first. A handler that takes the target, amount, or role
from its arguments lets the caller pick them.

```lua
-- BAD — the client chooses who gets paid, how much, and claims to be an admin
RegisterNetEvent('bank:deposit', function(targetId, amount, isAdmin)
  local xPlayer = Framework.GetPlayer(targetId)        -- any player, chosen by the caller
  if isAdmin then xPlayer.setJob('police', 4) end      -- client-asserted privilege
  xPlayer.addMoney(amount)                              -- negative / huge / NaN amounts
end)

-- GOOD — identity from `source`, value checked against server-side state
RegisterNetEvent('bank:deposit', function(amount)
  local src = source                                    -- capture before any Wait/await
  if not isPositiveInt(amount, 1, 1000000) then return end
  local player = Framework.GetPlayer(src)
  if not player or player.getAccount('cash') < amount then return end
  player.removeAccountMoney('cash', amount)
  player.addAccountMoney('bank', amount)
end)
```

Admin actions check the caller's permission server-side — the built-in ACL
(`IsPlayerAceAllowed`) or the framework's server-held group — never a flag, job name, or
"password" the client sends.

```lua
RegisterNetEvent('admin:kick', function(targetId, reason)
  local src = source
  if not IsPlayerAceAllowed(src, 'command.kick') then return end
  targetId = tonumber(targetId)
  if not targetId or not DoesPlayerExist(targetId) then return end
  DropPlayer(targetId, ('Kicked: %s'):format(tostring(reason):sub(1, 100)))
end)
```

The JS shape is identical (`onNet('bank:deposit', (amount) => { const src = global.source; ... })`).

**Exports are a second entry point.** `exports('Name', fn)` (or `server_export` in the manifest)
makes a function callable from other resources as `exports.myresource:Name(...)` (Lua runtime docs).
Any server resource can call a server export — including a free script installed last week — so a
privileged export (pay, give item, set job, ban) is an unauthenticated admin API inside your server.
Don't export privileged actions; if you must, check the caller and still validate the arguments.

```lua
-- BAD — any resource can mint money for anyone
exports('addMoney', function(playerId, amount) Framework.GetPlayer(playerId).addMoney(amount) end)

-- GOOD — named callers only, arguments still checked
local CALLERS = { my_jobs = true, my_shops = true }
exports('addMoney', function(playerId, amount)
  if not CALLERS[GetInvokingResource() or ''] then return false end
  if not isPositiveInt(amount, 1, 100000) then return false end
  local player = Framework.GetPlayer(tonumber(playerId))
  if not player then return false end
  player.addMoney(amount)
  return true
end)
```

`GetInvokingResource()` names a **resource, not a player**. Per the source (`ScriptHost.cpp`
`GetInvokingRuntime`, `ResourceScriptFunctions.cpp`) it returns the resource one level down the
script-runtime stack and `nil` when there is none — which is the case inside a net event delivered
from a client. In a net event it can only tell "another server resource called `TriggerEvent`" from
"the network delivered this"; it says nothing about which player sent it or what they may do. An
allowlisted caller that forwards a client's arguments passes the export's check, so that caller must
authorize on `source` itself.

**ACE gates commands and ACE objects, not net events.** `RegisterCommand(name, fn, true)` makes
players *"need the command.yourCommandName ace permission"* (RegisterCommand reference); a net event
has no such gate — the handler must call `IsPlayerAceAllowed(src, '<object>')`. In the source
(`Security.cpp`) ACE objects are hierarchical (`command` covers every `command.*`), a `deny` beats
any `allow`, and every principal also matches `builtin.everyone`.

```lua
-- BAD — a second, hand-rolled admin list (often in a shared config, so public — §4; often has ip: entries — §6)
local ADMINS = { ['license:1a2b3c4d'] = true, ['ip:203.0.113.7'] = true }
RegisterNetEvent('admin:revive', function(targetId)
  for _, id in ipairs(GetPlayerIdentifiers(source)) do
    if ADMINS[id] then return Revive(targetId) end         -- and targetId is unchecked
  end
end)

-- GOOD — one ACL, managed in cfg; the handler asks it
-- server.cfg: add_ace group.admin myadmin.revive allow
RegisterNetEvent('admin:revive', function(targetId)
  local src = source
  if not IsPlayerAceAllowed(src, 'myadmin.revive') then return end
  targetId = tonumber(targetId)
  if not targetId or not DoesPlayerExist(targetId) then return end
  Revive(targetId)
end)
```

In cfg: the docs' own example `server.cfg` ships `add_ace group.admin command allow # allow all
commands`, `add_ace group.admin command.quit deny` and `add_principal identifier.fivem:1 group.admin`,
so a broad `group.admin` grant is the documented baseline, not a finding by itself — what matters is
who is in the group. Flag `add_ace builtin.everyone command allow` (every player gets every command),
`add_ace resource.<x> command allow` or a grant of just `command.add_ace`/`command.add_principal`
(that resource can `ExecuteCommand('add_ace ...')` — admin equivalent, §11), admin principals keyed on `identifier.ip:` (§6), and the docs' placeholder
`identifier.fivem:1` left in. A committed admin roster is not a credential, but it names your admins
and changes to it deserve review; it can live in an `exec`'d untracked file like the secrets (§5, §11).

```bash
# Exports: every one is callable by any server resource — read each for privileged actions
grep -rnE "exports\s*\(\s*['\"]|^\s*server_exports?\s" --include='*.lua' --include='*.js' resources/
grep -rn "GetInvokingResource" --include='*.lua' --include='*.js' resources/   # used as player auth?
# ACL in cfg (and exec'd files, §11): everyone/resource granted every command or an ACL-editing
# command (admin-equivalent); ip / placeholder admins
grep -rniE "^\s*add_ace\s+(builtin\.everyone|resource\.\S+)\s+command(\.(add_ace|remove_ace|add_principal|remove_principal))?\s+allow" --include='*.cfg' .
grep -rniE "^\s*add_principal\s+identifier\.(ip:\S+|fivem:1)\s" --include='*.cfg' .
grep -rniE "^\s*add_principal\s+identifier\.\S+\s+group\." --include='*.cfg' .   # review the roster
# Admin checks against hardcoded identifiers in Lua instead of IsPlayerAceAllowed
grep -rnE "['\"](license2?|steam|discord|fivem|ip):[0-9a-fA-F.]+['\"]" --include='*.lua' resources/
```

## 2. `AddEventHandler` vs `RegisterNetEvent` — Don't Network a Server-Only Event

**What to look for.** Events meant only for other server resources (a job payout, a framework
`addItem` hook) registered with `RegisterNetEvent`. The guide: *"A common mistake is registering
server events that are not supposed to be called by the client"*; use `AddEventHandler` for
same-context events so they are *"not networked and cannot be called by the opposing side."* Because
`RegisterNetEvent` is *"a wrapper"* around `RegisterNetEvent(name)` + `AddEventHandler(name, fn)`, the
server-to-server path keeps working and nobody notices the event became client-callable.

```lua
-- BAD — intended for jobs/server.lua only, but now any client can pay itself
RegisterNetEvent('jobs:payout', function(playerId, amount) ... end)
-- GOOD — local-only; other server resources still TriggerEvent it (or use an export instead)
AddEventHandler('jobs:payout', function(playerId, amount) ... end)
```

On the **client**, the guide's `if source ~= 65535 then return end` (*"server will send net id
`65535` for events from the server"*) rejects calls from other client resources; the guide itself
says it is not bullet-proof. It is not a security boundary.

## 3. Validate Every Argument, Keep the Authority Server-Side, Throttle Chatty Events

**What to look for.** Arguments used without type/range checks; handlers that grant something
because the client said a condition was met; events a client can spam.

The guide lists what to re-check server-side — money, state bags, inventory, position,
experience/level, permissions and roles — and says *"Make sure to retrieve all values using
server-side methods, not allowing players to change the values."* Its bad example is a
`job:givePlayerItem(item, count)` net event that calls `addItem(item, count)` straight from the
arguments. The fix is a server-held state machine: the server records when a job starts, checks
position itself (`GetEntityCoords(GetPlayerPed(src))` — server-side entity state needs OneSync, which
the docs' example `server.cfg` enables), and computes the reward.

The official page's own "good" example is a sketch, not working code: its tick thread calls
`GetPlayerPed(source)` inside `CreateThread`, where `source` is not the player (use the loop's `src`),
and its `job:givePlayerItem` handler passes an undefined `ped` to `isPedWithinRange`. Copy the
pattern, not the code; the version below captures `src` before anything else.

```lua
local active = {}            -- [src] = { startedAt = os.time() }
local JOB_COORD, TURNIN = vector3(125.0, 111.1, 35.8), vector3(1888.0, 1254.1, 48.0)
local function near(src, coords) return #(GetEntityCoords(GetPlayerPed(src)) - coords) < 15.0 end

RegisterNetEvent('job:start', function()
  local src = source
  if near(src, JOB_COORD) then active[src] = { startedAt = os.time() } end
end)
RegisterNetEvent('job:turnIn', function()            -- takes no item, no count
  local src = source
  local job = active[src]
  if not job or not near(src, TURNIN) then return end
  active[src] = nil                                    -- one payout per job, no replays
  FX.GetPlayerFromSource(src).addItem('log', math.min(math.floor((os.time() - job.startedAt) / 60), 10))
end)
AddEventHandler('playerDropped', function() active[source] = nil end)
```

A reusable guard (the runtime is Lua 5.4): reject NaN, infinities, non-integers, and out-of-range
values; cap string length and allowlist names of items, jobs, and models.

```lua
function isPositiveInt(n, min, max)
  return type(n) == 'number' and n == n and n == math.floor(n) and n >= min and n <= max
end
local ALLOWED_ITEMS = { bread = true, water = true }
if type(item) ~= 'string' or not ALLOWED_ITEMS[item] then return end
```

**Throttle per `source`.** FXServer has built-in token-bucket rate limiters (server-commands, "Rate
limiters": `netEvent` 50/s burst 200, `netEventFlood` 75/300, `stateBag` 75/125, tunable with
`set rateLimiter_<name>_rate` / `_burst`). The docs define them per traffic class, not per event or
per resource, so tens of calls a second to your most expensive handler still pass. An event that
writes to a database, calls your web API (§9), or broadcasts with `TriggerClientEvent(name, -1, ...)`
needs its own cooldown keyed by `src` (limiter design: `secaudit:rate-limiting`).

```lua
local last = {}
local function throttled(src, key, ms)
  local now, k = GetGameTimer(), src .. ':' .. key
  if last[k] and now - last[k] < ms then return true end
  last[k] = now
  return false
end
RegisterNetEvent('report:submit', function(text)
  local src = source
  if throttled(src, 'report', 30000) then return end
  ...
end)
AddEventHandler('playerDropped', function()
  local prefix = source .. ':'
  for k in pairs(last) do if k:sub(1, #prefix) == prefix then last[k] = nil end end
end)
```

**Two-party events, rejections, and value caps** (pattern from pyth3rex, 2026-03-24 — supporting):

- An event naming a second player (transfer, give, cuff, revive) normalizes the target and requires
  `target ~= src` and `DoesPlayerExist(target)` before touching either side — and proximity when the
  action is physical (the `near()` check above).
- Every early `return` is a rejection honest play never triggers: log it with `src` and the event
  name, and flag a player who trips several.
- Cap value moved per account per time window, and flag fan-in — many accounts paying one recipient is
  how duped or stolen money is consolidated.

```lua
local function flag(src, event, why)            -- rejections never happen in honest play
  print(('[flag] %s (%s) %s: %s'):format(src, GetPlayerName(src), event, why))
end
RegisterNetEvent('bank:transfer', function(target, amount)
  local src = source
  target = math.tointeger(tonumber(target))     -- msgpack may deliver 3.0; nil on anything else
  if not target or target == src or not DoesPlayerExist(target) or not isPositiveInt(amount, 1, 50000) then
    return flag(src, 'bank:transfer', 'bad target or amount')
  end
  ...
end)
```

```bash
# Two-party net events (heuristic: names and first-argument names vary) — check each for target ~= src + DoesPlayerExist
grep -rnE "RegisterNetEvent\(\s*['\"][^'\"]*(transfer|give|send|pay|cuff|revive|trade|rob)[^'\"]*['\"]\s*,\s*function\s*\(\s*(target|player|id|playerId|targetId|tgt)\b" \
  --include='*.lua' resources/
```

## 4. Everything the Manifest Ships to Players Is Public

**What to look for.** Secrets, internal URLs, or authorization logic in any client-downloaded file.
Per the resource manifest reference:

- `client_script` *"implicitly adds the file to the resource packfile"*; `shared_script` is loaded on
  both sides and *"adds the file to the resource packfile"* — a `config.lua` listed there is
  client-readable, including any key added later.
- `file`/`files`: *"Adds the specified file to the resource packfile, to be downloaded by clients
  upon loading the resource."* `ui_page`/`loadscreen` HTML is referenced via `files` (NUI docs:
  *"every client-side file still needs to be added to the resource packfile!"*) or loaded from an
  external URL — public either way.
- `server_script`'s definition does not add the file to the packfile — keep secrets there.
  `server_only 'yes'` *"stops clients from downloading anything of this resource."*

```lua
-- BAD — fxmanifest.lua; config.lua holds Config.ApiKey and Config.DiscordWebhook
shared_script 'config.lua'
-- GOOD — public values only in the shared file; secrets read server-side from a permissioned convar (§5)
shared_script 'config.lua'
client_script 'client.lua'
server_scripts { 'server/config.lua', 'server/main.lua' }
```

Script directives support globbing (`client_scripts { 'client/*.lua' }`) and the reference's own
`files` example uses a glob — check that none sweeps in a `.env`, a config dump, or server code.

**Asset Escrow is not secret storage.** The docs describe Escrow as protecting code *"by preventing
others from modifying or accessing certain scripts directly"*, supporting Lua, YFT, YDD and YDR
only, with NUI *"not currently supported"* and `escrow_ignore` exclusions. They present it as
licensing/IP protection and say nothing about secrets. Our reasoning: an escrowed client script is
still loaded on the player's machine, so treat any credential it needs as player-reachable.

## 5. Convars: `set` vs `setr` vs `sets`, and Locking Down Who Can Read a Secret

The convars page defines three kinds:

- `set` — *"standard convars can only be used in server-side scripts. They can not be obtained or
  set from a client script."*
- `setr` / `SetConvarReplicated` — *"the convar will be available on the client side to get the
  value"*: every connected player can `GetConvar` it.
- `sets` — *"their name and value will appear on the server connect details/info page, on the
  server list, and will be exposed in the `http://<server_ip>:<server_port>/info.json` server info
  file"*: public to the internet.

```cfg
# BAD — every player can GetConvar these; the sets one is on the public server list
setr game_api_key "fk_live_9f2c..."
sets discord_webhook "https://discord.com/api/webhooks/<id>/<token>"

# GOOD — server.cfg (committed): pull secrets from an untracked file, restrict who reads them
exec secrets.cfg                     # gitignored, chmod 600; contains: set game_api_key "..." / sv_licenseKey "..."
add_convar_permission my_api_bridge read game_api_key
```

The sandbox docs: *"By default, ConVars are readable by all resources. Once a ConVar has at least
one permission configured, it becomes restricted and only explicitly permitted resources can access
it."* Without `add_convar_permission`, any installed resource — including a malicious free script —
can read the key.

The vanilla setup docs put `sv_licenseKey` in `server.cfg` (with a commented `#set rcon_password
""`), so a committed `server.cfg` leaks the license key, RCON password, and any DB string. Move them
to the untracked file and rotate anything ever committed (`secaudit:secrets`).

## 6. Player Identity: Read It on the Server, From `source`

**What to look for.** Events that accept a `license`, `discord`, `steam`, or `identifier` argument;
web API calls whose player identity originates on the client. The server reads identifiers itself:
`GetPlayerIdentifiers(src)` returns all, `GetPlayerIdentifierByType(src, 'license')` one. The
documented types are `steam`, `discord`, `license`, `license2`, `fivem` and `ip`. An identifier that
arrives as an event argument is just a string the client chose.

```lua
-- BAD — the client tells the server whose account to act on
RegisterNetEvent('profile:link', function(license, discordId) linkAccount(license, discordId) end)

-- GOOD — identity derived from source, never accepted as input
RegisterNetEvent('profile:link', function()
  local src = source
  local license = GetPlayerIdentifierByType(src, 'license')
  if not license then return DropPlayer(src, 'Missing license identifier') end
  linkAccount(license, GetPlayerIdentifierByType(src, 'discord'))   -- discord may be nil
end)
```

- Key game accounts on one stable type the server reads itself (commonly `license:`). The docs note
  `license2` *"can be the same value as license"* — not two independent proofs.
- `ip:` is a connection address, not a person (`sv_authMaxVariance` is documented as *"how likely
  the user's id will change for a given provider (i.e. 'steam', 'ip', or 'license')"*). Don't key
  accounts or bans solely on it.
- The docs publish no per-provider spoofability table; `sv_authMinTrust` (1–5, default 1) is the
  owner's knob for *"how unlikely it is for the user's identity to be spoofed by a malicious
  client"*. A resource can't assume it was raised.
- If the **web portal** grants anything on Discord identity (roles, admin, account linking), have
  the user prove it on the portal with Discord OAuth — not the game server's `discord:` alone (§10).

Behind a proxy, `sv_proxyIPRanges` lists ranges allowed to send `X-Real-IP` and *"bypass the rate
limiter"*; its default covers all RFC 1918 ranges and loopback. On shared hosting, narrow it, or
spoofed `X-Real-IP` becomes a spoofed `ip:` (see `secaudit:proxy-trust`).

## 7. State Bags Are Writable by Players Unless You Say Otherwise

**What to look for.** Server logic treating `Player(src).state.x` or `Entity(e).state.x` as a fact
(duty status, handcuffed, owned vehicle, admin), or change handlers that grant something on a flip.

The docs' policy: *"By default player state can be able to be written by the player and the server,
entity state can be written by the owning player and the server, and global state can be written by
the server."* Client sets are not replicated by default, but a client can opt in with
`state:set(key, value, true)`, as the docs' example does. And `AddStateBagChangeHandler`: *"At this
time, the change handler can't opt to reject changes."*

```lua
-- BAD — server trusts a player-writable flag
RegisterNetEvent('armory:take', function(weapon)
  if Player(source).state.onDuty then Framework.GiveWeapon(source, weapon) end
end)
-- GOOD — authority in a server table (or the framework's server-side object); state bags mirror it
local onDuty = {}                         -- [src] = true, set only by a server-verified clock-in
RegisterNetEvent('armory:take', function(weapon)
  local src = source
  if not onDuty[src] or not ARMORY_WEAPONS[weapon] then return end
  ...
end)
```

`setr sv_stateBagStrictMode true` (server version 12739+) means *"Only the server can modify the
state of networked entities and the player state"*; *"Client-side (non-replicated) entities are not
affected by this variable."* Enable it when no resource depends on client writes; otherwise treat
client-writable values as client input. A server change handler reacting to a client write is a
net event by another name — validate it, and remember it cannot veto. Entity *creation* can be vetoed (§12).

## 8. NUI: Callbacks Are Client Input, Pages Are Public, Player Strings Are XSS

NUI runs in Chromium Embedded Framework on the player's machine, and the docs state *"CEF remote
debugging tools are exposed on `http://localhost:13172/` as long as the game is running."* The
player can read every NUI file, call any NUI callback (`fetch('https://<resource>/<callback>')`) with
any JSON, and edit page state. A NUI callback is the client talking to itself; the security decision
stays in the server net event it triggers (§1–3). Grep both `RegisterNuiCallback` (the docs' name)
and `RegisterNUICallback` (common in resources).

```lua
-- BAD — NUI decides the price; the server believes it
RegisterNuiCallback('buy', function(data, cb)
  TriggerServerEvent('shop:buy', data.item, data.price); cb({ ok = true })
end)
-- GOOD — NUI sends only the choice; the server looks the price up
RegisterNuiCallback('buy', function(data, cb)
  if type(data.item) == 'string' and #data.item <= 32 then TriggerServerEvent('shop:buy', data.item) end
  cb({ ok = true })                   -- always answer, or the page's fetch stalls (per the docs)
end)
```

**No backend key in NUI.** `PerformHttpRequest` is listed under server-side Lua functions, so
resources sometimes call the web API from the NUI page with `fetch` and an embedded key — which is
then public (§4). Route it through a server event that authorizes on `source`.

**Stored and blind XSS from player-written data.** Anything a player wrote and the server stored —
item metadata and labels, evidence notes, vehicle descriptions and plates, gang tags, report and
ticket text, character bios, chat — reaches *other* players' NUI through `SendNUIMessage`. Rendered
with `innerHTML`/`insertAdjacentHTML`/jQuery `.html()` or `.append('<…>')`/`v-html`/
`dangerouslySetInnerHTML`, it runs script in every viewer's frame, where it can call that resource's
NUI callbacks as the victim. The attacker can be offline; the payload travels with the item. Staff
tools — report queues, admin panels, MDT/CAD-style screens that list other players' text — are the
high-value case: **blind XSS** fires in a staff member's client and calls staff-only callbacks whose
server events trust that staff `source`. (A worked case of item-metadata and report-queue XSS:
pyth3rex, 2026-03-26 — supporting reference.) Use `textContent` or the framework's default escaping
(`{{ }}` in Vue, JSX text in React). If rich text is genuinely needed, sanitize on the server when it
is written and with a sanitizer at render (`secaudit:rich-text-security`), and cap length on write (§3).
XSS fundamentals: `secaudit:web-vulns`.

```js
row.innerHTML = `<td>${player.name}</td>`;                                         // BAD
const td = document.createElement('td'); td.textContent = player.name; row.append(td); // GOOD

$('#tickets').append(`<li>${t.author}: ${t.body}</li>`);           // BAD — staff panel, player-written body
$('<li>').text(`${t.author}: ${t.body}`).appendTo('#tickets');      // GOOD
```

**Callback routers widen one XSS to everything.** A generic NUI callback that triggers whatever event
or export the page names turns an XSS in *any* page that can reach it into a call to every server
event and export it can name.

```lua
-- BAD — the page chooses the event and its arguments
RegisterNUICallback('ui:call', function(data, cb)
  TriggerServerEvent(data.event, table.unpack(data.args or {}))
  cb({ ok = true })
end)

-- GOOD — fixed routes, each with its own argument checks (the server events still authorize on source, §1)
local MAX_SLOTS = 50
local ROUTES = {
  ['inventory:use'] = function(d)
    local slot = math.tointeger(d.slot)
    if slot and slot >= 1 and slot <= MAX_SLOTS then TriggerServerEvent('inventory:use', slot) end
  end,
  ['phone:call'] = function(d)
    if type(d.number) == 'string' and #d.number <= 10 then TriggerServerEvent('phone:call', d.number) end
  end,
}
RegisterNUICallback('ui:call', function(data, cb)
  local route = type(data) == 'table' and ROUTES[data.action] or nil
  if route then route(data) end
  cb({ ok = route ~= nil })
end)
```

**Which frame can call a callback.** The docs: *"The NUI system registers a `https://cfx-nui-`
protocol scope for resource files"* (formerly `nui://`), callbacks are `fetch`ed from
`` `https://${GetParentResourceName()}/<name>` ``, and resources *"are currently implemented as
full-screen iframes"*. In the source (`ResourceUI.cpp`) a `fx_version 'cerulean'`-or-later page loads
from `https://cfx-nui-<resource>/<page>`, so each resource's page is its own origin and cannot read
another's DOM — unless a central UI or notification resource renders everyone's data in one frame,
which puts all of its callbacks behind any XSS in it. The callback handler checks the caller's origin
only when the manifest opts in with `nui_callback_strict_mode 'true'` (source, commit `ef3d8e0`,
2024-08; read from the resource's single `ui_page` — a second `ui_page` already stops the UI loading; not on the docs' manifest page — verify on your client build):
then it accepts only `Origin: https://cfx-nui-<same resource>` (or `nui://<same resource>`), and an
externally hosted `ui_page` would be blocked too. Without it, a request from another resource's frame
is not rejected by origin. Missing strict mode is advisory.

**CSP on `ui_page`.** NUI's scheme handler sends no CSP header (`NUISchemeHandler.cpp` sets content
type, CORS and cache headers only), so a policy has to be a `<meta http-equiv>` in the page; missing
is advisory. It blocks injected inline script and `onerror=` handlers and stops exfiltration to other
hosts, but not a payload that only abuses allowed sinks. Inline `<script>` blocks must move to files
(or use hashes). Policy basics: `secaudit:deployment`.

```html
<!-- resource "inventory" — connect-src must name the callback host https://<resource> -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src https://inventory;
  object-src 'none'; base-uri 'none'; form-action 'none'">
```

Chromium's CSP parser accepts only letters, digits and `-` in a host (`content_security_policy.cc`),
so a resource named with `_` cannot be listed in `connect-src`/`img-src` — the source is dropped and
callbacks break. Rename it with `-`, or fall back to `connect-src https:` (weaker: any HTTPS host).
List each other resource whose images you load (`https://cfx-nui-<name>`); there is no `cfx-nui-*`
wildcard. Test the page in game after adding the policy.

Kept out deliberately: claims that NUI XSS escalates through `window.invokeNative` or the CEF debug
port to the player's OS are unverified research here (described in pyth3rex, 2026-03-26), not
something this skill asserts.

```bash
# HTML sinks in NUI code (heuristic first pass: noisy, and not exhaustive) — then trace whether the
# value comes from SendNUIMessage data (server/DB/other players). `.html()` with no argument is a getter, skipped.
grep -rnE "innerHTML|outerHTML|insertAdjacentHTML|document\.write|setHTMLUnsafe|createContextualFragment|\.srcdoc\s*=|setAttribute\(\s*['\"]on|eval\(|new Function\(|\.html\(\s*[^)[:space:]]|\.(append|prepend|before|after|replaceWith)\(\s*([\`'\"]\s*<|[A-Za-z_\$])|\\\$\(\s*(['\"]\s*<.*\+|\`[^\`]*\\\$\{)|v-html|dangerouslySetInnerHTML|\{@html" \
  --include='*.html' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx' --include='*.vue' --include='*.svelte' resources/
# Callback routers: within 8 lines of a NUI callback registration (longer bodies need reading), an
# event whose name is a variable or a concatenation, or an export indexed by a variable
grep -rnE -A8 "RegisterNU[Ii]Callback" --include='*.lua' resources/ \
  | grep -E "Trigger(Server)?Event\(\s*([A-Za-z_][A-Za-z0-9_.]*\s*[,)]|[^)]*\.\.)|exports\[\s*[A-Za-z_]"
# JS fetching a callback on a page-chosen resource (template or concatenation)
grep -rnE "fetch\(\s*(\`https?://\\\$\{|['\"]https?://['\"]\s*\+)" --include='*.js' --include='*.ts' --include='*.vue' --include='*.html' resources/ \
  | grep -v GetParentResourceName
# ui_page without a CSP meta tag or callback strict mode (both advisory; if the built page isn't committed, check its source HTML)
grep -rlE "^[[:space:]]*ui_page" --include='fxmanifest.lua' resources/ | while IFS= read -r m; do
  d=$(dirname "$m"); pg=$(sed -nE "s/^[[:space:]]*ui_page[[:space:](]*['\"]([^'\"]+)['\"].*/\1/p" "$m" | head -n 1)
  case $pg in *://*) echo "EXTERNAL ui_page: $m -> $pg"; continue;; esac
  grep -qi 'Content-Security-Policy' "$d/$pg" 2>/dev/null || echo "ADVISORY no CSP (or page not in repo): $d/$pg"
  grep -qE "nui_callback_strict_mode[[:space:](]*['\"]true" "$m" || echo "ADVISORY no nui_callback_strict_mode: $m"
done
```

## 9. Server → Web API: `PerformHttpRequest` With a Server-Held, Community-Scoped Key

**What to look for.** URL, key, or headers built from client input; the key in a client file,
replicated convar, or log line; `http://` base URLs; ignored errors; one key across communities.

`PerformHttpRequest(url, cb, method, data, headers, options)` is server-side; its callback gets
`(statusCode, body, headers, errorData)` and its reference shows `options = { followLocation = true }`
as the default. The option's definition comes from the `PerformHttpRequestAwait` page (server build
9515+): *"Makes cURL follow the redirects of the URL"*.

```lua
-- BAD — client chooses the endpoint; key from a replicated convar; key printed on error
RegisterNetEvent('api:sync', function(path, body)
  local key = GetConvar('game_api_key', '')                    -- set with setr → public
  PerformHttpRequest('http://api.example.com' .. path, function(code, res)
    print('sync failed', code, key, res)                       -- key lands in console logs
  end, 'POST', body, { ['Authorization'] = 'Bearer ' .. key })
end)

-- GOOD — fixed HTTPS base, server-held key, server-built body, no redirects, errors handled
local API_BASE = 'https://api.example.com/v1/game'
local API_KEY  = GetConvar('game_api_key', '')                 -- plain `set` + add_convar_permission
if API_KEY == '' then error('game_api_key not set; refusing to start') end

local function apiPost(path, payload, onDone)
  PerformHttpRequest(API_BASE .. path, function(status, body, _headers, err)
    if status < 200 or status >= 300 then
      print(('[api] %s failed: %s %s'):format(path, tostring(status), tostring(err)))  -- no key
      return onDone(false)
    end
    onDone(true, json.decode(body))
  end, 'POST', json.encode(payload), {
    ['Authorization'] = 'Bearer ' .. API_KEY,
    ['Content-Type']  = 'application/json',
    ['Idempotency-Key'] = payload.requestId,                   -- same id on retry (§10)
  }, { followLocation = false })                               -- your API never needs to redirect
end

RegisterNetEvent('report:submit', function(text)
  local src = source
  if type(text) ~= 'string' or #text == 0 or #text > 500 then return end
  apiPost('/reports', {
    requestId = ('%d-%d-%d'):format(os.time(), src, math.random(1, 1000000000)),
    license   = GetPlayerIdentifierByType(src, 'license'),     -- identity read server-side (§6)
    text      = text,
  }, function() end)
end)
```

One key per game server or community; HTTPS only; paths constant or from a server-side allowlist —
a URL built from player input is SSRF from your game server (`secaudit:web-vulns`). Bound retries
with backoff and reuse the `requestId`.

**Discord webhooks.** A webhook URL embeds its token, and Discord's docs say webhooks *"do not
require a bot user or authentication to use"*; Get/Modify/Delete Webhook with Token also need no
auth. Call it only from `server_script` code with the URL in a permissioned convar, never from a
client script, shared config, or NUI (`secaudit:discord-bot-security`; rotation: `secaudit:secrets`).

## 10. The Web API Side: Treat Each Game Server as Semi-Trusted

A game server holding a valid key is authenticated, but a community you don't control runs it, its
operators can read the key, and its resources may be compromised. Design for **blast radius**: a
stolen key touches only its own community's data, and nothing a game server asserts escalates into
the web portal.

**Key storage and lookup.** A random secret with a non-secret lookup prefix; store only the SHA-256
of the full key (fine for high-entropy random keys, never for passwords — `secaudit:cryptography`).
Look up by prefix, compare in constant time, check revocation and expiry on every request.

```ts
// Hono 4 — game API key middleware
import { createMiddleware } from 'hono/factory';
import { createHash, timingSafeEqual } from 'node:crypto';

type GameEnv = { Variables: { communityId: string; serverId: string; keyId: string } };

export const gameAuth = createMiddleware<GameEnv>(async (c, next) => {
  const raw = c.req.header('authorization')?.replace(/^Bearer /, '') ?? '';
  const m = /^fk_live_([a-z0-9]{8})_([A-Za-z0-9_-]{32,})$/.exec(raw);
  if (!m) return c.json({ error: 'unauthorized' }, 401);
  const key = await db.gameKeys.findByPrefix(m[1]);      // indexed, non-secret prefix
  const presented = createHash('sha256').update(raw).digest();
  const stored = key ? Buffer.from(key.sha256, 'hex') : Buffer.alloc(32);
  const hashOk = timingSafeEqual(presented, stored);     // both 32 bytes; runs even if no key
  if (!key || !hashOk || key.revokedAt || (key.expiresAt && key.expiresAt <= new Date()))
    return c.json({ error: 'unauthorized' }, 401);
  const k = key;                                          // narrowed: non-null from here on
  c.set('communityId', k.communityId);                   // tenant comes from the KEY
  c.set('serverId', k.serverId);
  c.set('keyId', k.id);
  await next();
});
```

**Scope every query by the key's community — never by a path or body id.**

```ts
// BAD — community chosen by the caller: any valid key reads any community (IDOR)
app.get('/v1/game/communities/:communityId/events', gameAuth, async (c) =>
  c.json(await db.events.list({ communityId: c.req.param('communityId') })));

// GOOD — tenant from the authenticated key; per-object lookups filter by it too
app.get('/v1/game/events', gameAuth, async (c) =>
  c.json(await db.events.list({ communityId: c.var.communityId, after: c.req.query('after') })));
app.post('/v1/game/players/:license/ban', gameAuth, async (c) => {
  const player = await db.players.find({ communityId: c.var.communityId, license: c.req.param('license') });
  if (!player) return c.json({ error: 'not found' }, 404);   // other communities' players don't exist here
  ...
});
```

The **SSE / long-poll stream** follows the same rule: filter by `c.var.communityId`, and treat a
resume cursor (`Last-Event-ID`, `?after=`) as a position *within* that community's stream
(`WHERE community_id = $1 AND id > $2`). Connection caps and auth-on-reconnect:
`secaudit:realtime-security`.

**Validate what the game server sends** with a schema (`secaudit:data-access`): identifiers match
their `type:value` shape, amounts are bounded integers, text is length-capped. The API trusts a game
server for *its own* players only; linking a `discord:` id to a portal account, granting portal
roles, or moving value between communities must be confirmed by the user on the portal (Discord
OAuth / portal session), not by a game-server call alone.

**Idempotency.** `PerformHttpRequest` callers time out and retry; a non-idempotent `POST /payouts`
double-pays. Require an idempotency key on state-changing calls and enforce it in the database:

```sql
CREATE UNIQUE INDEX game_requests_idem ON game_requests (community_id, idempotency_key);
-- insert the request row first; on unique violation, return the stored response instead of re-running
```

**Rate limit, rotate, revoke.** Limit by `keyId`, not IP (communities share hosting providers), with
tighter write limits (`secaudit:rate-limiting`). Allow several active keys per server for zero-downtime
rotation, show `lastUsedAt`, make revocation immediate (no long-lived cache of valid keys), and log
key id + community — never the raw key.

## 11. Server Operations: txAdmin, RCON, and the `server.cfg` Hardening Checklist

- **txAdmin** ships with FXServer; `txAdminPort` defaults to **40120** and `txAdminInterface` to
  **`0.0.0.0`** (every interface). Its in-game menu includes spawn, teleport, heal and ban. Firewall
  40120 to admin IPs/VPN or bind to `127.0.0.1` behind an SSH tunnel; otherwise only its login
  (password or CitizenFX) and brute-force protection stand in the way.
- **ACL** — grant resources only the commands they need (`add_ace resource.x command.y allow`). The
  ACL cookbook shows a resource granted `command.add_ace`/`command.add_principal` rewriting the ACL
  at runtime via `ExecuteCommand`; treat those grants as admin-equivalent.
- The sandbox blocks cross-resource file writes, `os.execute`, and child processes by default;
  each `add_filesystem_permission`, `add_unsafe_worker_permission`, or
  `add_unsafe_child_process_permission` in `server.cfg` is a finding to justify.

**The convar checklist.** Audit `server.cfg` *and every file it `exec`s* — `exec` *"Runs the
commands specified in the filename, relative to the server data directory, or any resource name
specified with `@`"* (`exec @vMenu/config/permissions.cfg`), so a setting can live inside a resource.
When a convar is set twice, the later command wins, so judge each convar by its *effective* value —
the last assignment in `exec` order — not by whether a good line exists somewhere (the script below
resolves this). A convar line may be bare (`sv_pureLevel 1`) or prefixed with `set`/`setr`/`sets`
(§5). FXServer parses booleans as `true`/`false` in any case, otherwise as an integer (non-zero,
even `-1`, is true; anything unparseable is false — `Console.Commands.h`), so `1`/`0` count the same as
`true`/`false`. Sources: **[cmds]** =
server-commands page, **[sec]** = server-security page ("Server owner options"), **source** = the
citizenfx/fivem files listed in Sources. Defaults are quoted
only where the docs state one.

| Convar | Safe value / what to flag | Why | Source |
| --- | --- | --- | --- |
| **Client integrity** | | | |
| `sv_pureLevel` | `1` or `2`; flag missing or `0` (advisory) | `1` *"Will block all modified client files except audio files and known graphics mods"*, `2` *"Will block all modified client files"*. Only levels 1 and 2 are documented; the page names no default. `2` can break players' graphics mods — owner's call. | [cmds] |
| `sv_scriptHookAllowed` | default `false`; flag `true` | Lets Script Hook V clients connect — *"Not recommended - makes the server vulnerable to security issues."* | [cmds] |
| `sv_disableClientReplays` | optional; enabling is a hardening choice, absence is not a finding | *"Enabling this will aim to reduce chances of cheating options"*; it also *"will disable Rockstar Editor"*. No default stated. | [sec] |
| **Networked-event abuse** | | | |
| `sv_enableNetworkedSounds` | default `true`; recommend `false` unless a resource needs networked sounds (advisory) | Stops clients routing `NETWORK_PLAY_SOUND_EVENT` through the server, *"which is commonly used by malicious actors."* | [cmds] |
| `sv_enableNetworkedScriptEntityStates` | default `true` (server 8540+); recommend `false` unless needed (advisory) | Same, for `SCRIPT_ENTITY_STATE_CHANGE_EVENT`, *"commonly used by malicious actors."* | [cmds] |
| `sv_enableNetworkedPhoneExplosions` | default `false` (server 6831+); flag `true` | `true` routes `REQUEST_PHONE_EXPLOSION_EVENT`; the drawback is that *"it can also be used by malicious actors."* | [cmds] |
| `sv_netEventReassemblyUnlimitedPendingEvents` | default `false`; flag `true` | Allows *"unlimited pending reassembled events per client"* and overrides the cap below. Our reading: one client can then make the server hold unbounded partial events in memory. | [cmds] |
| `sv_netEventReassemblyMaxPendingEvents` | default `100` (range 0-254); flag a raised value | Per-client cap on pending reassembled events; the docs: *"decrease to limit memory usage."* `sv_enableNetEventReassembly` (default `true`) is the feature switch, not a security setting. | [cmds] |
| **Entity and state control** | | | |
| `sv_entityLockdown` | `strict` or `relaxed`; flag default `inactive` (advisory); `full` is a review item | `inactive`: *"Clients can create any entity."* `strict`: *"No entities can be created by clients"*; `relaxed` blocks only client-created script-owned entities. `full` *"Disables dummy object creation. Only usable on FiveM for GTAV Enhanced"* — the docs don't say it also blocks client entities, and the server source's lockdown checks (including the control-request filter) test for `strict` exactly, so don't count `full` as `strict`. The public source's parser (`OneSyncVars.h`) accepts `strict`, `relaxed`, `no_dummy` (allows everything except dummy objects) and `inactive`/`false`/`off` — not `full` — so on a non-Enhanced build confirm the value took effect in the server console. | [cmds], source |
| `sv_filterRequestControl` | non-zero, e.g. `2`; missing or `0` is advisory only | Default `0` is off. `1` blocks control requests to player-controlled entities (*"currently, occupied vehicles only"*) once "settled" (older than the settle timer); `2` *"Blocks control requests to all entities controlled by players"*; `3` blocks all player-controlled entities regardless of age plus settled non-player entities; `4` routes no `REQUEST_CONTROL_EVENT` at all; `-1` = `2` plus a console warning. Any non-off mode also stops control requests across routing buckets and always blocks senders in `strict` lockdown. [sec] puts this convar in its *"shouldn't be touched unless you know what you are doing"* group, so recommending non-zero is our judgement (it can break resources that take control of player entities) — hence advisory, not a finding. | [cmds], [sec] |
| `sv_filterRequestControlSettleTimer` | default `30000` **milliseconds**; only matters with modes `1`/`3`; flag a raised value | Entities younger than the timer are not yet "settled": mode `1` leaves them open (occupied vehicles), mode `3` leaves only *non-player* entities open (player-controlled ones are always blocked in 3). Our reading: a larger value widens that window. The argument *"must be provided in milliseconds."* | [cmds] |
| `sv_stateBagStrictMode` | `true` (server 12739+) when no resource needs client writes (advisory) | Default `false`: the network owner can modify its entities' and its player state. `true`: *"Only the server can modify the state of networked entities and the player state"* (§7). The docs show `setr`; the server registers its own non-replicated copy (`ServerGameState.cpp`), so a plain `set` still reaches the server-side check, and `setr` also tells clients, which then refuse writes locally with the documented console error. | [cmds], source |
| **Rate limiting** | | | |
| `rateLimiter_<name>_rate` / `_burst` | flag any value raised above the documented default | Token buckets per traffic class (rate/burst): `netEvent` 50/200, `netEventFlood` 75/300, `netCommand` 7/14, `netCommandFlood` 25/45, `netCommandSize` 1024/8192, `stateBag` 75/125, `stateBagFlood` 150/175, `stateBagSize` 131072/262144, `rcon` 2/5, `handshake` 4/10, `handshakeUDP` 1/5, `challenge` 4/10, `resourceList` 10/25, `res_http_handler` 10/25, `http_info`/`http_dynamic`/`http_players` 4/10, `http_perf` 2/5. Raising one to silence a chatty resource removes flood protection for every client — fix the resource. These are not per-event limits (§3). | [cmds] |
| `sv_requestParanoia` | optional `1`/`2`/`3`; `0` (default) is advisory only | Docs: *"This helps counter proxy-based HTTP floods"* — `1` blocks IPs sending a `Via` header, `2` also `Upgrade-Insecure-Requests` (*"all browser-based attempts at requesting .json endpoints, so use with care"*), `3` also closes the socket. In the source (`InfoHttpHandler.cpp`) a matching request to `/info.json`, `/players.json` or `/dynamic.json` gets `403 Nope.` **and its peer is blocked** (`BlockPeer`); level `3`'s socket close applies to `/info.json` and `/players.json` only, not `/dynamic.json`; requests without those headers are served normally — the docs' "all requests ... will return Nope." overstates it. Trade-off: `1` blocks a reverse proxy or CDN that adds `Via`; `2` blocks browser-based tools and dashboards that fetch the JSON (§13). | [cmds], source |
| `sv_proxyIPRanges` | narrow to your real proxies | Default `10.0.0.0/8 127.0.0.0/8 192.168.0.0/16 172.16.0.0/12`; listed ranges may send `X-Real-IP` and bypass the rate limiter (§6). | [cmds] |
| **Secrets, privacy, and dev settings** | | | |
| `steam_webApiKey` | never in a committed cfg; never `setr`/`sets` | A Steam Web API key (*"required to allow for Steam identifiers to be returned by the server"*) is a credential: put it in the untracked `exec`'d secrets file (§5, `secaudit:secrets`). A launch-time `+set steam_webApiKey "$STEAM_WEB_API_KEY"` (the same `+` syntax as the docs' `FXServer.exe +exec server.cfg`; `%STEAM_WEB_API_KEY%` in Windows `cmd`; under txAdmin, its additional-arguments setting) keeps it out of git but is visible in the host's process list. Rotate any key ever committed. | [cmds] |
| `sv_licenseKey`, `sv_tebexSecret`, `sv_prometheusBasicAuthPassword`, `sv_playersToken` | same as `steam_webApiKey` | License key, the Tebex server-authentication secret, the `/perf` basic-auth password (*"Also sent to txAdmin"*), and the token that unlocks player names and identifiers on `/players.json` (source; §13). | [cmds], source |
| `rcon_password` | unset unless needed; if set, long and random, from the secrets file | *"if unset then RCon will be disabled. FXServer RCon uses UDP."* The documented `rcon` limiter (2/s, burst 5) throttles guessing. | [cmds] |
| `sv_devMode` | default `false`; flag `true` | Enables dev mode for joining clients and caps clients at 8 — *"Do not enable in production."* | [cmds] |
| `sv_endpointPrivacy`, `sv_exposePlayerIdentifiersInHttpEndpoint` | older builds: flag `sv_endpointPrivacy false` or `sv_exposePlayerIdentifiersInHttpEndpoint true`; current builds: both are deprecated no-ops — remove them | Docs: `sv_endpointPrivacy` *"hides player IP addresses from public reports"*. Source: until commit `d52296e` (2026-07-08) it defaulted to `true` (`false` put real IPs in `/players.json` and kept `ip:` identifiers), and public identifiers needed `sv_exposePlayerIdentifiersInHttpEndpoint true` (default `false`). Since then both are removed in effect: they still exist as no-op variables (default `false`) and the server logs a deprecation warning only when one is set to `true`; public `/players.json` is anonymized (§13). The docs page has not caught up; check which you run. | [cmds], source |
| **Cfx anti-cheat defaults — do not weaken** | | | |
| `sv_kick_players_cnl_timeout_sec`, `sv_kick_players_cnl_update_rate_sec`, `sv_kick_players_cnl_consecutive_failures` | leave unset; flag any override, especially a raised timeout or failure count | CnL check-in kicks (*"Connection to CNL timed out."*). The docs give `600` = 10 minutes as an example timeout and `2` as the consecutive-failures default; no other defaults stated. | [sec] |
| `sv_pure_verify_client_settings` | leave unset; flag an override that disables it | Verifies *"some of the `sv_settings` such as pureLevel, scripthook and other settings"* over the `adhesive`<->`svadhesive` connection. | [sec] |
| `sv_authMaxVariance`, `sv_authMinTrust` | report the value; no finding at default | Defaults `5` and `1` (range 1-5) are already the most permissive, so these can only be tightened, which may lock out players. Resources must not assume they were raised (§6). | [cmds], [sec] |

[sec] says these anti-cheat options *"shouldn't be touched unless you know what you are doing"* and
that *"You will have most of those features enabled by default with FXServer `8450` build version
and higher."*

```bash
# Run from the server data dir. Walk server.cfg in exec order (any extension; `exec @res/x.cfg`
# = x.cfg inside resource `res`) and emit every assignment: name<TAB>value<TAB>set|setr|sets<TAB>file:line.
# The LAST assignment of a name is the effective value. Cfg files never exec'd don't count, and a
# `grep -r` hit is not proof of the effective value. MISSING = not in the repo (often the
# untracked secrets file - good - but unaudited here).
ALL=$(awk -v bom="$(printf '\357\273\277')" '
function walk(f, depth,   l, ln, j, m, q, ch, c, part) {
  if (depth > 8 || f in stk) { print "CYCLE exec " f > "/dev/stderr"; return }
  if (system("test -f \"" f "\"")) { print "MISSING exec " f > "/dev/stderr"; return }
  stk[f] = 1                                         # on the exec stack: blocks exec loops
  while ((getline l < f) > 0) {
    ln++; sub(/\r$/, "", l); if (index(l, bom) == 1) l = substr(l, length(bom) + 1)   # BOM
    m = 0; q = 0; c = ""                             # split on ; outside quotes
    for (j = 1; j <= length(l); j++) { ch = substr(l, j, 1); if (ch == "\"") q = !q
      if (ch == ";" && !q) { part[++m] = c; c = "" } else c = c ch }
    part[++m] = c
    for (j = 1; j <= m; j++) one(part[j], f, ln, depth)
  }
  close(f); delete stk[f]                            # a later, non-nested exec of f walks it again
}
function one(l, f, ln, depth,   n, a, k, i, v, d, r, cmd) {
  sub(/^[ \t]+/, "", l)
  if (l == "" || l ~ /^(#|\/\/)/) return
  n = split(l, a, /[ \t]+/); k = tolower(a[1])
  if (k == "exec") {
    d = a[2]; gsub(/"/, "", d)
    if (d ~ /^@/) {
      r = ""; cmd = "find . -type d -name \"" substr(d, 2, index(d, "/") - 2) "\" | head -n 1"
      cmd | getline r; close(cmd); if (r != "") d = r substr(d, index(d, "/"))
    }
    walk(d, depth + 1); return
  }
  i = (k ~ /^set[rs]?$/) ? 2 : 1                    # convar name position
  v = ""; if (n > i) { v = l; sub(/^[^ \t]+[ \t]+/, "", v); if (i == 2) sub(/^[^ \t]+[ \t]*/, "", v) }
  if (v ~ /^"/) { v = substr(v, 2); sub(/".*/, "", v) } else sub(/[ \t].*/, "", v)
  gsub(/"/, "", a[i])
  print tolower(a[i]) "\t" v "\t" (i == 2 ? k : "") "\t" f ":" ln
}
BEGIN { walk("server.cfg", 0) }')
val() { printf '%s\n' "$ALL" | awk -F'\t' -v k="$(printf %s "$1" | tr A-Z a-z)" '$1 == k { v = $2 } END { print v }'; }
# FXServer bools: "true"/"false" any case, else a leading integer != 0 (even -1) is true, else false
on() { v=$(val "$1"); [ -n "$v" ] || v=$2
  case $(printf %s "$v" | tr A-Z a-z) in true) return 0;; -[0-9]*|[0-9]*) n=${v#-}; [ "${n%%[!0-9]*}" -ne 0 ];; *) return 1;; esac; }
# Client integrity
case $(val sv_pureLevel) in 1|2) ;; *) echo "ADVISORY: sv_pureLevel='$(val sv_pureLevel)' (want 1 or 2)";; esac
on sv_scriptHookAllowed false && echo 'FLAG: sv_scriptHookAllowed on'
on sv_disableClientReplays false && echo 'info: sv_disableClientReplays on (Rockstar Editor disabled)'
# Networked-event abuse (first two default true)
on sv_enableNetworkedSounds true && echo 'ADVISORY: sv_enableNetworkedSounds on'
on sv_enableNetworkedScriptEntityStates true && echo 'ADVISORY: sv_enableNetworkedScriptEntityStates on'
on sv_enableNetworkedPhoneExplosions false && echo 'FLAG: sv_enableNetworkedPhoneExplosions on'
on sv_netEventReassemblyUnlimitedPendingEvents false && echo 'FLAG: sv_netEventReassemblyUnlimitedPendingEvents on'
[ "$(val sv_netEventReassemblyMaxPendingEvents)" -gt 100 ] 2>/dev/null && echo 'FLAG: sv_netEventReassemblyMaxPendingEvents > 100'
# Entity and state control
case $(val sv_entityLockdown | tr A-Z a-z) in strict|relaxed) ;; *) echo "ADVISORY: sv_entityLockdown='$(val sv_entityLockdown)'";; esac
case $(val sv_filterRequestControl) in -1|1|2|3|4) ;; *) echo "ADVISORY: sv_filterRequestControl off";; esac
[ "$(val sv_filterRequestControlSettleTimer)" -gt 30000 ] 2>/dev/null && echo 'FLAG: sv_filterRequestControlSettleTimer > 30000 ms'
on sv_stateBagStrictMode false || echo 'ADVISORY: sv_stateBagStrictMode off (§7)'
# Rate limiting: effective values above the documented defaults; proxy ranges to review
printf '%s\n' "$ALL" | awk -F'\t' 'BEGIN { n = split("challenge 4 10 handshake 4 10 handshakeudp 1 5 http_dynamic 4 10 http_info 4 10 http_perf 2 5 http_players 4 10 netcommand 7 14 netcommandflood 25 45 netcommandsize 1024 8192 netevent 50 200 neteventflood 75 300 rcon 2 5 res_http_handler 10 25 resourcelist 10 25 statebag 75 125 statebagflood 150 175 statebagsize 131072 262144", d, " ")
  for (i = 1; i < n; i += 3) { def["ratelimiter_" d[i] "_rate"] = d[i+1]; def["ratelimiter_" d[i] "_burst"] = d[i+2] } }
  $1 in def { e[$1] = $2 } END { for (k in e) if (e[k] + 0 > def[k] + 0) print "FLAG: " k "=" e[k] " (default " def[k] ")" }'
[ -n "$(val sv_proxyIPRanges)" ] && echo "REVIEW: sv_proxyIPRanges='$(val sv_proxyIPRanges)'"
case $(val sv_requestParanoia) in 1|2|3) ;; *) echo 'ADVISORY: sv_requestParanoia off (optional, §13)';; esac
# Secrets: EVERY assignment counts, not just the last; committed if `git ls-files <file>` lists it
printf '%s\n' "$ALL" | awk -F'\t' '$1 ~ /^(steam_webapikey|sv_licensekey|sv_tebexsecret|sv_prometheusbasicauthpassword|sv_playerstoken|rcon_password)$/ && $2 != "" {
  print "SECRET: " $1 " at " $4 ($3 ~ /^set[rs]$/ ? " via " $3 " - PUBLIC (§5)" : "") }'
on sv_devMode false && echo 'FLAG: sv_devMode on'
# Older builds only (both removed in current source): real IPs / identifiers on public /players.json
on sv_endpointPrivacy true || echo 'FLAG (older builds): sv_endpointPrivacy false'
on sv_exposePlayerIdentifiersInHttpEndpoint false && echo 'FLAG (older builds): sv_exposePlayerIdentifiersInHttpEndpoint on'
# Cfx anti-cheat: any override is a review item; loosening one is a finding
printf '%s\n' "$ALL" | awk -F'\t' '$1 ~ /^(sv_kick_players_cnl_.*|sv_pure_verify_client_settings|sv_authmaxvariance|sv_authmintrust)$/ {
  e[$1] = $2 " (" $4 ")" } END { for (k in e) print "REVIEW: " k "=" e[k] }'
# Not in the walk: launch-time +set/+exec (scripts, service units; txAdmin keeps its own startup args)
grep -rnE '\+(set[rs]?|exec)[[:space:]]' --include='*.bat' --include='*.cmd' --include='*.sh' \
  --include='*.ps1' --include='*.service' --include='*.yml' --include='*.yaml' .
```

Scope limits: the walk follows `exec` lines from `server.cfg` only, so a cfg that is never `exec`'d
doesn't count, and launch-time `+set`/`+exec` (in `.bat`/`.sh`/service files, or txAdmin's startup
arguments, which live outside the repo) applies in command-line order and needs a separate look —
the last grep only finds the in-repo ones. `git ls-files` needs a git checkout; without one, treat
every secret hit as possibly committed. `@res` resolves to the first directory named `res`, so check
duplicates by hand. The walk handles CRLF, a UTF-8 BOM, `;`-joined commands and quoted names; it reports
`CYCLE` for an `exec` loop and skips it, and walks a file again when it is `exec`'d again later (not
nested), as the server would.

## 12. Server-Side Vetoes: Game Events and Entity Creation

With OneSync the server parses some of the game's own network events before routing them, and a
server handler can veto one with `CancelEvent()`. Cheat effects — explosions, projectiles, damage,
weapon removal, particle spam, spawned props and vehicles — arrive this way, not through your
resource's net events. These handlers are defence in depth: **their absence is advisory, not a
finding**; `sv_entityLockdown` and the `sv_enableNetworked*` convars (§11) come first.

**Which events.** Official: the server events reference lists `entityCreating` (*"can be canceled to
instantly delete the entity"*), `weaponDamageEvent` (*"This event can be canceled"*),
`startProjectileEvent`, `ptFxEvent` and `removeAllWeaponsEvent`; the OneSync cookbook adds
`explosionEvent` (server 1543+, *"SERVER script, requires OneSync!"*, `CancelEvent()` in its
explosion-free-zone example; archived 2019). The source (`ServerGameState.cpp`) raises those plus
`giveWeaponEvent`, `removeWeaponEvent`, `clearPedTasksEvent` and `fireEvent` through one path: if a
handler cancels, the server does not route the event to other players. Those four are
source-confirmed only — no reference page, so treat their payload fields as unstable. Our reading:
cancelling stops routing; it does not undo the effect on the sender's own game.

Handler arguments are `(sender, data)`. `sender` arrives as a **string** — the server packs
`std::to_string(client->GetNetId())` — so `tonumber(sender)` before using it as a table key or
comparing it to a `source` you stored.

```lua
-- BAD — "anticheat" that only logs; every explosion is still routed to every player
AddEventHandler('explosionEvent', function(sender, ev) print(GetPlayerName(sender), json.encode(ev)) end)

-- GOOD — per-sender flood limit; excess explosions are not routed
local recent = {}                                  -- [src] = { n = count, t = windowStart }
AddEventHandler('explosionEvent', function(sender, ev)
  local src, now = tonumber(sender), GetGameTimer()
  local r = recent[src]
  if not r or now - r.t > 10000 then r = { n = 0, t = now }; recent[src] = r end
  r.n = r.n + 1
  if r.n > 5 then
    CancelEvent()
    if r.n == 6 then print(('[anticheat] explosion flood from %s'):format(GetPlayerName(src))) end
  end
end)
AddEventHandler('playerDropped', function() recent[tonumber(source)] = nil end)
```

**Client-created entities: `entityCreating`.** It fires when a client's entity reaches the server
(in the source it runs while processing a client clone, after the `sv_entityLockdown` check;
server-script entities raise `serverEntityCreated` instead). Cancel it and the (non-player) entity is deleted.
Veto on the model (`GetEntityModel(entity)`, optionally `GetEntityType(entity)`: 1 ped, 2 vehicle,
3 object). **Never gate a veto on `GetEntityPopulationType(entity)`**: the population type comes
from the client-supplied sync data (the server's own lockdown check reads it from the entity's sync
tree and exempts the `POPTYPE_RANDOM_*` "ambient" values outside `strict`), so a cheat can flag a
blocked model as ambient traffic and skip a `== POPTYPE_MISSION` condition. Use it for logging only.

```lua
-- BAD — the pop type is client-controlled: mark the tank as "ambient" and it skips the check
AddEventHandler('entityCreating', function(entity)
  if GetEntityPopulationType(entity) == 7 and GetEntityModel(entity) == `rhino` then CancelEvent() end
end)

-- GOOD — block on the model whatever the client claims it is
local BLOCKED = { [`rhino`] = true, [`hydra`] = true, [`prop_windmill_01`] = true }
AddEventHandler('entityCreating', function(entity)
  if BLOCKED[GetEntityModel(entity)] then
    print(('[anticheat] blocked model %d from %s'):format(GetEntityModel(entity),
      tostring(NetworkGetFirstEntityOwner(entity))))
    CancelEvent()
  end
end)
```

This is a denylist: it stops the models you thought of. The stronger control is `sv_entityLockdown
strict` (§11) with vehicles and props spawned by the server from a server-owned allowlist
(below). `relaxed` is not enough here: it exempts entities the client labels as ambient
population, which is the same label this bypass relies on.

**Server-side spawns from a net event.** On the server, `CreateVehicle`, `CreatePed`,
`CreateObject` and `CreateObjectNoOffset` are entity RPC natives (`rpc_spec_natives.lua`) and
`CreateVehicleServerSetter(modelHash, type, x, y, z, heading)` is the server-setter variant. A net
event that passes the client's model string into one of them lets the client spawn anything.

```lua
-- BAD — the client picks the model
RegisterNetEvent('garage:spawn', function(model)
  local c = GetEntityCoords(GetPlayerPed(source))
  CreateVehicleServerSetter(GetHashKey(model), 'automobile', c.x, c.y, c.z, 0.0)
end)

-- GOOD — the client sends a key; the server owns model, type, cooldown (and ownership checks)
local GARAGE = { sultan = { model = `sultan`, type = 'automobile' }, faggio = { model = `faggio`, type = 'bike' } }
RegisterNetEvent('garage:spawn', function(key)
  local src = source
  local v = type(key) == 'string' and GARAGE[key]
  if not v or throttled(src, 'garage', 10000) then return end   -- throttled() from §3
  local ped = GetPlayerPed(src)
  local c = GetEntityCoords(ped)
  CreateVehicleServerSetter(v.model, v.type, c.x, c.y, c.z, GetEntityHeading(ped))
end)
```

```bash
# Which vetoes exist (none = advisory). Matches the event-name string anywhere, so a handler split
# across lines is found too; read each: does it CancelEvent(), or only log? A RegisterNetEvent on one
# of these names is a red flag: it would let clients trigger that resource's handler with forged data.
grep -rnE "['\"](explosionEvent|entityCreating|weaponDamageEvent|startProjectileEvent|ptFxEvent|removeAllWeaponsEvent|giveWeaponEvent|removeWeaponEvent|clearPedTasksEvent|fireEvent)['\"]" \
  --include='*.lua' --include='*.js' resources/
# Server spawns whose model is a variable (not a `backtick` literal) — trace it back to net event
# arguments. The model is CreatePed's 2nd and CreatePedInsideVehicle's 3rd argument.
grep -rnE "(Create(VehicleServerSetter|Vehicle|ObjectNoOffset|Object)\s*\(|CreatePed\s*\([^,]+,|CreatePedInsideVehicle\s*\([^,]+,[^,]+,)\s*((GetHashKey|joaat)\(\s*)?[A-Za-z_][A-Za-z0-9_.]*\s*[,)]" \
  --include='*.lua' resources/
```

## 13. Inbound HTTP on the Game Port: the JSON Endpoints and `SetHttpHandler` Routes

The game port (default 30120, TCP) is also an HTTP server. It serves the server's own JSON endpoints
to anyone, and every resource that calls `SetHttpHandler` gets a public route on it. This is its own
section because §9 is the server *calling out* with a key it holds, and §10 is your separate web API;
here the game server *is* the web endpoint.

**What the built-in endpoints return** (source: `InfoHttpHandler.cpp`, current master):

- `/info.json` — `server` (`FXServer-<version>`, handy to compare against advisories),
  `enhancedHostSupport`, `resources` (every *started* resource's name, plus `hardcap`), `vars` (every
  convar carrying the server-info flag except `sv_hostname`/`sv_infoVersion` — built-ins that have it
  plus everything you set with `sets`, which sets that flag: `Console.Variables.cpp`),
  `requestSteamTicket` (`unset` when `steam_webApiKey` is empty, `off` when it is `none`, else `on`
  — never the key), `enforceSteamAuth`, `version`, and `icon` if one is loaded. Rate limited per address (`http_info`).
- `/dynamic.json` — `hostname`, `gametype`, `mapname`, `clients`, `iv`, `sv_maxclients`.
- `/players.json` — current source: one anonymized entry per player (`name: "Player"`, `id: 0`, no
  identifiers, `endpoint: "127.0.0.1"`). With `sv_playersToken` sent as `X-Players-Token` (or
  `?token=`, which lands in proxy and access logs — prefer the header) it returns `id`, `name`,
  `identifiers` and `ping`. Older builds (before commit `d52296e`, 2026-07-08) published names, ids
  and pings, real IPs when `sv_endpointPrivacy` was `false`, and identifiers when
  `sv_exposePlayerIdentifiersInHttpEndpoint` was `true` (§11). Anything not listed here: verify on a
  live server.

So the checks are: a secret set with `sets` is published in `vars` (§5, §11); the `resources` list
names every started resource, including internal admin tools — assume an attacker knows which
free resources you run and looks up their known bugs; on older builds, player IPs and
identifiers.

**Probe** — only a server you own or are explicitly authorized to test, under the "Authorization gate
(browser probes)" in `secaudit:dynamic-verification` (state the target in one line first). Read-only GETs; each one
spends a token of the per-address limiter.

```bash
H=http://HOST:30120
curl -s "$H/info.json" | jq '{server, requestSteamTicket, enforceSteamAuth, resources: (.resources | length)}'
curl -s "$H/info.json" | jq -r '.vars | to_entries[]
  | select(.key | test("key|token|secret|pass|webhook|license|db|mysql"; "i")) | "SECRET? \(.key)=\(.value)"'
curl -s "$H/info.json" | jq -r '.resources[]' | sort     # anything internal or admin-only by name?
curl -s "$H/dynamic.json" | jq .
curl -s "$H/players.json" | jq '.[0]'   # identifiers or a real endpoint here = older build / leak
```

Don't probe `sv_requestParanoia` from your workstation: a matching request gets the probing address
blocked by the server.

**`SetHttpHandler` routes are public.** The reference: *"Sets the handler for HTTP requests made to
the executing resource. Example request URL: `http://localhost:30120/http-test/ping` - this request
will be sent to the `http-test` resource with the `/ping` path."* Nothing authenticates the caller;
the only built-in brake is a per-resource, per-address rate limiter (`http_<resource>`, rate 10,
burst 25 in `ResourceHttpHandler.cpp`, skipped for addresses in `sv_proxyIPRanges` — §6). The request
object has `address`, `headers`, `method`, `path`, `setDataHandler`, `setCancelHandler`; the
response has `writeHead`, `write`, `send`. A route that runs `ExecuteCommand` inherits the resource's
ACE grants (§1, §11): with `command` granted, it is a remote console.

```lua
-- BAD — anyone who can reach the game port runs console commands and pays themselves
SetHttpHandler(function(req, res)
  req.setDataHandler(function(body)
    local data = json.decode(body)
    if req.path == '/exec' then ExecuteCommand(data.cmd) end
    if req.path == '/pay' then Framework.GetPlayer(data.id).addMoney(data.amount) end
    res.send('ok')
  end)
end)

-- GOOD — fail closed without a token; constant-time compare; one method, one path; capped, validated body
local TOKEN = GetConvar('ops_http_token', '')    -- plain `set` in the untracked secrets file + add_convar_permission (§5)
local MAX_BODY = 4096

local function safeEqual(a, b)                   -- Lua has no constant-time compare built in
  if type(a) ~= 'string' or type(b) ~= 'string' or #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do diff = diff | (a:byte(i) ~ b:byte(i)) end
  return diff == 0
end

local function header(req, name)                 -- header names arrive as the client sent them
  for k, v in pairs(req.headers) do if k:lower() == name then return v end end
end

SetHttpHandler(function(req, res)
  local function reply(code, body)
    res.writeHead(code, { ['Content-Type'] = 'application/json' })
    res.send(body or '{}')
  end
  if TOKEN == '' then return reply(503) end
  if not safeEqual(header(req, 'authorization') or '', 'Bearer ' .. TOKEN) then return reply(401) end
  if req.method ~= 'POST' or req.path ~= '/announce' then return reply(404) end
  -- the data handler only runs when a body arrives: without one the request would never be answered
  local cl = header(req, 'content-length') or ''
  local len = cl:match('^%d+$') and tonumber(cl)   -- digits only: the server parses it with atoi
  local chunked = (header(req, 'transfer-encoding') or ''):lower() == 'chunked'
  if not chunked and (not len or len == 0) then return reply(400) end
  if len and len > MAX_BODY then return reply(413) end
  req.setDataHandler(function(body)
    if #body > MAX_BODY then return reply(413) end
    local ok, data = pcall(json.decode, body)
    if not ok or type(data) ~= 'table' or type(data.text) ~= 'string' or #data.text > 200 then
      return reply(400)
    end
    TriggerClientEvent('chat:addMessage', -1, { args = { 'Server', data.text } })
    reply(200)
  end)
end)
```

In the source (`Http1Server.cpp`, `HttpServer.h`) the data handler is called once with the whole
body, and only when a body is read (`Content-Length` > 0 or chunked) — a bodyless POST never reaches
it, hence the early `400`. (HTTP/2, off by default via `sv_netHttp2`, needs no `Content-Length`, so
a valid h2 POST without one gets the same `400` — fails closed.) The size checks limit what your handler processes, not memory: the server
buffers the whole body first and no size limit is visible in the source
— put a proxy with a body limit in front if that matters (`secaudit:rate-limiting`). Don't rely on
`req.address` for an IP allowlist behind a proxy (§6), and keep `ExecuteCommand`/`PerformHttpRequest`
off any route that does not pass the token check (SSRF: `secaudit:web-vulns`).

```bash
# Every SetHttpHandler is a public route. First filter only (read every hit): flags a file where no
# non-comment line both compares (==, ~=, !=, safeEqual/timingSafeEqual) and names a token/auth/key
grep -rlE "SetHttpHandler" --include='*.lua' --include='*.js' resources/ | while IFS= read -r f; do
  grep -vE '^\s*(--|//)' "$f" | grep -E "(safeEqual|timingSafeEqual)\(|[=~!]=" \
    | grep -qiE "token|auth|api.?key|secret|bearer" || echo "NO AUTH CHECK: $f"
  grep -nE "ExecuteCommand|PerformHttpRequest|addMoney|addItem|DropPlayer|TriggerEvent" "$f" | sed "s|^|$f:|"
  grep -nE "[!~=]=\s*['\"]Bearer|headers\[[^]]+\]\s*[!~=]=" "$f" | sed "s|^|$f: non-constant-time compare? |"
done
```

## FiveM Footgun Checklist

- A net event taking a target id, identifier, amount, price, role, or `isAdmin` from its arguments
  instead of `source` + server state; `source` read after `Wait()`/`await`.
- A server-to-server event registered with `RegisterNetEvent` instead of `AddEventHandler`/export.
- Arguments without type/NaN/integer/range/length/allowlist checks; rewards granted because the
  client said a condition was met.
- Expensive net events with no per-`source` cooldown (built-in limiters are per traffic class).
- A key, webhook URL, DB string, or password in a `client_script`, `shared_script`, `files`, NUI
  bundle, or loadscreen.
- Secrets in `setr`/`sets`; secret convars without `add_convar_permission`; `server.cfg` with
  `sv_licenseKey`/`rcon_password` committed.
- Player identity accepted as an event argument; accounts keyed on `ip:`.
- Authorization read from a client-writable state bag with `sv_stateBagStrictMode` off.
- A NUI callback forwarding price/amount/target; a backend key in NUI; player strings via `innerHTML`.
- Player-written DB fields (item metadata, notes, tickets) rendered as HTML in NUI, especially staff
  panels; a NUI callback routing to an event/export named by the page; no CSP meta / strict mode (advisory).
- Two-party events without `target ~= src` / `DoesPlayerExist`; rejections never logged.
- `PerformHttpRequest` URL from client input, `http://` base, key in logs, non-2xx ignored, retries
  without an idempotency key.
- Web API scoped by a path/body community id instead of the key; unscoped stream cursors; one key
  shared across communities; no revocation; a game-server call alone granting portal privileges.
- txAdmin on `0.0.0.0:40120` unfirewalled; RCON with a weak or committed password.
- A privileged `exports(...)` with no caller check; `GetInvokingResource()` treated as player auth;
  admin net events checking a hand-rolled identifier list instead of `IsPlayerAceAllowed`;
  `builtin.everyone`/`resource.*` granted `command`, or `ip:`-keyed admins, in cfg.
- A net event passing a client-chosen model to `CreateVehicle*`/`CreatePed`/`CreateObject*`;
  game-event "anticheat" handlers that log but never `CancelEvent()` (no handlers at all: advisory).
- A `SetHttpHandler` route with no token check, or reaching `ExecuteCommand`/money/`PerformHttpRequest`;
  a secret in `info.json` `vars` via `sets`; `sv_playersToken` committed or sent as `?token=`.
- `server.cfg` (or an `exec`'d cfg) with `sv_pureLevel` unset, `sv_scriptHookAllowed`/`sv_devMode`/
  `sv_enableNetworkedPhoneExplosions`/`sv_netEventReassemblyUnlimitedPendingEvents` true, raised
  `rateLimiter_*` values, overridden CnL anti-cheat convars, or `steam_webApiKey` committed (§11).

## Related skills

- `secaudit:secrets` — storing, rotating, and scrubbing leaked API keys, license keys, RCON passwords, webhook URLs.
- `secaudit:rate-limiting` — limiter design for the game-facing API and per-source throttles.
- `secaudit:realtime-security` — SSE/long-poll auth, connection caps, resume cursors, reconnects.
- `secaudit:discord-bot-security` — Discord bots and webhooks a FiveM community runs.
- `secaudit:web-vulns` — SSRF via `PerformHttpRequest` URLs, XSS in NUI pages, IDOR fundamentals.
- `secaudit:data-access` — schema validation of game-server request bodies.
- `secaudit:cryptography` — why a fast hash suits random API keys but not passwords.
- `secaudit:proxy-trust` — `X-Real-IP`/`sv_proxyIPRanges` and the web API behind a proxy.
- `secaudit:privilege-escalation` — admin endpoints on the web portal side.

## Sources

- https://docs.fivem.net/docs/developers/server-security/ -- "Cheats can allow the client to trigger events in any context"; AddEventHandler vs RegisterNetEvent; RegisterNetEvent is a wrapper; `65535` server source on client; server-side checks list; bad `job:givePlayerItem` example; "good" example's `GetPlayerPed(source)` in a thread and undefined `ped`; "Server owner options": `sv_kick_players_cnl_*`, `sv_pure_verify_client_settings`, `sv_authMaxVariance`/`sv_authMinTrust`, `sv_filterRequestControl` "shouldn't be touched", most enabled by default from build 8450, `sv_disableClientReplays` disables Rockstar Editor
- https://docs.fivem.net/docs/scripting-manual/working-with-events/listening-for-events/ -- `source` holds the triggering player, valid only for the initial call; registering is what lets a client-side script trigger a server event
- https://docs.fivem.net/docs/scripting-manual/working-with-events/triggering-events/ -- `TriggerServerEvent`/`emitNet`, `TriggerClientEvent` with `-1` for all clients
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/RegisterNetEvent/ -- "Marks the event safe for network use" (triggerability itself rests on the two pages above)
- https://docs.fivem.net/docs/scripting-reference/convars/ -- `set` server-only, `setr` readable by clients, `sets` exposed in `info.json` and the server list
- https://docs.fivem.net/docs/developers/sandbox/ -- `add_convar_permission`; "ConVars are readable by all resources" by default; filesystem/worker/child-process restrictions and overrides
- https://docs.fivem.net/docs/scripting-reference/resource-manifest/ -- `client_script`/`shared_script` add files to the packfile; `file` "to be downloaded by clients"; `ui_page`; `server_only`; globbing; `escrow_ignore`
- https://docs.fivem.net/docs/scripting-manual/nui-development/full-screen-nui/ -- client-side NUI files must be in the packfile; CEF remote debugging on `localhost:13172`; `https://cfx-nui-` scope (formerly `nui://`); resources are full-screen iframes
- https://docs.fivem.net/docs/scripting-manual/nui-development/nui-callbacks/ -- `RegisterNuiCallback`, JSON-parsed POST data, always return via `cb`; callbacks fetched from `https://${GetParentResourceName()}/<name>`
- https://github.com/citizenfx/fivem/blob/master/code/components/nui-resources/src/ResourceUI.cpp -- page origin `https://cfx-nui-<resource>/` (cerulean+, else `nui://`); `nui_callback_strict_mode` origin check; cross-origin whitelist to the callback host
- https://github.com/citizenfx/fivem/commit/ef3d8e0eb4 -- "strict mode for callbacks" (2024-08)
- https://github.com/citizenfx/fivem/blob/master/code/components/nui-core/src/NUISchemeHandler.cpp -- NUI responses set content type, CORS and cache headers, no CSP
- https://chromium.googlesource.com/chromium/src/+/main/services/network/public/cpp/content_security_policy/content_security_policy.cc -- CSP host sources: letters, digits and `-` only; wildcard only as a leading `*.`
- https://pyth3rex.github.io/blog/2026/03/26/fivem-web-surface/ -- supporting reference: stored XSS via item metadata, blind XSS in report queues, a generic NUI callback pass-through; its `invokeNative`/OS-escape claims are not adopted
- https://pyth3rex.github.io/blog/2026/03/24/fivem-server-events/ -- supporting reference: default-deny handlers, logging rejections, `src ~= target` + `DoesPlayerExist` on transfers
- https://docs.fivem.net/docs/scripting-manual/networking/state-bags/ -- default write policy (player/owner/server), client sets replicated only on opt-in
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/AddStateBagChangeHandler.md -- "the change handler can't opt to reject changes"
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/GetPlayerIdentifiers/ -- identifier types `steam`, `discord`, `license`, `license2`, `fivem`, `ip`; `license2` can equal `license`
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/GetPlayerIdentifierByType.md -- server-side `GetPlayerIdentifierByType(src, 'license')`
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/PerformHttpRequest/ -- signature, callback `(statusCode, body, headers, errorData)`, `followLocation = true` default
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/PerformHttpRequestAwait/ -- definition of `followLocation` ("Makes cURL follow the redirects of the URL"); server build 9515+
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/server-functions/ -- `PerformHttpRequest` listed as a server-side Lua function
- https://docs.fivem.net/docs/server-manual/server-commands/ -- `exec` (relative to server data dir or `@resource`); `sv_endpointPrivacy`, `sv_scriptHookAllowed`, `sv_entityLockdown` modes, `sv_filterRequestControl` modes and `sv_filterRequestControlSettleTimer` (30000 ms, modes 1/3), `sv_pureLevel` levels 1/2, `sv_enableNetworkedSounds`/`sv_enableNetworkedScriptEntityStates` (default true, 8540+)/`sv_enableNetworkedPhoneExplosions` (default false, 6831+), `sv_enableNetEventReassembly`/`sv_netEventReassemblyMaxPendingEvents` (100, 0-254)/`sv_netEventReassemblyUnlimitedPendingEvents` (false), `sv_authMaxVariance` (1-5, default 5), `sv_authMinTrust` (1-5, default 1), `sv_proxyIPRanges` default, `setr sv_stateBagStrictMode` (12739+, non-replicated entities unaffected), `rcon_password` (unset = disabled, UDP), `steam_webApiKey`, `sv_licenseKey`, `sv_tebexSecret`, `sv_prometheusBasicAuthPassword`, `sv_devMode` ("Do not enable in production"), `sv_requestParanoia` levels, "Rate limiters" table (all bucket names and defaults; `rateLimiter_<name>_rate`/`_burst`)
- https://docs.fivem.net/docs/server-manual/setting-up-a-server-vanilla/ -- `sv_licenseKey` in `server.cfg`, commented `rcon_password`, OneSync for server-side state awareness
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-server-impl/src/state/ServerGameState.cpp -- server registers `sv_stateBagStrictMode` as its own non-replicated variable; entity-lockdown checks (population, control-request filter) compare against `strict` exactly; `entityCreating` raised while processing client clones; game events (`explosionEvent`, `weaponDamageEvent`, `giveWeaponEvent`, `removeWeaponEvent`, `removeAllWeaponsEvent`, `clearPedTasksEvent`, `fireEvent`, `startProjectileEvent`, `ptFxEvent`) passed as `(tostring(netId), data)` and not routed when cancelled
- https://github.com/citizenfx/fivem/blob/master/code/client/citicore/console/Console.Commands.h -- boolean convar parsing: `true`/`false` case-insensitive, else integer non-zero = true, unparseable = false
- https://docs.fivem.net/docs/server-manual/proxy-setup/ -- `sv_proxyIPRanges` allows `X-Real-IP` and bypasses the rate limiter
- https://docs.fivem.net/docs/resources/txAdmin/ -- `txAdminPort` default 40120, `txAdminInterface` default `0.0.0.0`, admin menu actions, brute-force protection
- https://docs.fivem.net/docs/server-manual/asset-escrow/ -- Escrow scope (Lua/YFT/YDD/YDR), NUI not supported, `escrow_ignore`
- https://docs.fivem.net/docs/cookbook/2021/07/17/quick-note-on-using-built-in-acl-security/ -- built-in ACL; resources granted `command.add_ace`/`command.add_principal` change the ACL at runtime via `ExecuteCommand`; `IsPlayerAceAllowed` for checks
- https://docs.fivem.net/docs/cookbook/2019/08/19/onesync-intercepting-game-events-such-as-explosions/ -- `explosionEvent` (server 1543+, requires OneSync), `(sender, ev)` handler, `CancelEvent()` to stop routing
- https://docs.fivem.net/docs/scripting-reference/events/server-events/ -- `entityCreating` (cancel deletes the entity), `weaponDamageEvent` (cancelable), `startProjectileEvent`, `ptFxEvent`, `removeAllWeaponsEvent` signatures
- https://github.com/citizenfx/fivem-docs/blob/master/static/examples/config/server.cfg -- the docs' example `server.cfg`: `add_ace group.admin command allow`, `command.quit deny`, `add_principal identifier.fivem:1 group.admin`, `set steam_webApiKey ""`
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/RegisterCommand.md -- `restricted` commands need the `command.<name>` ace
- https://github.com/citizenfx/fivem/blob/master/code/client/citicore/se/Security.cpp -- ACE objects hierarchical, deny wins, every principal matches `builtin.everyone`
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-scripting-core/src/ScriptHost.cpp -- `GetInvokingRuntime`: the runtime one level down the stack, null when there is none
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-scripting-core/src/ResourceScriptFunctions.cpp -- `GET_INVOKING_RESOURCE` returns that runtime's resource name or nil; client-side strict-mode state bag warning
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/CancelEvent.md -- "Cancels the currently executing event"
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/GetEntityPopulationType.md -- `ePopulationType` enum (RANDOM_* 1-5, MISSION 7)
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/NetworkGetFirstEntityOwner.md -- server ID of an entity's first owner
- https://github.com/citizenfx/fivem/blob/master/ext/natives/rpc_spec_natives.lua -- server `CREATE_VEHICLE`/`CREATE_PED`/`CREATE_OBJECT`/`CREATE_OBJECT_NO_OFFSET` are entity RPC natives
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/server/CreateVehicleServerSetter.md -- `CreateVehicleServerSetter(modelHash, type, x, y, z, heading)`
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-server-impl/include/OneSyncVars.h -- `sv_entityLockdown` parser accepts `strict`/`relaxed`/`no_dummy`/`inactive`
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-server-impl/src/InfoHttpHandler.cpp -- `/info.json` fields (`vars` = server-info convars, started `resources`, `server` version, `requestSteamTicket`), `/dynamic.json` fields, anonymized public `/players.json`, `sv_playersToken` via `X-Players-Token`/`?token=`, `sv_endpointPrivacy`/`sv_exposePlayerIdentifiersInHttpEndpoint` removed, `sv_requestParanoia` `Via`/`Upgrade-Insecure-Requests` checks, `403 Nope.` and `BlockPeer`
- https://github.com/citizenfx/fivem/commit/d52296e06e -- "anonymize player data in HTTP endpoints" (2026-07-08)
- https://github.com/citizenfx/fivem/blob/master/code/client/citicore/console/Console.Variables.cpp -- `sets` sets the server-info flag that `/info.json` publishes
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-server-impl/src/GameServer.cpp -- `sv_playersToken` convar
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/SetHttpHandler.md -- `SetHttpHandler`: route `http://localhost:30120/<resource>/<path>`, request/response API
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-server-impl/src/ResourceHttpHandler.cpp -- `/<resource>/` prefix, per-resource `http_<resource>` limiter (10/25, skipped for proxy addresses)
- https://github.com/citizenfx/fivem/blob/master/code/components/net-http-server/src/Http1Server.cpp -- request body read in full per `Content-Length`/chunked (no body state otherwise), no size cap visible
- https://github.com/citizenfx/fivem/blob/master/code/components/net-http-server/include/HttpServer.h -- `SetDataHandler` delivers pending body data once; no call when no body was read
- https://docs.fivem.net/docs/scripting-manual/runtimes/lua/ -- `json` global is dkjson; `exports('Name', fn)`, `server_export`, `exports.res:Name()`
- https://docs.discord.com/developers/resources/webhook -- webhooks "do not require a bot user or authentication"; token-based Get/Modify/Delete need no auth
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025 (unauthorized net events, cross-community IDOR)
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025 (replicated convars, server.cfg, txAdmin/RCON exposure)
- https://top10.owasp.org/2025/A05_2025-Injection/ -- A05:2025 (XSS in NUI pages)
- https://top10.owasp.org/2025/A06_2025-Insecure_Design/ -- A06:2025 (client-authoritative game logic)
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025 (game-server API keys, identity from event arguments)
