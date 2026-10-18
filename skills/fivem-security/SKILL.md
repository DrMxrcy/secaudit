---
name: fivem-security
description: Audits FiveM (CitizenFX / Cfx.re) server resources (Lua/JS) and the web APIs a FiveM server calls. Covers `RegisterNetEvent` handlers any client can trigger with arbitrary arguments (authorize on `source`, never on an id/identifier argument), server-only events wrongly networked, files `fxmanifest.lua` ships to players, `setr`/`sets` convars, committed `server.cfg` secrets, client-writable state bags, NUI callbacks and XSS, `PerformHttpRequest` keys, txAdmin exposure, and the game-facing API (per-community key scoping, cross-community IDOR, idempotent retries). Use whenever the project has `fxmanifest.lua`, `server.cfg`, Lua/JS calling `RegisterNetEvent`/`TriggerServerEvent`/`PerformHttpRequest`, or an API called by a FiveM game server. Hand-offs: secaudit:secrets, secaudit:rate-limiting, secaudit:realtime-security, secaudit:discord-bot-security, secaudit:web-vulns.
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
net event by another name — validate it, and remember it cannot veto.

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

**XSS.** Player names, chat, and report text rendered with `innerHTML`/`v-html`/
`dangerouslySetInnerHTML` run script in every viewer's NUI context, where it can call that
resource's NUI callbacks as the victim. Use `textContent` or default escaping (`secaudit:web-vulns`).

```js
row.innerHTML = `<td>${player.name}</td>`;                                         // BAD
const td = document.createElement('td'); td.textContent = player.name; row.append(td); // GOOD
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
| `sv_entityLockdown` | `strict` or `relaxed`; flag default `inactive` (advisory); `full` is a review item | `inactive`: *"Clients can create any entity."* `strict`: *"No entities can be created by clients"*; `relaxed` blocks only client-created script-owned entities. `full` *"Disables dummy object creation. Only usable on FiveM for GTAV Enhanced"* — the docs don't say it also blocks client entities, and the server source's lockdown checks (including the control-request filter) test for `strict` exactly, so don't count `full` as `strict`. | [cmds], source |
| `sv_filterRequestControl` | non-zero, e.g. `2`; missing or `0` is advisory only | Default `0` is off. `1` blocks control requests to player-controlled entities (*"currently, occupied vehicles only"*) once "settled" (older than the settle timer); `2` *"Blocks control requests to all entities controlled by players"*; `3` blocks all player-controlled entities regardless of age plus settled non-player entities; `4` routes no `REQUEST_CONTROL_EVENT` at all; `-1` = `2` plus a console warning. Any non-off mode also stops control requests across routing buckets and always blocks senders in `strict` lockdown. [sec] puts this convar in its *"shouldn't be touched unless you know what you are doing"* group, so recommending non-zero is our judgement (it can break resources that take control of player entities) — hence advisory, not a finding. | [cmds], [sec] |
| `sv_filterRequestControlSettleTimer` | default `30000` **milliseconds**; only matters with modes `1`/`3`; flag a raised value | Entities younger than the timer are not yet "settled": mode `1` leaves them open (occupied vehicles), mode `3` leaves only *non-player* entities open (player-controlled ones are always blocked in 3). Our reading: a larger value widens that window. The argument *"must be provided in milliseconds."* | [cmds] |
| `sv_stateBagStrictMode` | `true` (server 12739+) when no resource needs client writes (advisory) | Default `false`: the network owner can modify its entities' and its player state. `true`: *"Only the server can modify the state of networked entities and the player state"* (§7). The docs show `setr`; the server registers its own non-replicated copy (`ServerGameState.cpp`), so a plain `set` still reaches the server-side check, and `setr` also tells clients, which then refuse writes locally with the documented console error. | [cmds], source |
| **Rate limiting** | | | |
| `rateLimiter_<name>_rate` / `_burst` | flag any value raised above the documented default | Token buckets per traffic class (rate/burst): `netEvent` 50/200, `netEventFlood` 75/300, `netCommand` 7/14, `netCommandFlood` 25/45, `netCommandSize` 1024/8192, `stateBag` 75/125, `stateBagFlood` 150/175, `stateBagSize` 131072/262144, `rcon` 2/5, `handshake` 4/10, `handshakeUDP` 1/5, `challenge` 4/10, `resourceList` 10/25, `res_http_handler` 10/25, `http_info`/`http_dynamic`/`http_players` 4/10, `http_perf` 2/5. Raising one to silence a chatty resource removes flood protection for every client — fix the resource. These are not per-event limits (§3). | [cmds] |
| `sv_proxyIPRanges` | narrow to your real proxies | Default `10.0.0.0/8 127.0.0.0/8 192.168.0.0/16 172.16.0.0/12`; listed ranges may send `X-Real-IP` and bypass the rate limiter (§6). | [cmds] |
| **Secrets, privacy, and dev settings** | | | |
| `steam_webApiKey` | never in a committed cfg; never `setr`/`sets` | A Steam Web API key (*"required to allow for Steam identifiers to be returned by the server"*) is a credential: put it in the untracked `exec`'d secrets file (§5, `secaudit:secrets`). A launch-time `+set steam_webApiKey "$STEAM_WEB_API_KEY"` (the same `+` syntax as the docs' `FXServer.exe +exec server.cfg`; `%STEAM_WEB_API_KEY%` in Windows `cmd`; under txAdmin, its additional-arguments setting) keeps it out of git but is visible in the host's process list. Rotate any key ever committed. | [cmds] |
| `sv_licenseKey`, `sv_tebexSecret`, `sv_prometheusBasicAuthPassword` | same as `steam_webApiKey` | License key, the Tebex server-authentication secret, and the `/perf` basic-auth password (*"Also sent to txAdmin"*). | [cmds] |
| `rcon_password` | unset unless needed; if set, long and random, from the secrets file | *"if unset then RCon will be disabled. FXServer RCon uses UDP."* The documented `rcon` limiter (2/s, burst 5) throttles guessing. | [cmds] |
| `sv_devMode` | default `false`; flag `true` | Enables dev mode for joining clients and caps clients at 8 — *"Do not enable in production."* | [cmds] |
| `sv_endpointPrivacy` | `true` (advisory) | *"hides player IP addresses from public reports output by the server."* | [cmds] |
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
# Secrets: EVERY assignment counts, not just the last; committed if `git ls-files <file>` lists it
printf '%s\n' "$ALL" | awk -F'\t' '$1 ~ /^(steam_webapikey|sv_licensekey|sv_tebexsecret|sv_prometheusbasicauthpassword|rcon_password)$/ && $2 != "" {
  print "SECRET: " $1 " at " $4 ($3 ~ /^set[rs]$/ ? " via " $3 " - PUBLIC (§5)" : "") }'
on sv_devMode false && echo 'FLAG: sv_devMode on'
on sv_endpointPrivacy false || echo 'ADVISORY: sv_endpointPrivacy off'
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
- `PerformHttpRequest` URL from client input, `http://` base, key in logs, non-2xx ignored, retries
  without an idempotency key.
- Web API scoped by a path/body community id instead of the key; unscoped stream cursors; one key
  shared across communities; no revocation; a game-server call alone granting portal privileges.
- txAdmin on `0.0.0.0:40120` unfirewalled; RCON with a weak or committed password.
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

- https://docs.fivem.net/docs/developers/server-security/ -- "Cheats can allow the client to trigger events in any context"; AddEventHandler vs RegisterNetEvent; RegisterNetEvent is a wrapper; `65535` server source on client; server-side checks list; bad `job:givePlayerItem` example; "Server owner options": `sv_kick_players_cnl_*`, `sv_pure_verify_client_settings`, `sv_authMaxVariance`/`sv_authMinTrust`, `sv_filterRequestControl` "shouldn't be touched", most enabled by default from build 8450, `sv_disableClientReplays` disables Rockstar Editor
- https://docs.fivem.net/docs/scripting-manual/working-with-events/listening-for-events/ -- `source` holds the triggering player, valid only for the initial call; registering is what lets a client-side script trigger a server event
- https://docs.fivem.net/docs/scripting-manual/working-with-events/triggering-events/ -- `TriggerServerEvent`/`emitNet`, `TriggerClientEvent` with `-1` for all clients
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/RegisterNetEvent/ -- "Marks the event safe for network use" (triggerability itself rests on the two pages above)
- https://docs.fivem.net/docs/scripting-reference/convars/ -- `set` server-only, `setr` readable by clients, `sets` exposed in `info.json` and the server list
- https://docs.fivem.net/docs/developers/sandbox/ -- `add_convar_permission`; "ConVars are readable by all resources" by default; filesystem/worker/child-process restrictions and overrides
- https://docs.fivem.net/docs/scripting-reference/resource-manifest/ -- `client_script`/`shared_script` add files to the packfile; `file` "to be downloaded by clients"; `ui_page`; `server_only`; globbing; `escrow_ignore`
- https://docs.fivem.net/docs/scripting-manual/nui-development/full-screen-nui/ -- client-side NUI files must be in the packfile; CEF remote debugging on `localhost:13172`
- https://docs.fivem.net/docs/scripting-manual/nui-development/nui-callbacks/ -- `RegisterNuiCallback`, JSON-parsed POST data, always return via `cb`
- https://docs.fivem.net/docs/scripting-manual/networking/state-bags/ -- default write policy (player/owner/server), client sets replicated only on opt-in
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/AddStateBagChangeHandler.md -- "the change handler can't opt to reject changes"
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/GetPlayerIdentifiers/ -- identifier types `steam`, `discord`, `license`, `license2`, `fivem`, `ip`; `license2` can equal `license`
- https://github.com/citizenfx/fivem/blob/master/ext/native-decls/GetPlayerIdentifierByType.md -- server-side `GetPlayerIdentifierByType(src, 'license')`
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/PerformHttpRequest/ -- signature, callback `(statusCode, body, headers, errorData)`, `followLocation = true` default
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/functions/PerformHttpRequestAwait/ -- definition of `followLocation` ("Makes cURL follow the redirects of the URL"); server build 9515+
- https://docs.fivem.net/docs/scripting-reference/runtimes/lua/server-functions/ -- `PerformHttpRequest` listed as a server-side Lua function
- https://docs.fivem.net/docs/server-manual/server-commands/ -- `exec` (relative to server data dir or `@resource`); `sv_endpointPrivacy`, `sv_scriptHookAllowed`, `sv_entityLockdown` modes, `sv_filterRequestControl` modes and `sv_filterRequestControlSettleTimer` (30000 ms, modes 1/3), `sv_pureLevel` levels 1/2, `sv_enableNetworkedSounds`/`sv_enableNetworkedScriptEntityStates` (default true, 8540+)/`sv_enableNetworkedPhoneExplosions` (default false, 6831+), `sv_enableNetEventReassembly`/`sv_netEventReassemblyMaxPendingEvents` (100, 0-254)/`sv_netEventReassemblyUnlimitedPendingEvents` (false), `sv_authMaxVariance` (1-5, default 5), `sv_authMinTrust` (1-5, default 1), `sv_proxyIPRanges` default, `setr sv_stateBagStrictMode` (12739+, non-replicated entities unaffected), `rcon_password` (unset = disabled, UDP), `steam_webApiKey`, `sv_licenseKey`, `sv_tebexSecret`, `sv_prometheusBasicAuthPassword`, `sv_devMode` ("Do not enable in production"), "Rate limiters" table (all bucket names and defaults; `rateLimiter_<name>_rate`/`_burst`)
- https://docs.fivem.net/docs/server-manual/setting-up-a-server-vanilla/ -- `sv_licenseKey` in `server.cfg`, commented `rcon_password`, OneSync for server-side state awareness
- https://github.com/citizenfx/fivem/blob/master/code/components/citizen-server-impl/src/state/ServerGameState.cpp -- server registers `sv_stateBagStrictMode` as its own non-replicated variable; entity-lockdown checks (population, control-request filter) compare against `strict` exactly
- https://github.com/citizenfx/fivem/blob/master/code/client/citicore/console/Console.Commands.h -- boolean convar parsing: `true`/`false` case-insensitive, else integer non-zero = true, unparseable = false
- https://docs.fivem.net/docs/server-manual/proxy-setup/ -- `sv_proxyIPRanges` allows `X-Real-IP` and bypasses the rate limiter
- https://docs.fivem.net/docs/resources/txAdmin/ -- `txAdminPort` default 40120, `txAdminInterface` default `0.0.0.0`, admin menu actions, brute-force protection
- https://docs.fivem.net/docs/server-manual/asset-escrow/ -- Escrow scope (Lua/YFT/YDD/YDR), NUI not supported, `escrow_ignore`
- https://docs.fivem.net/docs/cookbook/2021/07/17/quick-note-on-using-built-in-acl-security/ -- built-in ACL; resources granted `command.add_ace`/`command.add_principal` change the ACL at runtime via `ExecuteCommand`
- https://docs.fivem.net/docs/scripting-manual/runtimes/lua/ -- `json` global is dkjson
- https://docs.discord.com/developers/resources/webhook -- webhooks "do not require a bot user or authentication"; token-based Get/Modify/Delete need no auth
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025 (unauthorized net events, cross-community IDOR)
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025 (replicated convars, server.cfg, txAdmin/RCON exposure)
- https://top10.owasp.org/2025/A05_2025-Injection/ -- A05:2025 (XSS in NUI pages)
- https://top10.owasp.org/2025/A06_2025-Insecure_Design/ -- A06:2025 (client-authoritative game logic)
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025 (game-server API keys, identity from event arguments)
