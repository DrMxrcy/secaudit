---
name: discord-bot-security
description: Audits discord.js v14 bots and apps using Discord OAuth2 as their login: the bot token as a full-takeover credential, minimal privileged intents and invite permissions, slash-command and component authorization (default_member_permissions is a default server admins can override; custom_id is untrusted state), role-sync privilege escalation and the bot's role hierarchy, allowedMentions against @everyone/role-ping injection, phishing and spam via bot messages and DMs, 429 and invalid-request bans, and Discord OAuth identity (snowflake id, verified email, minimal scopes, revocation). Use whenever the project depends on discord.js, @discordjs/* or discord-api-types, registers slash commands, syncs roles to a Discord guild, sends Discord DMs or webhook posts, or offers "Sign in with Discord". HTTP-interactions signature verification and webhook URLs as secrets: secaudit:webhook-security; generic OAuth mechanics: secaudit:oauth-oidc-security.
license: MIT
---

# Discord Bot and Discord OAuth Security

A Discord bot is a privileged service account sitting inside someone else's community. It holds a
token that *is* the bot, a role somewhere in the guild's hierarchy, and whatever permissions the
invite link asked for — and every slash command, button and synced role is a request for the bot
to use that authority on behalf of a user who usually has less of it. Discord's own permission UI
(`default_member_permissions`, the command picker) decides who *sees* a command, not who your code
lets *complete* one. Apps that use "Sign in with Discord" as their only login inherit a second
trust boundary: the OAuth identity Discord hands back, and which of its fields are stable enough
to key an account on.

The recurring AI-codegen failure mode is a bot that works in the developer's test server — where
the developer is the owner, the bot's role is at the top, and nobody types `@everyone` into a form
field — and skips every check that matters once strangers use it: no server-side authorization
because `setDefaultMemberPermissions` "already handles it", a role-sync job that grants whatever
role ID a portal admin picked, ``channel.send(`Welcome ${member.displayName}`)`` with the default
mention parsing, a `custom_id` of `approve:<userId>` acted on without asking who clicked, the token
in a `NEXT_PUBLIC_` variable so the dashboard can call the API, and accounts looked up by Discord
username. Findings map to OWASP **A01:2025** (Broken Access Control — command authorization, role
sync, confused-deputy actions, `custom_id` tampering), **A07:2025** (Authentication Failures — the
bot token and the OAuth identity), **A05:2025** (Injection — mention and markdown injection into
bot-sent messages), and **A02:2025** (Security Misconfiguration — over-broad intents and invite
permissions).

`secaudit:webhook-security` §4 owns Ed25519 verification of Discord's HTTP interactions endpoint
and treats Discord channel-webhook URLs as bearer secrets; `secaudit:oauth-oidc-security` owns
generic OAuth client mechanics. This skill adds only what is Discord-specific and cross-references
the rest.

## When to Use

- `discord.js`, `@discordjs/rest`, `@discordjs/ws`, `@discordjs/builders`, `discord-api-types`,
  or `discord-interactions` in any `package.json` of the repo or monorepo.
- Slash-command, button, select-menu or modal handlers (`InteractionCreate`, `isChatInputCommand`,
  `isButton`, `customId`).
- Code that adds/removes guild roles from a mapping stored in your own database (role sync,
  verification roles, "link your account" flows).
- A worker or bot that sends DMs, channel messages or Discord webhook posts containing
  user-supplied text.
- "Sign in with Discord", a Discord-only login, or any code that calls `/users/@me`,
  `/oauth2/token` or `/users/@me/guilds/{guild.id}/member`.

Review grep heuristics:

```bash
grep -rnE "DISCORD_(BOT_)?TOKEN|client\.login\(|new (Client|ShardingManager|REST)\(" \
  --include='*.ts' --include='*.js' --include='*.env*' .
grep -rnE "NEXT_PUBLIC_DISCORD|VITE_DISCORD|EXPO_PUBLIC_DISCORD" .               # token/secret client-side
grep -rnE "GatewayIntentBits\.(GuildMembers|GuildPresences|MessageContent)|Partials\." --include='*.ts' .
grep -rnE "setDefaultMemberPermissions|default_member_permissions|setDMPermission|dm_permission" --include='*.ts' .
grep -rnE "roles\.(add|set|remove)\(|addRole\(|Routes\.guildMemberRole" --include='*.ts' .   # role writes
grep -rnE "allowedMentions|allowed_mentions" --include='*.ts' .                  # absent = default parsing
grep -rnE "customId\.(split|startsWith)|custom_id" --include='*.ts' .           # state in custom_id
grep -rnE "guilds\.join|guilds\.members\.read|scope=.*guilds|\.username\b|global_name" --include='*.ts' .
grep -rnE "discord(app)?\.com/api/webhooks" . | grep -v '\.env'                  # webhook URLs in code
```

## 1. The Bot Token Is the Bot

**What to look for:** the bot token in any client bundle (`NEXT_PUBLIC_`, `VITE_`), a committed
`.env`/`config.json`, a Dockerfile `ENV`, CI logs, or error-reporter payloads; one application
(and so one token) shared by dev, staging and production; code that logs `process.env`, a `Shard`
object, or REST request headers; a reconnect loop with no backoff.

**Why it's exploitable:** Discord's getting-started guide is explicit: *"Your token is used to
authorize API requests and carry your app's permissions, so they are highly sensitive. Make sure
to never share your token or check it into any kind of version control."* There is no scoping
below "everything the bot can do in every guild it is in" — a leaked token lets an attacker act
as the bot: assign any role below its highest role, read whatever its intents deliver, DM members
as a trusted bot, and post in every channel it can see. Three Discord/discord.js specifics make
leaks more likely than with an ordinary API key:

- **Sharding copies the token into an object people log.** discord.js's `Shard` builds
  `this.env = Object.assign({}, process.env, { …, DISCORD_TOKEN: this.manager.token })` — the
  whole parent environment plus the token, on a plain property. `console.log(shard)` or a crash
  reporter serializing it prints the token. (By contrast `Client#token` is defined
  non-enumerable and the `debug` event logs only a censored form, `Provided token: <first two
  segments>.*****`.)
- **`Client` reads `DISCORD_TOKEN` implicitly.** If `DISCORD_TOKEN` is in the environment,
  `new Client()` picks it up without the code ever naming it — so every child process, test runner
  and preview deployment that inherits that environment holds a working production token.
- **A crash loop can reset the token for you.** *"Clients are limited to 1000 IDENTIFY calls to
  the websocket in a 24-hour period… Upon hitting this limit, all active sessions for the app will
  be terminated, the bot token will be reset, and the owner will receive an email notification."*

GitHub's secret scanning lists **Discord Bot Token** (`discord_bot_token`) as a partner pattern
with push protection and validity checks — partner alerts are *"Reported directly to secret
providers that are part of secret scanning's partner program"*, not to you. Do not treat that as
remediation: if a token was ever committed, reset it yourself (Developer Portal → Bot → **Reset
Token**; *"You won't be able to view your token again unless you regenerate it"*) and redeploy.

**Fix:**

```ts
// BAD — token reachable from the browser bundle, one token for every environment,
// and the sharding manager's per-shard env dumped to logs
// apps/portal/.env:  NEXT_PUBLIC_DISCORD_TOKEN=MTk4NjIy...
const manager = new ShardingManager('./bot.js', { token: process.env.DISCORD_TOKEN });
manager.on('shardCreate', (shard) => logger.info({ shard }, 'launched'));   // shard.env has the token
```

```ts
// GOOD — server-only, per-environment application, fail closed, log only identifiers
const token = process.env.DISCORD_BOT_TOKEN;       // a separate Discord application per env
if (!token) throw new Error('DISCORD_BOT_TOKEN missing');   // refuse to boot
const manager = new ShardingManager('./bot.js', { token });
manager.on('shardCreate', (shard) => logger.info({ shardId: shard.id }, 'launched'));
```

The web portal should not hold the bot token at all if it can avoid it: have it enqueue a "sync
roles for user X" job that the bot/worker executes. If it must call the Discord API, the token
lives in a server-only module and never in an env var with a client-exposed prefix
(`secaudit:secrets`). Add the token to your logger's redaction paths (`authorization` header,
`token`, `DISCORD_*`) — `secaudit:logging-monitoring`.

## 2. Intents and Invite Permissions: Request the Minimum

**What to look for:** `intents: Object.values(GatewayIntentBits)` or every privileged intent
enabled "to be safe"; `MessageContent` in a slash-command-only bot; an invite URL with
`permissions=8` (Administrator); a bot meant for one community left as a **Public Bot**.

**Why it's exploitable:** privileged intents widen what a token leak (§1) or a logging bug
exposes. Discord names them — *"GUILD_PRESENCES GUILD_MEMBERS MESSAGE_CONTENT"* — and says *"You
may only enable a privileged intent if your use case requires it to function"*. Verified apps
(*"required for apps in 100+ guilds"*) must be approved per intent, and an app with *"more than
10,000 unique users"* needs review for continued access; requesting an unapproved one closes the
connection with code `4014`. Role sync that looks up one member by ID over REST
(`guild.members.fetch(id)` issues a REST Get Guild Member) does not need `GuildMembers`;
receiving `GUILD_MEMBER_ADD`/`UPDATE` events or enumerating the member list (List Guild Members:
*"This endpoint requires the GUILD_MEMBERS Privileged Intent"*) does.

The invite's `permissions` parameter is the bot's blast radius. `ADMINISTRATOR` *"Allows all
permissions and bypasses channel permission overwrites"* — a role-sync bot needs `ManageRoles`
plus whatever it posts with, nothing more. For a single-community bot, turn off **Public Bot**:
with `bot_public` false, *"only the app owner can add the app to guilds"*, which removes the
"someone added our bot to their server and ran our commands" class entirely.

```ts
// BAD
new Client({ intents: Object.values(GatewayIntentBits) as number[] });

// GOOD — only what the handlers consume; justify each privileged one in a comment
new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers], // GuildMembers: join-verification flow
  allowedMentions: { parse: [] },                                       // see §6
});
```

## 3. Slash Command Authorization: `default_member_permissions` Is Only a Default

**What to look for:** a handler whose only gate is `.setDefaultMemberPermissions(...)` on the
builder; no check that `interaction.guildId` is the guild your community is bound to; a global
command with no `setContexts`, so it also runs in DMs; admin actions authorized by Discord
permissions alone when the real authority lives in the portal's community roles.

**Why it's exploitable:** Discord's docs describe the field as the permissions a user must have
*by default*: setting it to `"0"` *"will prohibit anyone in a guild from using the command unless a
specific overwrite is configured or the user has admin permissions."* Those overwrites are
editable outside your code — *"Command permissions can also be updated by users in the client if
they have the necessary permissions"*, via *"Server Settings > Integrations"* — and *"Members with
the Administrator permission can use all commands."* So the gate is controlled by the guild's
admins, not by you: any guild admin can hand `/sync-roles` or `/verify approve` to `@everyone`.
For a bot bound to one community, that also means *any* guild that has the bot (§2, Public Bot)
gets its own copy of every global command.

Contexts are a separate axis — *"Contexts are distinct from, and do not affect, any command
permissions"*. `dm_permission` is *"Deprecated (use contexts instead)"* (`setDMPermission`: *"Use
setContexts instead"*), and a command's `contexts` *"defaults to all contexts [0,1,2]"* — guild,
bot DM, and private channels — so without `setContexts` a "guild admin" command can be invoked
from a DM, where there is no member and no guild permissions to check.

**Fix:** keep `setDefaultMemberPermissions` as UI hygiene, then authorize in the handler against
your own data, keyed on the server-provided actor (§4) and the guild binding.

```ts
// BAD — relies entirely on the picker; runs in any guild and in DMs
export const data = new SlashCommandBuilder()
  .setName('grant').setDescription('Grant a community role')
  .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles);

export async function execute(interaction: ChatInputCommandInteraction) {
  await grantCommunityRole(interaction.options.getUser('target', true).id, interaction.options.getString('role', true));
}
```

```ts
// GOOD — default stays as a hint; the handler re-checks guild binding and app-level role
export const data = new SlashCommandBuilder()
  .setName('grant').setDescription('Grant a community role')
  .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
  .setContexts(InteractionContextType.Guild)
  .setIntegrationTypes(ApplicationIntegrationType.GuildInstall);

export async function execute(interaction: ChatInputCommandInteraction) {
  if (!interaction.inCachedGuild()) return deny(interaction);              // no DMs, no unknown guilds
  const community = await db.community.findUnique({ where: { discordGuildId: interaction.guildId } });
  if (!community) return deny(interaction);                                // guild not bound to us

  const actor = await db.member.findUnique({                               // portal role, not Discord perms
    where: { communityId_discordUserId: { communityId: community.id, discordUserId: interaction.user.id } },
  });
  if (!actor || !can(actor.role, 'roles:grant')) return deny(interaction);
  await assertAssignable(interaction.guild, interaction.options.getRole('role', true).id, interaction.member); // §5
}

const deny = (i: ChatInputCommandInteraction) =>
  i.reply({ content: 'Not allowed.', flags: MessageFlags.Ephemeral });
```

`interaction.memberPermissions` (*"The permissions of the member, if one exists, in the channel
this interaction was executed in"*) is a reasonable *additional* check when the action is a
Discord-native one (kick, ban); it is not a substitute for the portal-role check when the
authority lives in your app.

## 4. Who Is Acting: `interaction.user` vs Options and `custom_id`

**What to look for:** an actor ID taken from a command option, a modal field, or a segment of
`customId` (`const [, action, userId] = interaction.customId.split(':')`) and then used as *who is
doing this*; buttons on a non-ephemeral message that perform a privileged action without checking
who clicked; roles, amounts or community IDs encoded in `customId` and trusted on return.

**Why it's exploitable:** the invoking user is what Discord attaches to the interaction —
`member` (*"Guild member data for the invoking user, including permissions"*) in a guild, `user`
in a DM; discord.js exposes it as `interaction.user` / `interaction.member`. Everything the user
*typed or picked* is input: `options.getUser('target')` is the target, never the actor.
`custom_id` is *"Developer-defined"*, 1–100 characters, and *"can be used flexibly to maintain
state or pass through other important data"* — it is a value your bot put on a message and gets
back from whoever clicks. Anyone who can see a non-ephemeral message can click its buttons, so a
`verify:approve:123` button posted in a moderators' channel — or one leaked into a public channel
— approves for whoever presses it unless the handler checks. Treat every `custom_id` as untrusted
input: parse strictly, look state up server-side, and re-authorize the clicker.

Real-world shape of both bugs, in a Discord-integrated npm package: OpenClaw
**GHSA-wh94-p5m6-mr7j** — moderation actions (`timeout`, `kick`, `ban`) *"used sender identity
from request parameters… instead of trusted runtime sender context"*, letting a non-admin spoof
the sender (fixed 2026.2.18); and **GHSA-jp4j-q5fc-58gv** — *"Discord button and component
interaction ingress did not consistently reapply the same guild and channel policy gates used for
normal inbound messages"* (fixed 2026.3.28). Component handlers need the same authorization as the
slash command that created them.

```ts
// BAD — state and authority both come from the button
if (interaction.isButton() && interaction.customId.startsWith('verify:approve:')) {
  const userId = interaction.customId.split(':')[2];
  await approveVerification(userId);                 // anyone who clicks approves anyone
}
```

```ts
// GOOD — opaque handle, server-side state, clicker re-authorized, single use
if (interaction.isButton() && interaction.customId.startsWith('verify:')) {
  const handle = interaction.customId.slice('verify:'.length);
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(handle) || !interaction.inCachedGuild()) return;
  const req = await db.verificationRequest.findUnique({ where: { handle } });
  if (!req || req.status !== 'pending' || req.discordGuildId !== interaction.guildId) return;
  if (!(await isCommunityModerator(req.communityId, interaction.user.id))) {
    return interaction.reply({ content: 'Not allowed.', flags: MessageFlags.Ephemeral });
  }
  const { count } = await db.verificationRequest.updateMany({   // compare-and-set: one approval
    where: { handle, status: 'pending' }, data: { status: 'approved', approvedBy: interaction.user.id },
  });
  if (count === 1) await applyVerifiedRole(req);               // §5 checks inside
}
```

If the bot uses an HTTP interactions endpoint instead of the gateway, the `member`/`user` fields
are only trustworthy after the Ed25519 check — that verification is `secaudit:webhook-security` §4.

## 5. Role Sync: The Bot Grants What It Can, Not What the Requester Should

**What to look for:** a portal UI or API that stores `{ communityRole → discordRoleId }` mappings
and a sync job that calls `member.roles.add(mapping.discordRoleId)` with no checks on the role;
mappings validated only when created; no check that the Discord role belongs to the community's
bound guild; a "sync everyone" job that retries every failure.

**Why it's exploitable:** this is a confused deputy. Discord's hierarchy rule for the *bot* is
*"A bot can grant roles to other users that are of a lower position than its own highest role"* —
nothing in that rule says the role must be harmless, or that the human who configured the mapping
could have granted it. Bots are usually placed near the top so sync "just works", so the bot can
typically assign roles carrying `ADMINISTRATOR`, `MANAGE_GUILD` or `MANAGE_ROLES`. Escalation
paths:

- A community admin in the portal (who may hold no Discord permissions at all) maps the
  "Member" community role to the guild's Admin role; every member is now a Discord admin.
- A user who can edit any mapping (IDOR on the mapping endpoint — `secaudit:web-vulns`) maps
  their own role to a privileged one, then triggers a sync.
- The bot is in several guilds; community A's mapping stores a role ID from guild B, and the sync
  job resolves it through a global cache.
- A mapping was harmless when saved; a guild admin later added `ADMINISTRATOR` to that role.

The same rule cuts the other way: a role **at or above** the bot's highest role cannot be
assigned and the API returns 403 — retried in a loop, those 403s count toward the invalid-request
ban (§8). Roles with `managed: true` (*"whether this role is managed by an integration"* — bot,
booster and integration roles) are not assignable either.

**Fix:** validate the role against the bound guild, the bot's position, its permission bits and
the configuring admin's own Discord position — at save time *and* at every sync, because role
permissions and positions change underneath you. Safer default: allow only roles whose `permissions`
bitfield is `0` (cosmetic/access roles); the deny-list below is the minimum.

```ts
const F = PermissionFlagsBits;
const DANGEROUS = [F.Administrator, F.ManageGuild, F.ManageRoles, F.ManageWebhooks, F.ManageChannels,
  F.BanMembers, F.KickMembers, F.ModerateMembers, F.MentionEveryone, F.ManageMessages, F.ManageNicknames,
  F.ManageThreads, F.ManageEvents, F.ManageGuildExpressions, F.ViewAuditLog, F.ViewGuildInsights,
  F.MuteMembers, F.DeafenMembers, F.MoveMembers];

// configuredBy: the human requesting the grant/mapping (null = scheduled sync re-validation only)
export async function assertAssignable(guild: Guild, roleId: string, configuredBy: GuildMember | null) {
  const role = await guild.roles.fetch(roleId);                    // fetched from THIS guild only
  if (!role || role.id === guild.id) throw new Error('unknown role or @everyone');
  if (role.managed) throw new Error('integration-managed role');
  if (DANGEROUS.some((p) => role.permissions.has(p, false))) throw new Error('role carries privileged permissions');

  const me = guild.members.me ?? (await guild.members.fetchMe());
  if (role.comparePositionTo(me.roles.highest) >= 0) throw new Error('role is at/above the bot');

  if (configuredBy === null) return role;   // sync job: requester was checked when the mapping was saved
  // The human who set the mapping must be able to grant it themselves in Discord.
  if (configuredBy.id !== guild.ownerId && (!configuredBy.permissions.has(F.ManageRoles) ||
      role.comparePositionTo(configuredBy.roles.highest) >= 0)) throw new Error('configuring admin cannot grant this role');
  return role;
}

const guild = await client.guilds.fetch(community.discordGuildId);   // the community's bound guild only
// save endpoint: refuse the mapping if the portal admin is not a member of that guild
const admin = await guild.members.fetch(session.discordUserId).catch(() => null);
if (!admin) throw new Error('not a member of the bound guild');
await assertAssignable(guild, input.discordRoleId, admin);
const role = await assertAssignable(guild, mapping.discordRoleId, null).catch((e) => disableMapping(mapping, e)); // sync
if (role) await (await guild.members.fetch(discordUserId)).roles.add(role, `portal sync: ${mapping.id}`);
```

`has(p, false)` skips discord.js's admin-implies-everything shortcut so the role's literal bits are
read. `comparePositionTo` returns *"positive number if this one is higher… 0 if equal"*, and equal
positions are *"sorted by id"*, so `>= 0` is not assignable. The mapping editor should list only
passing roles, and the save endpoint must call it again (`secaudit:privilege-escalation`).

Reverse direction: mapping a Discord role *to* a portal privilege is only safe for roles that only
Discord admins can grant — never self-assignable or reaction roles.

## 6. `allowedMentions`: Turn Pings Off by Default

**What to look for:** `channel.send`, `member.send`, `message.reply` or webhook posts that
interpolate usernames, nicknames, community names, form answers or any portal field, with no
client-level `allowedMentions` and no per-message override.

**Why it's exploitable:** Discord's defaults depend on the context: *"In regular messages, all
mention types are parsed"* (`{ "parse": ["users", "roles", "everyone"] }`), while *"In interactions
and webhooks, only user mentions are parsed"*. A bot announcing "Welcome, {community name}!" in a
regular channel message pings `@everyone` the moment someone names their community `@everyone`, if
the bot has `MENTION_EVERYONE` — *"To mention @everyone and @here, the bot must have the
MENTION_EVERYONE permission"*, and the same permission lets it ping non-mentionable roles. Discord
forbids `@` in **usernames** and usernames equal to `everyone`/`here`, but those rules are listed
for usernames only; display names, nicknames and every field in your own portal are free text,
and `<@&roleId>` is just text until it is parsed.

**Fix:** set the client default to nothing, then opt specific users in per message.
`MessageMentionOptions` in discord.js is `{ parse?, roles?, users?, repliedUser? }`. Discord notes
*"the parse field is mutually exclusive with the other fields"*, so name users explicitly rather
than combining them with `parse`.

```ts
// BAD — default parsing; user-controlled text can ping @everyone/@here/roles
await channel.send(`🎉 ${community.name} just verified ${member.displayName}!`);

// GOOD — nothing pings unless named; the intended user is pinged by ID
const client = new Client({ intents, allowedMentions: { parse: [], repliedUser: false } });
await channel.send({
  content: `🎉 ${escapeMarkdown(community.name, { maskedLink: true })} just verified <@${member.id}>!`,
  allowedMentions: { users: [member.id] },
});
```

```ts
// Webhook worker — set it explicitly rather than relying on the webhook default
await fetch(webhookUrl, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ content, allowed_mentions: { parse: [] } }),
});
```

## 7. Untrusted Text in Messages, Embeds and DMs

**What to look for:** user-supplied text placed into bot messages or embeds unescaped; user URLs
placed into links or Link buttons without validation; a feature that DMs arbitrary members (bulk
"notify everyone", "DM this user" commands, verification reminders) with no throttling.

**Why it's exploitable:** messages from a bot carry the bot's credibility, which is exactly what a
phishing message needs. Discord *"utilizes a subset of markdown"*, including masked links —
discord.js's `hyperlink()` formatter *"Formats the content and the URL into a masked URL"*,
`[text](url)` — so user text can render as an innocent label pointing anywhere, or as a heading
announcing a fake giveaway. discord.js's `escapeMarkdown` does **not** escape everything by
default: in `@discordjs/formatters` its options `maskedLink`, `heading`, `bulletedList` and
`numberedList` all default to `false`. It also does nothing about mentions — that is §6's job.
Mentions inside embeds *"may resolve correctly in embed titles, descriptions and field values but
will never notify the user"*, so embeds reduce ping risk but not the phishing one.

DMs are the amplifier. Discord's Create DM endpoint: *"You should not use this endpoint to DM
everyone in a server about something. DMs should generally be initiated by a user action. If you
open a significant amount of DMs too quickly, your bot may be rate limited or blocked from opening
new ones."* A command that DMs a user-chosen target with user-chosen text turns your bot into a
spam relay and gets it blocked for everyone.

```ts
// BAD — user text with masked links and headings intact, DM to any target, no limit
await target.send(`${interaction.user.username} says: ${interaction.options.getString('message', true)}`);
```

```ts
// GOOD — escaped fully, attributed, rate-limited per sender and per recipient, opt-in recipients
const text = escapeMarkdown(input.slice(0, 500), { maskedLink: true, heading: true, bulletedList: true, numberedList: true });
if (!(await limiter.allow(`dm:from:${interaction.user.id}`, 5, '1h')) ||
    !(await limiter.allow(`dm:to:${target.id}`, 3, '1h')) ||
    !(await prefs.acceptsDms(target.id))) {
  return interaction.reply({ content: 'Not now.', flags: MessageFlags.Ephemeral });
}
await target.send({ content: `Message from <@${interaction.user.id}> via ${guildName}:\n${text}`, allowedMentions: { parse: [] } });
```

For URLs a user supplies (a "community website" field rendered as a Link button), require
`https:` and an allowlisted host or show the raw URL — never hide it behind custom label text.
Per-user and per-IP limits on whatever triggers these sends are `secaudit:rate-limiting`.

## 8. Rate Limits: 429s and the Invalid-Request Cloudflare Ban

**What to look for:** raw `fetch` calls to the Discord API or webhook URLs (bypassing
`@discordjs/rest`'s queue) that retry on any error with a fixed delay; sync jobs that retry 403
"Missing Permissions" forever; rate limits hard-coded as constants; no alert on invalid-request
counts.

**Why it's exploitable (availability):** *"All bots can make up to 50 requests per second to our
API"*; on excess *"the API will return a HTTP 429"* and *"Your application should rely on the
Retry-After header or retry_after field"*. Discord adds that *"rate limits should not be hard
coded into your app"*. The sharp edge is the **invalid request limit**: *"IP addresses that make
too many invalid HTTP requests are automatically and temporarily restricted from accessing the
Discord API. Currently, this limit is 10,000 per 10 minutes. An invalid request is one that
results in 401, 403, or 429 statuses"* (429s with `X-RateLimit-Scope: shared` are not counted).
The ban is per IP, so a role-sync worker hammering 403s on a role above the bot (§5), or a worker
retrying 401/403 (e.g. after a token reset), takes the bot on the same egress IP offline too. A
deleted webhook's 404 doesn't count toward the limit, but retrying it is still pointless. A user who can
trigger Discord calls (a "resync me" button) can drive this deliberately.

`@discordjs/rest` already waits out 429s (its `rejectOnRateLimit` defaults to `null`, meaning
queue), emits `rateLimited`, and can warn on invalid requests — but `invalidRequestWarningInterval`
defaults to `0` (*"0 for no warnings"*).

```ts
// GOOD — discord.js client: surface invalid-request pressure before the ban
const client = new Client({ intents, rest: { invalidRequestWarningInterval: 500 } });
client.rest.on(RESTEvents.InvalidRequestWarning, ({ count, remainingTime }) =>
  alert(`discord invalid requests: ${count} (window resets in ${remainingTime}ms)`));
```

```ts
// GOOD — raw webhook worker: honour retry_after; 401/403 count toward the ban, 404 = webhook gone
const res = await fetch(url, { method: 'POST', headers, body });
if (res.status === 429) {
  const { retry_after } = (await res.json()) as { retry_after: number };   // seconds (float)
  return job.retryIn(Math.ceil(retry_after * 1000));
}
if ([401, 403, 404].includes(res.status)) return disableTarget(job.targetId, res.status);  // stop, alert
if (!res.ok) return job.retryWithBackoff();
```

On 401 from the bot token, stop all REST traffic and alert — it means the token was reset (§1).

## 9. Discord OAuth as the Only Login

Generic mechanics — `state` binding, PKCE, exact `redirect_uri`, provider tokens encrypted at
rest, open redirects on `returnTo` — are `secaudit:oauth-oidc-security` §1, §2 and §5. The
Discord-specific checks:

**Key the account on the snowflake `id`, as a string.** The User object's `username` is *"the
user's username, not unique across the platform"*; `global_name` is *"the user's display name,
if it is set"* (nullable, and user-editable). Only `id` is stable. Snowflakes *"are always
returned as strings in the HTTP API to prevent integer overflows"* — keep them as strings
(`text`/`varchar`, never a JS `number`, which silently rounds 64-bit IDs and can make two users
compare equal). Allowlists and role checks keyed on names are the same bug. OpenClaw
**GHSA-cw4q-gqg5-g38h** (CVE-2026-53849, fixed 2026.5.7): *"Discord allowFrom could bind to
mutable display names"*. Same project, **GHSA-4cqv-h74h-93j4** (first safe release 2026.2.22):
name/tag slug normalization let *"different user tags… collide to the same slug"*.

**Only trust the email when `verified` is true — and prefer not to link on it at all.** `email` is
returned only with the `email` scope, alongside `verified`: *"whether the email on this account
has been verified"*. Linking a Discord login to an existing portal account by an unverified email
is the nOAuth takeover (`secaudit:oauth-oidc-security` §4). For a Discord-only login, there is
usually no reason to request `email` at all.

**Minimal scopes.** `identify` *"allows /users/@me without email"* — enough for login.
`guilds` returns *"basic information about all of a user's guilds"*, which you rarely need and
should not store. To check membership in *your* community, use `guilds.members.read`, which
*"allows /users/@me/guilds/{guild.id}/member to return a user's member information in a guild"*.
Avoid `guilds.join` unless the product's purpose is joining users to a guild: it *"allows
/guilds/{guild.id}/members/{user.id} to be used for joining users to a guild"*, and Add Guild
Member accepts `nick` and `roles` — so a database of stored `guilds.join` tokens plus the bot
token lets whoever holds both add your entire user base to any guild the bot is in, with roles.
Use the authorization-code grant: the implicit grant returns the `access_token` in the redirect
URL's fragment.

**Don't keep tokens you don't use; revoke the ones you drop.** If login needs only identity and
a membership check, fetch both during the callback, issue your own opaque session, and discard the
Discord tokens. If you keep them (scheduled role re-sync), encrypt them (`oauth-oidc-security` §5)
and revoke on unlink/account deletion at the revocation URL — it *"will only accept a content type
of application/x-www-form-urlencoded"*, and *"any active access or refresh tokens associated with
that authorization will be revoked"*.

```ts
// BAD — username as identity, unverified email linking, Discord token as the session
const me = await discordGet('/users/@me', accessToken);
const user = await db.user.findFirst({ where: { OR: [{ discordName: me.username }, { email: me.email }] } });
cookies().set('session', accessToken);
```

```ts
// GOOD — Next.js callback after state/PKCE checks; authorize URL requested scope=identify guilds.members.read
import { RouteBases, Routes, OAuth2Routes } from 'discord-api-types/v10';

const auth = { headers: { authorization: `Bearer ${tokens.access_token}` } };
const me = await (await fetch(RouteBases.api + Routes.user('@me'), auth)).json();
const memberRes = await fetch(RouteBases.api + Routes.userGuildMember(COMMUNITY_GUILD_ID), auth);
if (!memberRes.ok) return redirect('/join-our-server');          // not a member (or token lacks scope)

const user = await db.user.upsert({                               // keyed on the snowflake string
  where: { discordId: String(me.id) },
  create: { discordId: String(me.id), displayName: me.global_name ?? me.username },
  update: { displayName: me.global_name ?? me.username },
});

try {                                                             // best-effort: login must not fail on it
  await fetch(OAuth2Routes.tokenRevocationURL, { method: 'POST',  // identity captured; drop Discord's token
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: tokens.access_token, token_type_hint: 'access_token',
      client_id: process.env.DISCORD_CLIENT_ID!, client_secret: process.env.DISCORD_CLIENT_SECRET! }) });
} catch (e) { logger.warn({ err: e }, 'discord token revocation failed'); }
await createOpaqueSession(user.id);                               // your session, not Discord's token
```

Discord's own OAuth2 page frames `state` as *"a value that binds the user's request to their
authenticated state"* — a per-flow nonce tied to the browser, compared on the callback. The
`client_secret` is server-only for the same reasons as the bot token (§1).

## 10. Discord Webhook URLs

Treating a channel-webhook URL as a bearer secret (never committed, logged, or sent to the client)
is `secaudit:webhook-security` §1. Two Discord-specific reasons it matters more than "someone can
post": Discord's Modify, Delete and Get Webhook **with Token** endpoints *"[do] not require
authentication"* — so whoever holds the URL can also rename and re-avatar the webhook to
impersonate staff, or delete it. Store webhook URLs encrypted, redact the path segment after the
webhook ID in logs, and if users paste webhook URLs into the portal, validate the host and path
shape server-side before your worker ever fetches them (an arbitrary URL is an SSRF target —
`secaudit:web-vulns` §2). Set `allowed_mentions` explicitly on every post (§6).

## 11. Dependency Advisories (OSV, queried 2026-10-16)

OSV lists no advisories for `discord.js`, `@discordjs/rest`, `@discordjs/ws`,
`@discordjs/builders`, `@discordjs/voice`, `@discordjs/core`, `@discordjs/formatters`,
`@discordjs/util` or `discord-api-types`; `discord.js@14.27.0` is the current v14 release. The one
Discord-maintained package with advisories is the voice codec `@discordjs/opus`:
**GHSA-43wq-xrcm-3vgr** (CVE-2024-21521), a process-crashing DoS via an input object with a
`toString` property; OSV records the range with `last_affected` 0.9.0 and no fix event, and 0.10.0
(January 2025) is outside that range. Only voice bots ship it. Run the live lookup in
`secaudit:framework-versions` for anything newer than this date.

## Discord Bot Footgun Checklist

- Bot token in a `NEXT_PUBLIC_`/`VITE_` var, a committed file, a Dockerfile `ENV`, or shared by
  dev/staging/prod; a logged `Shard` object or `process.env` dump.
- No backoff on gateway reconnects — 1000 IDENTIFYs in 24h resets the token.
- Every privileged intent enabled, `MessageContent` in a slash-only bot, invite asking for
  Administrator, single-community bot left as Public Bot.
- A command handler whose only gate is `setDefaultMemberPermissions` — server admins can override
  it under Server Settings > Integrations, and Administrators bypass it.
- No check that `interaction.guildId` is the community's bound guild; no `setContexts`, so the
  command also runs in DMs.
- Actor taken from an option, modal field or `customId` instead of `interaction.user.id`;
  buttons that act without re-authorizing the clicker; state trusted from `customId`.
- Role sync that grants a mapped role without checking the guild, `managed`, dangerous
  permission bits, the bot's position and the configuring admin's position — or validates only
  at save time.
- No client-level `allowedMentions: { parse: [] }`; user text in regular messages pings
  `@everyone`/roles; bot granted `MENTION_EVERYONE` it doesn't need.
- `escapeMarkdown(text)` with defaults — masked links and headings pass through.
- DM features without per-sender/per-recipient limits or opt-in.
- Raw `fetch` to Discord that ignores `retry_after` or retries 401/403; no
  `invalidRequestWarningInterval` alert.
- Accounts keyed on `username`/`global_name` or a numeric-cast snowflake; email linking without
  `verified`; `guilds`/`guilds.join`/`email` requested without need; Discord access token used as
  the session; tokens kept and never revoked.
- Webhook URLs logged in full, or user-pasted webhook URLs fetched without host validation.

## Related skills

- `secaudit:webhook-security` — §4 Discord HTTP interactions endpoint (Ed25519 over
  timestamp+body, 401 on failure, PING/PONG); §1 webhook URLs as bearer secrets.
- `secaudit:oauth-oidc-security` — `state`/PKCE binding, `redirect_uri`, account linking on
  verified email, provider tokens encrypted at rest.
- `secaudit:secrets` — client-exposed env prefixes, committed `.env`, rotation after a leak.
- `secaudit:privilege-escalation` — role values written from client input; admin-only actions.
- `secaudit:rate-limiting` — per-user/IP limits on commands that fan out DMs or Discord calls.
- `secaudit:web-vulns` — IDOR on mapping endpoints; SSRF on user-supplied webhook URLs.
- `secaudit:logging-monitoring` — redacting tokens and webhook URLs from logs and crash reports.

## Sources

- https://docs.discord.com/developers/quick-start/getting-started -- token "highly sensitive… never share your token or check it into any kind of version control"; Bot page "Reset Token"; token cannot be viewed again
- https://docs.discord.com/developers/events/gateway -- privileged intents GUILD_PRESENCES/GUILD_MEMBERS/MESSAGE_CONTENT; "only enable… if your use case requires it"; verified apps (100+ guilds) need approval; >10,000 users review; 4014 close code; 1000 IDENTIFY/24h then token reset
- https://docs.discord.com/developers/interactions/application-commands -- `default_member_permissions` "0" semantics and overwrites; Server Settings > Integrations; Administrators can use all commands; `dm_permission` deprecated for `contexts`; contexts default [0,1,2]; contexts don't affect permissions
- https://docs.discord.com/developers/interactions/receiving-and-responding -- interaction `member` ("invoking user, including permissions") / `user` fields, `app_permissions`, `authorizing_integration_owners`
- https://docs.discord.com/developers/components/reference -- `custom_id`: developer-defined, 1-100 characters, returned on interaction, "maintain state or pass through other important data"
- https://docs.discord.com/developers/topics/permissions -- role hierarchy rules for bots; ADMINISTRATOR "allows all permissions"; MANAGE_ROLES; MENTION_EVERYONE; role `managed`; equal positions sorted by id
- https://docs.discord.com/developers/resources/message -- allowed mentions object: defaults (regular messages parse all; interactions and webhooks parse users), MENTION_EVERYONE requirements, `parse` mutually exclusive, `replied_user`
- https://docs.discord.com/developers/resources/user -- User object (`id`, `username` "not unique across the platform", `global_name`, `verified`, `email`); username restrictions; Create DM guidance against mass DMs; Get Current User Guild Member requires `guilds.members.read`
- https://docs.discord.com/developers/resources/guild -- Add Guild Member requires a `guilds.join` token and bot token, accepts `roles`/`nick`; Add Guild Member Role requires MANAGE_ROLES; List Guild Members requires GUILD_MEMBERS
- https://docs.discord.com/developers/resources/application -- `bot_public` false: only the app owner can add the app to guilds
- https://docs.discord.com/developers/resources/webhook -- Get/Modify/Delete Webhook with Token do not require authentication
- https://docs.discord.com/developers/topics/oauth2 -- scopes (`identify`, `email`, `guilds`, `guilds.join`, `guilds.members.read`); `state` guidance; implicit grant returns token in URL fragment; revocation URL form-encoded only and revokes the whole authorization; bot authorization `permissions` parameter
- https://docs.discord.com/developers/topics/rate-limits -- 50 req/s global; 429 with `retry_after`/Retry-After; don't hard-code limits; invalid request limit 10,000 per 10 minutes on 401/403/429; shared-scope 429s not counted
- https://docs.discord.com/developers/reference -- snowflakes returned as strings to prevent integer overflow; message formatting (mentions, markdown subset)
- https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns -- Discord Bot Token (`discord_bot_token`): partner, push protection, validity check; partner alerts go to the provider
- https://discordjs.guide/legacy/slash-commands/permissions -- `setDefaultMemberPermissions(PermissionFlagsBits.…)`, `0` hides the command except for overwrites/Administrator, `setContexts`
- https://discordjs.guide/legacy/popular-topics/intents -- privileged intents in discord.js terms (`GuildPresences`, `MessageContent`, `GuildMembers`)
- https://discordjs.guide/legacy/popular-topics/faq -- `allowedMentions` as a `ClientOptions` default and per message; embed mentions never notify
- https://discordjs.guide/legacy/sharding -- `ShardingManager` takes the token and passes it to shards
- https://discord.js.org/docs/packages/discord.js/14.27.0/ClientOptions:Interface -- `allowedMentions`, `intents`, `rest` client options
- https://discord.js.org/docs/packages/discord.js/14.27.0/BaseInteraction:Class -- `memberPermissions`, `inCachedGuild()`, `inGuild()`, `user`, `guildId`
- https://discord.js.org/docs/packages/discord.js/14.27.0/Role:Class -- `comparePositionTo` return semantics, `managed`, `editable`, `permissions`, `position`
- https://discord.js.org/docs/packages/discord.js/14.27.0/GuildMemberRoleManager:Class -- `roles.add`, `roles.highest`, `botRole`
- https://discord.js.org/docs/packages/discord.js/14.27.0/GuildMemberManager:Class -- `members.fetch`, `members.me`, `fetchMe`
- https://discord.js.org/docs/packages/builders/1.14.1/SlashCommandBuilder:Class -- `setDefaultMemberPermissions`, `setContexts`, `setIntegrationTypes`; `setDMPermission` deprecated ("Use setContexts instead")
- https://github.com/discordjs/discord.js/blob/14.27.0/packages/discord.js/src/sharding/Shard.js -- `Shard#env` = `process.env` plus `DISCORD_TOKEN`
- https://github.com/discordjs/discord.js/blob/14.27.0/packages/discord.js/src/client/Client.js -- implicit `process.env.DISCORD_TOKEN`, non-enumerable `token`, censored token in debug output
- https://github.com/discordjs/discord.js/blob/14.27.0/packages/formatters/src/escapers.ts -- `escapeMarkdown` option defaults (`maskedLink`, `heading`, `bulletedList`, `numberedList` false)
- https://github.com/discordjs/discord.js/blob/%40discordjs/rest%402.6.3/packages/rest/src/lib/utils/types.ts -- `invalidRequestWarningInterval` (0 = no warnings), `rejectOnRateLimit`, `InvalidRequestWarningData`
- https://github.com/advisories/GHSA-wh94-p5m6-mr7j -- OpenClaw: Discord moderation authorization used sender identity from request params (CVE-2026-27484, fixed 2026.2.18)
- https://github.com/advisories/GHSA-jp4j-q5fc-58gv -- OpenClaw: Discord component interactions skipped guild/channel policy gates (fixed 2026.3.28)
- https://github.com/advisories/GHSA-cw4q-gqg5-g38h -- OpenClaw: Discord allowlist bound to mutable display names (CVE-2026-53849, fixed 2026.5.7)
- https://github.com/advisories/GHSA-4cqv-h74h-93j4 -- OpenClaw: Discord name/tag slug collision allowlist bypass (fixed 2026.2.22)
- https://github.com/advisories/GHSA-43wq-xrcm-3vgr -- `@discordjs/opus` DoS (CVE-2024-21521), OSV `last_affected` 0.9.0
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where §3, §4, §5 and §10 land
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025, where §1 and §9 land
- https://top10.owasp.org/2025/A05_2025-Injection/ -- A05:2025, where mention and markdown injection (§6, §7) land
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025, where intents and invite permissions (§2) land
