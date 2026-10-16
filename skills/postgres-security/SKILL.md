---
name: postgres-security
description: Audits self-hosted PostgreSQL 16+ via Drizzle, node-postgres (`pg`), or postgres.js. Covers Drizzle RLS that is declared but not in force (`drizzle-kit push` dropping hand-written policies, no FORCE, owner connections), tenant context in `db.transaction` and the `current_setting` NULL-vs-'' trap, PgBouncer transaction pooling breaking GUCs, LISTEN and session advisory locks, NOTIFY payloads bypassing RLS, advisory-lock collisions, SECURITY DEFINER `search_path`, roles and grants, TLS, and `pg_dump` backups. Use whenever the project has a `drizzle.config.ts`, imports `drizzle-orm/pg-core`, `pg`, or `postgres`, uses LISTEN/NOTIFY, advisory locks, PgBouncer, or `pg_dump`. Prisma stays in `secaudit:prisma-security`, Supabase RLS in `secaudit:database`, Drizzle `sql.raw` in `secaudit:data-access`, realtime fan-out in `secaudit:realtime-security`.
license: MIT
---

# Postgres Security (Self-Hosted, Drizzle / pg / postgres.js)

Self-hosted Postgres gives you every isolation primitive there is — roles, grants, row-level
security, transaction-scoped settings — and enforces none of them unless the app actually connects
in a way that makes them apply. The database will happily run `SELECT * FROM messages` for any
tenant if the connecting role owns the table, and it will deliver every `NOTIFY` payload to any
session that asked for it, policy or no policy. The controls are real; the defaults around them are
permissive.

The recurring AI-codegen failure mode on this stack is **isolation that exists in the schema file
and nowhere else**: `pgPolicy(...)` declared in `schema.ts` and then `drizzle-kit push` run against
a database where the app connects as the owner; a tenant id set with `set_config` on one pooled
connection and queried on another; a realtime trigger that ships the full row through `pg_notify`
to a listener that has no right to see it; an advisory-lock "per-community mutex" keyed on a 32-bit
hash. Each one passes the happy-path test and leaks under concurrency or under a second tenant.

Findings map to OWASP **A01:2025** (Broken Access Control — RLS not in force, tenant context
leaking, NOTIFY payloads past RLS), **A02:2025** (Security Misconfiguration — role design, grants,
`public` schema, `pg_hba.conf`, `listen_addresses`, logging settings), **A04:2025** (Cryptographic
Failures — unverified TLS, unencrypted backups stored beside their keys), **A05:2025** (Injection —
channel identifiers and SECURITY DEFINER `search_path` hijack), and **A09:2025** (Security Logging
and Alerting Failures — secrets written to the server log).

Sibling hand-offs, so nothing is explained twice: `secaudit:prisma-security` §2 (RLS bypassed by
owner/superuser/BYPASSRLS, `FORCE ROW LEVEL SECURITY`, the constraint existence oracle), §3
(`set_config` outside a transaction leaking across pooled connections), and §7 (`sslmode=require`
verifies nothing) apply to any ORM on Postgres and are summarized here, not repeated.
`secaudit:data-access` owns Drizzle `sql.raw()` and identifier injection (CVE-2026-39356).
`secaudit:database` owns Supabase RLS. `secaudit:realtime-security` owns who may subscribe to what
over websockets/SSE once a notification leaves Postgres. `secaudit:docker-security` §6 owns
Postgres published on `0.0.0.0` in compose.

## When to Use

- `drizzle.config.ts` exists, or code imports `drizzle-orm/pg-core`, `drizzle-orm/node-postgres`,
  `drizzle-orm/postgres-js`, `pg`, or `postgres`.
- The schema declares `pgPolicy`, `pgRole`, `crudPolicy`, `.enableRLS()`, or `pgTable.withRLS`.
- Any `set_config`, `current_setting`, `SET LOCAL`, or `SET ROLE` in application code or policies.
- LISTEN/NOTIFY, `pg_notify`, `sql.listen` (postgres.js), or `client.on('notification')` (pg).
- `pg_advisory_lock`, `pg_advisory_xact_lock`, `pg_try_advisory_*`.
- PgBouncer (`pgbouncer.ini`, `pool_mode`), a `:6432` connection string, or a managed pooler.
- A worker that runs `pg_dump` / `pg_dumpall`, or a cron/backup container with Postgres client tools.
- `postgresql.conf`, `pg_hba.conf`, or a compose/Helm file configuring the Postgres server.

Review grep heuristics:

```bash
# RLS declared in Drizzle, and how schema reaches the database
grep -rnE "pgPolicy|pgRole|crudPolicy|enableRLS\(|withRLS|FORCE ROW LEVEL" --include='*.ts' --include='*.sql' .
grep -rnE "drizzle-kit (push|migrate)|migrate\(" package.json Dockerfile* .github/ scripts/ 2>/dev/null
# tenant context: session-scoped set_config, or a policy that fails open on a missing GUC
grep -rnE "set_config\(" --include='*.ts' --include='*.sql' . | grep -viE "true\s*\)"
grep -rnE "current_setting\([^)]*\)\s*(IS NULL|=\s*'')" --include='*.ts' --include='*.sql' .
# LISTEN/NOTIFY: dynamic channels, full-row payloads
grep -rnE "LISTEN |pg_notify|NOTIFY |\.listen\(|on\('notification'" --include='*.ts' --include='*.sql' .
grep -rnE "row_to_json\(NEW\)|to_jsonb\(NEW\)" --include='*.sql' --include='*.ts' .
# advisory locks: session-level, hashed keys
grep -rnE "pg_(try_)?advisory_(xact_)?lock|hashtext\(" --include='*.ts' --include='*.sql' .
# SECURITY DEFINER without a pinned search_path
grep -rniE "security definer" --include='*.sql' --include='*.ts' . | grep -viE "search_path"
# server config, auth, TLS, pooler, logging, backups
grep -rnE "^\s*(listen_addresses|log_statement|pool_mode)\s*=|^\s*host.*\btrust\b" \
  --include='*.conf' --include='*.ini' . 2>/dev/null
grep -rnE "POSTGRES_HOST_AUTH_METHOD|sslmode=|ssl:\s*'(require|prefer)'|rejectUnauthorized|pg_dump" . 2>/dev/null
```

## 1. Drizzle RLS Declared in the Schema, Not in Force in the Database

Drizzle can declare RLS alongside the table. The API differs by major version — check which one
the lockfile resolves:

- `drizzle-orm` 0.45.x (the npm `latest` tag): `pgTable('t', {...}).enableRLS()`.
- `drizzle-orm` 1.0 (release candidates; what orm.drizzle.team now documents):
  `pgTable.withRLS('t', {...})`. The 1.0 type definitions mark `enableRLS` `@deprecated`.
- Both: `pgPolicy(name, { as, to, for, using, withCheck })` in the table's extra-config array,
  `pgRole(name, { createRole, createDb, inherit })`, `pgRole(name).existing()`, and
  `crudPolicy({ role, read, modify })` from `drizzle-orm/neon` (a wrapper that expands to four
  `pgPolicy` entries). Per the Drizzle docs, "If you add a policy to a table, RLS will be enabled
  automatically."

A `pgPolicy` is only a declaration. Four ways it ends up protecting nothing:

**a. The app connects as a role that bypasses it.** This is `secaudit:prisma-security` §2 in full
— superusers and `BYPASSRLS` roles always bypass RLS, table owners bypass it unless the table has
`FORCE ROW LEVEL SECURITY` — and it is the default outcome on Drizzle, because the URL in
`drizzle.config.ts` (the role that runs `drizzle-kit migrate` and therefore owns every table) is
usually the same `DATABASE_URL` the app uses. The Drizzle-specific twist: **drizzle-kit never emits
`FORCE ROW LEVEL SECURITY`.** Tested on `drizzle-kit` 0.31.11: `generate` on a table with a
`pgPolicy` produced `ENABLE ROW LEVEL SECURITY` and `CREATE POLICY`, and the published bundle
contains no `FORCE` DDL string at all; a string search of the 1.0.0-rc.4 bundle likewise found only
`ENABLE` / `DISABLE ROW LEVEL SECURITY`. If you need `FORCE`,
it goes in a custom migration (`drizzle-kit generate --custom`), and the real fix is still a
separate non-owner runtime role (§2).

**b. `drizzle-kit push` removes RLS it did not create.** `push` introspects the live database,
diffs it against `schema.ts`, and applies the difference. Tested on `drizzle-kit` 0.31.11 against a
table whose RLS was added by hand-written SQL (not in `schema.ts`), `push --force` printed and
executed:

```sql
ALTER TABLE "posts" DISABLE ROW LEVEL SECURITY;
DROP POLICY "tenant" ON "posts" CASCADE;
```

So a team that keeps policies in raw `.sql` files and also runs `push` (the Drizzle docs call it
"the best approach for rapid prototyping", and it is common in deploy scripts) silently turns RLS
off on every deploy. Either declare every policy in `schema.ts`, or never run `push` against an
environment that matters — apply versioned migrations with `drizzle-kit migrate` / `migrate()`.

**c. The policy targets a role the app never uses.** `to: appUser` compiles to
`TO "app_user"`. If the app connects as any other role, no permissive policy applies, and RLS
with no applicable policy is default-deny — PostgreSQL: "If no policy exists for the table, a
default-deny policy is used, meaning that no rows are visible or can be modified." The same holds
for restrictive-only tables: "If only restrictive policies exist, then no records will be
accessible." Empty results are the correct failure, but they are what pushes developers into (a):
"RLS broke the app, switch `DATABASE_URL` back to the owner." Treat that change as a critical
finding wherever you see it in history.

**d. Role management is off.** `entities.roles` in `drizzle.config.ts` defaults to `false`
("By default, drizzle-kit won't manage roles for you"), and `pgRole` options cover only
`createRole`, `createDb`, and `inherit` — there is no way to declare `LOGIN`, `NOBYPASSRLS`, or a
password. Create the runtime login role out of band (§2) and reference it with `.existing()`.

Verify against the target database, not the schema file:

```sql
-- RLS on, forced, and which policies exist, for every table in the app schema
SELECT c.relname, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced,
       (SELECT count(*) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname) AS policies
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
ORDER BY rls, c.relname;
```

## 2. The Runtime Role: Not the Owner, Not BYPASSRLS — Summary and the Drizzle Shape

The rule, from `secaudit:prisma-security` §2: the role in the app's connection string must be
`NOSUPERUSER NOBYPASSRLS` and must not own the tables, verified with
`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user` run **through the app's
own connection**. Unique and foreign-key checks still bypass RLS (an existence oracle) — see that
section. The Drizzle wiring that implements it:

```ts
// BAD — one URL for both; the runtime role owns every table it migrated, so every policy is inert
// drizzle.config.ts
export default defineConfig({ dialect: 'postgresql', schema: './src/db/schema.ts',
  dbCredentials: { url: process.env.DATABASE_URL! } });
// src/db/index.ts
export const db = drizzle(process.env.DATABASE_URL!);
```

```ts
// GOOD — migrations run as the owner; the Hono API, Next.js app and workers connect as app_rt
// drizzle.config.ts (used only by CI/deploy, never by the running app)
export default defineConfig({ dialect: 'postgresql', schema: './src/db/schema.ts',
  dbCredentials: { url: process.env.MIGRATION_DATABASE_URL! } });
// src/db/index.ts
export const db = drizzle(process.env.DATABASE_URL!); // postgresql://app_rt:...@db/app
```

```sql
-- once, as the owner (custom migration or bootstrap script)
CREATE ROLE app_rt LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA public TO app_rt;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rt;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_rt;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rt;    -- see §8 for why FOR ROLE matters
```

Note what is absent: `GRANT ALL` (which includes `TRUNCATE` — and "Operations that apply to the
whole table, such as TRUNCATE and REFERENCES, are not subject to row security"), and `CREATE` on
any schema.

**`SET LOCAL ROLE` patterns.** Some stacks connect as an "authenticator" role and switch with
`SET LOCAL ROLE` per transaction. Drizzle's own RLS page links a Supabase example (`createDrizzle`)
that does `set local role ${sql.raw(token.role ?? "anon")}` and splices JWT claims into
`set_config` with `sql.raw(JSON.stringify(token))`. Do not copy that shape: `sql.raw` of a claim is
injection (`secaudit:data-access`), and a role name taken from a token is a privilege choice made
by whoever minted the token. Map an allow-listed set of role names server-side, and bind values as
parameters (§3). The login role must not itself be a superuser or owner — `RESET ROLE` is one
statement away for any injected SQL.

## 3. Tenant Context in Drizzle Transactions — and the NULL vs Empty-String Trap

The pooled-connection leak from `set_config(..., false)` is `secaudit:prisma-security` §3. In
Drizzle, the safe form is `db.transaction` with a transaction-local setting, and **every query
in the callback must use `tx`, not `db`** — `db` checks out a different pooled connection that has
no context. node-postgres says the same at the driver level: "You must use the same client instance
for all statements within a transaction."

```ts
// BAD — session-scoped; the next request on this pooled connection inherits community A
await db.execute(sql`select set_config('app.community_id', ${communityId}, false)`);
return db.select().from(messages);

// BAD — transaction-local, but the read runs on another connection with no context
await db.transaction(async (tx) => {
  await tx.execute(sql`select set_config('app.community_id', ${communityId}, true)`);
  return db.select().from(messages);              // `db`, not `tx`
});
```

```ts
// GOOD — one helper every route goes through; the id comes from the verified session + membership
export async function withCommunity<T>(c: Context, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const session = await requireSession(c);                         // server-verified, never a header
  const communityId = c.req.param('communityId');
  await assertMember(session.userId, communityId);                  // or 404
  return db.transaction(async (tx) => {
    await tx.execute(sql`select set_config('app.community_id', ${communityId}, true)`); // bound $1
    return fn(tx);
  });
}
```

With a non-owner runtime role (§2), a route that forgets `withCommunity` and queries `db` directly
gets zero rows instead of every community — the missing helper fails closed. As the owner, the
same bug returns the whole table.

**What `current_setting(name, true)` returns is not stable across a connection's life.** The docs
promise NULL "if there is no such setting". Observed on PostgreSQL 17: a connection that has
**never** set `app.community_id` gets NULL, but once any transaction on that connection has run
`set_config('app.community_id', ..., true)`, after commit the same call returns `''` (empty
string), not NULL. Pooled connections spend most of their life in the second state. That decides
whether a policy fails open, fails loud, or fails closed:

```sql
-- BAD (fails OPEN) — the "no context = background job" escape hatch; a fresh connection sees everything
CREATE POLICY msgs_tenant ON messages TO app_rt
  USING (current_setting('app.community_id', true) IS NULL
         OR community_id = current_setting('app.community_id', true)::uuid);

-- FRAGILE (fails loud, intermittently) — on a reused connection ''::uuid raises
-- "invalid input syntax for type uuid", only in production, only on some requests — which is how
-- the escape hatch above gets added as the "fix"
CREATE POLICY msgs_tenant ON messages TO app_rt
  USING (community_id = current_setting('app.community_id', true)::uuid);

-- GOOD (fails CLOSED) — unset and reset both normalise to NULL; NULL matches no row
CREATE POLICY msgs_tenant ON messages TO app_rt
  USING      (community_id = nullif(current_setting('app.community_id', true), '')::uuid)
  WITH CHECK (community_id = nullif(current_setting('app.community_id', true), '')::uuid);
```

USING and WITH CHECK both treat NULL as not-true: a USING expression that is "false or null" hides
the row; a WITH CHECK that is "false or null" raises an error. Always give write policies a
`WITH CHECK` (or rely on the implicit copy of `USING` for `FOR ALL`) so an insert cannot name
another community. Cross-tenant workers (backups, fan-out, billing) get their own role and an
explicit policy, never "context unset means all rows".

## 4. PgBouncer Transaction Pooling Breaks Session State, LISTEN, and Session Locks

PgBouncer's feature map marks these **Never** supported in transaction pooling mode: `SET/RESET`,
`LISTEN`, `WITH HOLD CURSOR`, `PREPARE / DEALLOCATE`, `PRESERVE/DELETE ROWS temp tables`, `LOAD`,
and **session-level advisory locks**. `NOTIFY` works. The docs are blunt: "'transaction' pooling
breaks client expectations of the server by design and can be used only if the application
cooperates by not using non-working features." And the cleanup you might count on does not run:
"When transaction pooling is used, the server_reset_query is not used."

What that means for security, concretely:

- **Session GUCs leak deterministically.** A `set_config(..., false)` or plain `SET` lands on
  whichever server connection served that transaction and stays there for the next client. In
  session pooling `DISCARD ALL` would clean it; in transaction pooling nothing does. §3's
  transaction-local form is the only safe one behind PgBouncer.
- **LISTEN registers on a server connection you do not keep.** Notifications go to whichever
  client next holds that connection, or nowhere. Run listeners on a dedicated direct connection to
  Postgres (postgres.js `sql.listen` already opens "a dedicated connection"; with `pg`, a standalone
  `new Client()`, not a pool), and point that one URL past PgBouncer.
- **Session advisory locks outlive the request.** `pg_advisory_lock` held on a pooled server
  connection is never released by the client that took it, and another client can later "own" it.
  Use only `pg_advisory_xact_lock` (§6) behind a transaction pooler.

Keep `pool_mode = transaction` only for clients that use transaction-local state exclusively (the
Hono API after §3); give LISTEN and any session-lock user a direct DSN that bypasses PgBouncer.

PgBouncer itself has had serious auth bugs: 1.26.1 (2026-10-14) fixes CVE-2026-107350, where a
user who knows the password of any user listed in `auth_file` "could use this to log in as any other
user that authenticates using SCRAM, including admins and backend superusers" (1.17.0 through
1.26.0); 1.25.1 fixed CVE-2025-12819, arbitrary SQL during authentication via a malicious
`search_path` startup parameter when `track_extra_parameters` includes `search_path`, `auth_user`
is set, and `auth_query` is not schema-qualified. Floor: PgBouncer 1.26.1.

## 5. LISTEN/NOTIFY: Payloads Bypass RLS and Any Connected Role Can Listen

The LISTEN reference page lists no privilege requirement — the channel is "any identifier" — and
the NOTIFY page states it outright: "The NOTIFY command sends a notification event together with an
optional 'payload' string to each client application that has previously executed LISTEN channel
for the specified channel name in the current database. **Notifications are visible to all users.**"
Notifications are not rows: no table privilege, no RLS policy, nothing filters them. Tested on
PostgreSQL 17: a role with no `SELECT` on a forced-RLS table ran `LISTEN community_42` and received
`{"id":1,"community_id":"42","body":"private message text"}` from an insert trigger.

So the threat is any credential with `CONNECT` on the database — and `CONNECT` is granted to
`PUBLIC` by default — including an analytics/read-only role, a leaked worker credential, or SQL
injection anywhere in the app. Guessing channel names is trivial when they are `community_<id>`.

```sql
-- BAD — full row, including content and author email, to anyone listening on the channel
CREATE FUNCTION notify_message() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('community_' || NEW.community_id, row_to_json(NEW)::text);
  RETURN NEW;
END $$;
```

```sql
-- GOOD — id-only signal on a fixed channel; the payload reveals nothing worth stealing
CREATE FUNCTION notify_message() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('message_events',
    json_build_object('community_id', NEW.community_id, 'message_id', NEW.id)::text);
  RETURN NEW;
END $$;
```

```ts
// GOOD — the fan-out worker re-reads under each subscriber's own RLS context before sending
await sql.listen('message_events', async (raw) => {
  const { community_id, message_id } = JSON.parse(raw);
  for (const sub of hub.subscribersOf(community_id)) {            // authorization: realtime-security
    const row = await withSubscriberContext(sub, (tx) =>
      tx.select().from(messages).where(eq(messages.id, message_id)));
    if (row.length) sub.send(row[0]);                              // nothing if RLS hides it
  }
});
```

Re-fetching per subscriber is what makes RLS, membership changes, and per-message visibility apply
to realtime too; who may join `hub.subscribersOf(...)` at all is `secaudit:realtime-security`.

**Channel names are identifiers, not parameters.** `LISTEN` and `NOTIFY` take an identifier, so a
channel built from input and concatenated into `LISTEN ${name}` is SQL injection. Use
`pg_notify(text, text)` for sending — the docs: "much easier to use than the NOTIFY command if you
need to work with non-constant channel names and payloads" — and for `LISTEN` either a fixed
channel (preferred) or proper identifier quoting: postgres.js `sql.listen(name)` double-quotes and
escapes the name; with `pg` use `escapeIdentifier` from `pg`. Observed on PostgreSQL 17: a 64-byte
channel name fails with "channel name too long" (identifiers are capped by `NAMEDATALEN`).

**Payload limits are a write-path DoS.** "In the default configuration it must be shorter than 8000
bytes." Over that, `pg_notify` raises "payload string too long" — inside an `AFTER INSERT` trigger
that aborts the user's write. A trigger that serializes user-controlled content into the payload
lets any user make their own (or a shared) write path fail. Id-only payloads avoid both the leak
and the limit. Separately, the notification queue cannot be cleaned while a listening session sits
in a long transaction; "If this queue becomes full, transactions calling NOTIFY will fail at
commit."

## 6. Advisory Locks: Key Collisions, Pooled Sessions, and Locks Held Across Awaits

Advisory locks are application-defined and unenforced: "the system does not enforce their use — it
is up to the application to use them correctly." Keys are "either a single 64-bit key value or two
32-bit key values (note that these two key spaces do not overlap)", and "Advisory locks are local to
each database" — every subsystem in that database shares one key space.

**Hashed keys collide across tenants.** `pg_advisory_xact_lock(hashtext(community_id::text))`
squeezes a UUID into `hashtext`'s 32-bit integer result (observed return type: `integer`). By the
birthday bound, a 50% chance of at least one colliding pair arrives at roughly 77,000 communities.
A collision is not a data leak — it means community A's event ordering blocks behind community B's,
and a slow or stuck holder in one tenant stalls another. Also check every other `pg_advisory_*` call
in the database for overlap with the same integers.

```ts
// BAD — 32-bit hash of a UUID; collisions serialize unrelated communities
await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${communityId}))`);

// GOOD — two-int form: a fixed namespace for this subsystem + an integer surrogate key per community
const EVENT_ORDERING = 1001;
await tx.execute(sql`select pg_advisory_xact_lock(${EVENT_ORDERING}, ${community.lockKey})`);

// GOOD (often simpler) — a real row lock on the community's sequence row; no key space at all
await tx.execute(sql`select 1 from community_event_seq where community_id = ${communityId} for update`);
```

**Session locks survive the transaction — and the request.** "Once acquired at session level, an
advisory lock is held until explicitly released or the session ends", and "a lock acquired during a
transaction that is later rolled back will still be held following the rollback." On a pooled
connection the session does not end when the request does: a handler that throws between
`pg_advisory_lock` and `pg_advisory_unlock` leaves that community locked for the life of the pool
connection. Prefer `pg_advisory_xact_lock` / `pg_try_advisory_xact_lock`, which are released at
transaction end and have "no provision for manual release".

**A transaction-level lock outside a transaction does nothing.** `db.execute(sql\`select
pg_advisory_xact_lock(...)\`)` on its own runs as a single-statement transaction, so the lock is
released before the next `db.insert(...)` executes. The lock and the work it orders must share one
`db.transaction(async (tx) => ...)`.

**Never hold a lock across a network await.** Inside the locked transaction, do the database
writes and nothing else — no Discord/webhook/HTTP call, no LLM call, no S3 upload. A slow upstream
then holds a per-community lock, and every writer for that community queues behind it (and holds a
pooled connection while it waits). Cap the blast radius with per-role timeouts:

```sql
ALTER ROLE app_rt SET lock_timeout = '2s';
ALTER ROLE app_rt SET idle_in_transaction_session_timeout = '15s';
ALTER ROLE app_rt SET transaction_timeout = '30s';     -- PostgreSQL 17+ only; not available on 16
```

**Advisory locks are not authorization.** Any role that can connect can call the advisory lock
functions (they are executable by `PUBLIC` — observed with an unprivileged role on PostgreSQL 17).
A leaked low-privilege credential can take `pg_advisory_lock(1001, <key>)` and hold it for as long
as it keeps the connection open, stalling that community's event pipeline. Never use "I got the
lock" as proof a caller may act on a community; check membership, and alert on long-held advisory
locks (`pg_locks WHERE locktype = 'advisory'`).

## 7. SECURITY DEFINER Functions Without a Pinned `search_path`

RLS helpers (`is_member(community_id)`) are often written `SECURITY DEFINER` to avoid recursive
policies. Such a function "is executed with the privileges of the user that owns it" — if the owner
is the table owner or a superuser, the function body bypasses RLS on everything it touches. That is
the point, so the body must be narrow, and its name resolution must be pinned. The docs:
"search_path should be set to exclude any schemas writable by untrusted users... Particularly
important in this regard is the temporary-table schema, which is searched first by default, and is
normally writable by anyone."

```sql
-- BAD — unqualified `memberships` resolves via the caller's search_path; a caller who can create
-- a temp table or an object in a writable schema substitutes their own `memberships`
CREATE FUNCTION is_member(cid uuid) RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$
  SELECT EXISTS (SELECT 1 FROM memberships WHERE community_id = cid
                 AND user_id = current_setting('app.user_id', true)::uuid) $$;

-- GOOD — trusted schema first, pg_temp last; qualified names; EXECUTE revoked from PUBLIC
BEGIN;
CREATE FUNCTION app_private.is_member(cid uuid) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = app_private, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM app_private.memberships m WHERE m.community_id = cid
                 AND m.user_id = nullif(current_setting('app.user_id', true), '')::uuid) $$;
REVOKE ALL ON FUNCTION app_private.is_member(uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA app_private TO app_rt;
GRANT EXECUTE ON FUNCTION app_private.is_member(uuid) TO app_rt;
COMMIT;
```

The `REVOKE` matters because "by default, execute privilege is granted to PUBLIC for newly created
functions", and the docs recommend doing it in the same transaction as `CREATE` so there is no
window. Keep definer functions out of any schema an API layer auto-exposes.

## 8. Schema and Grant Hygiene: PG15 `public`, Default Privileges, Migration vs Runtime

**`public` schema.** PostgreSQL 15 removed `PUBLIC`'s `CREATE` permission on the `public` schema —
but only for new clusters and new databases: "Upgrading a cluster or restoring a database dump will
preserve public's existing permissions." A database that started on 14 or earlier and was upgraded
to 16 still lets every role create objects in `public`, which (per the schema docs) "effectively
trusts all users having CREATE privilege on that schema" for anyone whose `search_path` includes it.

```sql
-- check, then fix on upgraded databases
SELECT has_schema_privilege('public', 'public', 'CREATE');   -- must be false
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

**`ALTER DEFAULT PRIVILEGES` covers only the future, and only one creator.** It sets "the
privileges that will be applied to objects created in the future. (It does not affect privileges
assigned to already-existing objects.)", and applies to objects "created by the target_role, or the
current role if unspecified." A default-privileges statement run by a DBA as themselves does
nothing for tables later created by the migration role. Write it as
`ALTER DEFAULT PRIVILEGES FOR ROLE app_owner ...` (§2) and re-run the explicit `GRANT ... ON ALL
TABLES` for tables that already exist.

**Separate the roles and check them.** Migration/owner role: owns objects, used only by CI/deploy.
Runtime role: DML grants only. Backup role: read-only plus `BYPASSRLS` (§10). Worker roles: only the
tables they touch. Flag `GRANT ALL`, any runtime role with `CREATE` on a schema, any runtime role
that owns a table, and any role with `rolsuper` other than the bootstrap superuser:

```sql
SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin
FROM pg_roles WHERE rolname !~ '^pg_' ORDER BY rolsuper DESC, rolbypassrls DESC;
SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public';  -- owner must not be app_rt
```

## 9. Network Exposure, Authentication, and TLS

- **`listen_addresses`**: "The default value is localhost, which allows only local TCP/IP
  'loopback' connections." Anything wider (`*`, `0.0.0.0`) must be justified by a private network
  plus `pg_hba.conf` restrictions. In compose, Postgres reached by service name needs no host port
  at all — `secaudit:docker-security` §6.
- **`pg_hba.conf` `trust`**: "This method allows anyone that can connect to the PostgreSQL database
  server to login as any PostgreSQL user they wish, without the need for a password." Any `host ...
  trust` line is a finding unless the address is loopback on a single-user machine. In the official
  Docker image, `POSTGRES_HOST_AUTH_METHOD=trust` writes `host all all all trust` — every address,
  every user. "The first record with a matching connection type, client address, requested
  database, and user name is used", so a broad `trust` line above a `scram-sha-256` line wins.
- **TLS**: the libpq default `sslmode` is `prefer`, which the docs say "makes no sense from a
  security point of view". Use `verify-full` with a pinned CA. The `sslmode=require` and node-postgres
  `rejectUnauthorized: false` holes are `secaudit:prisma-security` §7. postgres.js has the same hole
  in its own code: `ssl: 'require'`, `'prefer'`, or `'allow'` (or the matching `?sslmode=`) all set
  `rejectUnauthorized = false`, and its README's cloud-provider sample does so explicitly while
  noting it is "vulnerable to MITM attacks". Pass `ssl: { ca: fs.readFileSync(caPath) }` (or `sslmode=verify-full` with the CA in the
  system trust store).

```ts
// BAD — encrypted, unauthenticated
const sql = postgres(process.env.DATABASE_URL!, { ssl: 'require' });
// GOOD — server certificate verified against the database CA, hostname checked by Node's TLS
const sql = postgres(process.env.DATABASE_URL!, { ssl: { ca: readFileSync('/etc/ssl/db-ca.pem') } });
```

## 10. Backups: The Dump Is the Whole Database, Unfiltered

`pg_dump` does not respect RLS by default — it refuses to be filtered: "By default, pg_dump will
set row_security to off, to ensure that all data is dumped from the table. If the user does not
have sufficient privileges to bypass row security, then an error is thrown." (Verified: a role with
`pg_read_all_data` but no `BYPASSRLS` fails with "query would be affected by row-level security
policy"; adding `BYPASSRLS` dumps every row.) So the backup worker's credential is necessarily one
of the most powerful in the system, and every dump contains every tenant's data, password hashes,
session/API token hashes, and every encrypted column's ciphertext.

```bash
# BAD — superuser, plaintext dump, uploaded to the same bucket the app writes user files to,
# with the app's field-encryption key sitting in the same worker env
pg_dump "postgresql://postgres:pw@db/app" | gzip > /backups/app.sql.gz
aws s3 cp /backups/app.sql.gz s3://app-uploads/backups/
```

```bash
# GOOD — least-privilege backup role, encrypted before it leaves the host, separate bucket
#   CREATE ROLE backup_rt LOGIN BYPASSRLS; GRANT pg_read_all_data TO backup_rt;
pg_dump --format=custom "postgresql://backup_rt@db/app?sslmode=verify-full" \
  | age -r "$BACKUP_PUBLIC_KEY" > "app-$(date +%F).dump.age"
aws s3 cp "app-$(date +%F).dump.age" s3://app-backups-writeonly/
```

Rules that follow from "the dump is everything":

- **Keys never travel with the dump.** If application-level encryption keys (field encryption,
  token-encryption keys) live in the same env/secret store the backup worker reads, or in the same
  bucket, the ciphertext in the dump is plaintext to whoever gets the bucket. The worker needs the
  backup *public* key only; the private key lives offline or in a separate KMS scope.
- **The bucket is a separate trust zone:** write-only credential for the worker, no public access,
  versioning/object lock for ransomware resistance, lifecycle expiry — `secaudit:object-storage-security`.
- **Test restores**, into an isolated environment, on a schedule. Restoring a dump runs its SQL
  with the restoring role's privileges, so restore only dumps you produced.
- **Patch the client tools in the worker image.** `pg_dump` / `psql` have had code-execution bugs
  triggered by a hostile object creator or origin server: CVE-2024-7348 (relation replacement during
  `pg_dump` executes arbitrary SQL as the dumping user, before 16.4), CVE-2025-8714 and CVE-2025-8715
  (code execution in `psql` / the restore target via a dump, before 16.10), CVE-2026-19385 (`pg_dump`
  heap overflow executing code as the OS user, before 16.15) and CVE-2026-18408 (`psql`
  `\unrestrict`, before 16.15). The backup container's client package version is what matters, and
  it is often older than the server.

## 11. Logging: `log_statement = all` Writes Secrets to Disk

`log_statement = all` logs every statement, and "For clients using extended query protocol, logging
occurs when an Execute message is received, and values of the Bind parameters are included." Every
ORM uses the extended protocol, so the server log receives every bound value: password hashes on
insert, session and reset tokens on lookup, OAuth tokens, PII. `log_min_duration_statement = 0`
does the same for every statement's text. And `CREATE ROLE ... PASSWORD '...'` / `ALTER ROLE ...
PASSWORD` in a migration "might also be logged in the client's command history or the server log".

```conf
# BAD — debugging setting left on in production
log_statement = 'all'

# GOOD — DDL audit trail without data; bind parameters never logged in full
log_statement = 'ddl'
log_parameter_max_length = 0          # 0 disables bind-parameter logging for non-error statements
log_parameter_max_length_on_error = 0
```

Set role passwords with `\password` in psql or a pre-hashed SCRAM verifier (a `PASSWORD` string
"already in MD5-encrypted or SCRAM-encrypted format ... is stored as-is"), not a plaintext literal
in a migration file. Treat Postgres logs as sensitive data for retention and access purposes —
`secaudit:logging-monitoring`.

## 12. Server Version Floor

Several 2024–2026 server fixes touch RLS and privileges directly: CVE-2026-14666 (row-security
policy caching ignores role membership/attribute changes, so a revoked user can keep reading or
writing until the cache is invalidated; fixed 16.15 / 17.11 / 18.6), CVE-2024-10976 (row security
below subqueries, CTEs, security-invoker views, and SQL functions disregards user-ID changes such as
`SET ROLE` and SECURITY DEFINER; fixed 16.5 / 17.1), and CVE-2025-8713 (optimizer statistics expose
sampled values that RLS hides in partitioning/inheritance hierarchies; fixed 16.10 / 17.6). The
2026-08-13 release also fixes a batch of authenticated code-execution bugs. Floor: **16.15,
17.11, or 18.6** — check `SELECT version()` on the running server, not the compose tag.

## Postgres Footgun Checklist

- Check `relrowsecurity` / `relforcerowsecurity` / `pg_policies` live; drizzle-kit never emits `FORCE`.
- One role for `drizzle.config.ts` and the app = owner = inert RLS; `push` drops hand-written policies.
- Default-deny empty results "fixed" by reconnecting as the owner is the real vulnerability.
- `set_config(..., false)` leaks across pooled connections; inside `db.transaction` use `tx`.
- `current_setting(name, true)` is NULL fresh and `''` after an earlier local set — use
  `nullif(..., '')`, never `IS NULL OR ...`.
- PgBouncer transaction mode: no `SET`, `LISTEN`, session advisory locks, or reset query; ≥ 1.26.1.
- NOTIFY payloads reach any session that LISTENs, regardless of grants or RLS — send ids, re-fetch
  under the subscriber's context. Channel names are identifiers; payloads over 8000 bytes fail writes.
- `hashtext()` advisory keys are 32-bit and collide across tenants; use two-int keys or a row lock.
- Session locks outlive the request; xact locks outside a transaction do nothing; no network awaits.
- SECURITY DEFINER without `SET search_path = trusted, pg_temp` and `REVOKE ... FROM PUBLIC`.
- Upgraded-from-≤14 databases still grant `CREATE` on `public`; `ALTER DEFAULT PRIVILEGES` without
  `FOR ROLE <migration role>` misses the migration role's new tables.
- `host ... trust`, `listen_addresses = '*'`, postgres.js `ssl: 'require'` (no cert verification).
- Dumps are everything: encrypt, keys elsewhere, separate bucket, test restores, patch `pg_dump`.
- `log_statement = 'all'` logs every bound secret. Server below 16.15 / 17.11 / 18.6.

## Related skills

- `secaudit:prisma-security` — §2 owner/BYPASSRLS bypass and `FORCE`, §3 transaction-local
  `set_config`, §7 `sslmode=require`; this skill gives the Drizzle form.
- `secaudit:data-access` — Drizzle `sql.raw()`, identifier injection (CVE-2026-39356).
- `secaudit:database` — Supabase RLS. `secaudit:realtime-security` — websocket/SSE fan-out authz.
- `secaudit:object-storage-security` — the backup bucket. `secaudit:docker-security` — `0.0.0.0`.
- `secaudit:secrets` (DB credentials), `secaudit:cryptography` (keys for what ends up in dumps),
  `secaudit:logging-monitoring` (log retention), `secaudit:framework-versions` (`drizzle-orm`).

## Sources

- https://orm.drizzle.team/docs/rls -- `pgTable.withRLS`, `pgPolicy` options (`as`/`to`/`for`/`using`/`withCheck`), `pgRole` options and `.existing()`, `crudPolicy` from `drizzle-orm/neon`, policies auto-enable RLS, `entities.roles` off by default, `createDrizzle` sample using `sql.raw` and `set local role`
- https://orm.drizzle.team/docs/drizzle-kit-push -- push introspects the database, diffs, and applies; "best approach for rapid prototyping"
- https://orm.drizzle.team/docs/drizzle-config-file -- `entities.roles` default false; `dbCredentials`
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html -- default-deny with no policy; owner/superuser/BYPASSRLS bypass; TRUNCATE and REFERENCES not subject to RLS; `row_security = off` throws instead of filtering
- https://www.postgresql.org/docs/current/sql-createpolicy.html -- permissive vs restrictive, restrictive-only denies all, USING vs WITH CHECK null handling
- https://www.postgresql.org/docs/current/functions-admin.html -- `set_config` is_local, `current_setting` missing_ok, advisory lock functions, 64-bit vs two-32-bit key spaces
- https://www.postgresql.org/docs/current/explicit-locking.html -- advisory locks unenforced; session locks survive rollback; transaction locks release at end (pg_locks: advisory locks are local to each database)
- https://www.postgresql.org/docs/current/runtime-config-client.html -- `lock_timeout`, `idle_in_transaction_session_timeout`, `transaction_timeout` (17+; absent from the 16 docs)
- https://www.postgresql.org/docs/current/sql-listen.html -- channel is any identifier; no privilege requirement listed; LISTEN takes effect at commit
- https://www.postgresql.org/docs/current/sql-notify.html -- "Notifications are visible to all users"; 8000-byte payload limit; `pg_notify(text, text)`; queue-full failure at commit
- https://www.postgresql.org/docs/current/sql-createfunction.html -- writing SECURITY DEFINER functions safely: `search_path` with `pg_temp` last, revoke EXECUTE from PUBLIC
- https://www.postgresql.org/docs/current/ddl-schemas.html -- CREATE on a search_path schema trusts its creators; PG15+ secure default; upgraded databases keep old grants
- https://www.postgresql.org/docs/release/15.0/ -- PUBLIC CREATE removed from `public`; upgrades and dump restores preserve existing permissions
- https://www.postgresql.org/docs/current/ddl-priv.html -- CONNECT on databases granted to PUBLIC by default
- https://www.postgresql.org/docs/current/predefined-roles.html -- `pg_read_all_data` does not bypass RLS
- https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html -- future objects only; scoped to objects created by the target role
- https://www.postgresql.org/docs/current/runtime-config-connection.html -- `listen_addresses` default localhost
- https://www.postgresql.org/docs/current/auth-pg-hba-conf.html -- `trust` allows login as any user; records matched in order
- https://github.com/docker-library/docs/blob/master/postgres/content.md -- official image: `POSTGRES_HOST_AUTH_METHOD` writes `host all all all <method>` to pg_hba.conf
- https://www.postgresql.org/docs/current/libpq-ssl.html -- default sslmode `prefer`; `verify-full` recommended
- https://www.postgresql.org/docs/current/app-pgdump.html -- pg_dump sets row_security off and errors without bypass privilege; `--enable-row-security`
- https://www.postgresql.org/docs/current/runtime-config-logging.html -- `log_statement` includes bind parameters; `log_parameter_max_length`
- https://www.postgresql.org/docs/current/sql-createrole.html -- plaintext PASSWORD may reach the server log; pre-hashed verifiers stored as-is
- https://www.postgresql.org/support/security/ -- CVE-2026-14666, CVE-2024-10976, CVE-2025-8713, CVE-2024-7348, CVE-2025-8714, CVE-2025-8715, CVE-2026-19385, CVE-2026-18408 and their fixed versions
- https://www.pgbouncer.org/features.html -- transaction pooling: SET/RESET, LISTEN, session advisory locks never supported; NOTIFY supported
- https://www.pgbouncer.org/config.html -- `server_reset_query` not used in transaction pooling; `max_prepared_statements`
- https://www.pgbouncer.org/changelog.html -- CVE-2026-107350 (1.26.1), CVE-2025-12819 (1.25.1)
- https://node-postgres.com/features/transactions -- same client instance for every statement in a transaction
- https://github.com/porsager/postgres -- `sql.listen` dedicated connection; `ssl` options; README `rejectUnauthorized: false` sample flagged as MITM-vulnerable
- https://github.com/porsager/postgres/blob/master/src/connection.js -- `ssl: 'require'` sets `rejectUnauthorized = false`
- https://top10.owasp.org/2025/ -- OWASP Top 10 (2025): A01, A02, A04, A05, A09 as mapped in the intro
