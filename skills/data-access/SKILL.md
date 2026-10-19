---
name: data-access
description: Audits data access and input validation — SQL injection, ORM operator injection (e.g. Prisma filter injection and $queryRawUnsafe), Drizzle raw SQL and identifier injection (sql.raw() triaged by value provenance, sql.identifier()/.as() aliases, dynamic orderBy), Drizzle write-path risks (drizzle-zod createInsertSchema without pick/omit, update/delete with no or non-tenant where, check-then-act races and .for('update'), the outer db used inside a transaction), SQLite/Turso/D1 specifics (no row-level security so tenant predicates are application code, database file and -wal/-shm exposure, auth tokens as secrets, prepared statements and bound params), runtime input validation at every boundary with a schema validator (Zod/Yup/Joi), and mass assignment from spread request bodies. Covers JS/TS (Prisma, Drizzle, better-sqlite3, libSQL, D1) and Python (SQLAlchemy text(), Pydantic). Use whenever writing or reviewing database queries, API handlers, Server Actions, webhook handlers, or form/URL input processing, or when auditing how untrusted input reaches the data layer.
license: MIT
---

# Data Access & Input Validation

## When to Use

- Writing or reviewing database queries (raw SQL or ORM).
- Handling external input in API routes, Server Actions, webhooks, forms, or URL params.
- Auditing how untrusted input reaches the data layer.
- The project uses Drizzle, better-sqlite3, Turso/libSQL, or Cloudflare D1.

## SQL Injection

Always use parameterized queries or ORM methods. Never concatenate user input into SQL strings:

```typescript
// BAD: SQL injection via string concatenation
const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);

// GOOD: parameterized query
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

## ORM Safety (Prisma)

Even with an ORM, injection is possible:

- **Validate input types with Zod before passing to Prisma.** `findFirst` and similar methods are
  vulnerable to operator injection if unvalidated objects are passed as filter values. An attacker
  can send `{ "email": { "contains": "" } }` to match all records.

```typescript
// BAD: raw request body passed directly to Prisma
const user = await prisma.user.findFirst({ where: req.body });

// GOOD: validate with Zod first
const schema = z.object({ email: z.string().email() });
const parsed = schema.parse(req.body);
const user = await prisma.user.findFirst({ where: { email: parsed.email } });
```

- **Never use `$queryRawUnsafe` or `$executeRawUnsafe` with user-supplied input.** These bypass
  Prisma's parameterization entirely.

```typescript
// BAD: raw SQL with user input
const results = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE name = '${name}'`
);

// GOOD: use the safe raw query with parameters
const results = await prisma.$queryRaw`
  SELECT * FROM users WHERE name = ${name}
`;
```

- **`Prisma.raw()` is as unsafe as `$queryRawUnsafe`,** even inside the "safe" `$queryRaw`.
  Assistants reach for it because identifiers (table, column, `ORDER BY`) cannot be template
  parameters. The fix is an allow-list map, not interpolation.

```typescript
// BAD: user input reaches Prisma.raw
await prisma.$queryRaw`SELECT * FROM "User" ORDER BY ${Prisma.raw(req.query.sort)} DESC`;

// GOOD: identifiers from an allow-list, values as parameters
const SORT = { name: '"name"', created: '"createdAt"' } as const;
const col = SORT[req.query.sort as keyof typeof SORT] ?? SORT.name;
await prisma.$queryRawUnsafe(`SELECT * FROM "User" ORDER BY ${col} DESC LIMIT $1`, take);
```

For tenant scoping, Postgres RLS under Prisma, and pgvector retrieval, see
`secaudit:prisma-security` — Prisma has no row-level security, so every query must carry the
tenant predicate itself.

## ORM Safety (SQLAlchemy)

`text()` is SQLAlchemy's escape hatch, and it is where "we use an ORM" stops protecting you. An
assistant reaches for it on any query the ORM makes awkward. Verified: the BAD form below returned
every row for an input of `' OR '1'='1`; the GOOD form returned zero.

```python
# BAD: f-string interpolation into text()
rows = conn.execute(text(f"SELECT id, email FROM users WHERE email = '{email}'")).all()

# GOOD: bound parameter
rows = conn.execute(text("SELECT id, email FROM users WHERE email = :email"),
                    {"email": email}).all()
```

The trap that *causes* the f-string: **you cannot bind an identifier** — column, table, `ORDER BY`,
`ASC`/`DESC`. Same fix as Prisma, an allow-list map:

```python
ALLOWED = {"id": users.c.id, "email": users.c.email}   # reject anything not a key
stmt = select(users).order_by(ALLOWED[sort_key])
```

Detection: `grep -rn "text(f\"\|text(f'\|\.execute(f\"" --include="*.py"`, then read every `text(`
whose argument is not a plain literal.

## ORM Safety (Drizzle)

Drizzle's `sql` template literal is safe by design: interpolated **values** become bound
placeholders (`$1`), and interpolated table/column **objects** become escaped identifiers.
`sql.raw()` is the opposite — the docs describe it as including raw SQL "without any additional
processing or escaping", and it stays raw even nested inside the `sql` template. An assistant
reaches for it the moment a query needs a dynamic identifier.

```typescript
// BAD: sql.raw() concatenates — no placeholder, no escaping
await db.execute(sql.raw(`select * from users where email = '${email}'`));

// GOOD: the template binds the value and escapes the identifiers
await db.execute(sql`select * from ${users} where ${users.email} = ${email}`);
```

- **Triage every `sql.raw()` by where its argument came from, not by the grep hit.** SAST tools
  rate any interpolated `sql.raw()` Critical ("easily exploitable") because they cannot see the
  value's origin. The auditor has to trace each argument back to its source and grade it:

| Argument origin | Severity | Reason |
|---|---|---|
| `req.query` / `body` / `params` / headers, a webhook payload, a JWT claim, a form field | **Critical** | attacker-controlled SQL, the BAD example above |
| A database column, tenant setting or third-party response that a user or org admin can write | **High** | stored injection: the payload sits in a row until the query runs |
| A compile-time constant: an `as const` array, an enum, a ternary between literals such as `sql.raw(asc ? '>' : '<')` | **Low / informational** | no attacker-reachable value; record it and move on |
| A helper that wraps `'${v}'` with no escaping, today fed only constants | **Low, latent footgun** | the next refactor (an enum that becomes a settings table) makes it Critical, and nothing in the helper stops it |

  The common legitimate case is a `CHECK (col in ('a','b'))` built from a domain enum. **Bound
  parameters are not the fix there:** DDL cannot take placeholders, and drizzle-kit 0.31 renders a
  `sql.join` of bound values inside `check()` as `CHECK ("t"."event" in ($1, $2))`, which Postgres
  rejects (verified). Use `sql.join` of bound values in *queries*, and in schema DDL escape the
  quote and restrict the helper to literal types so a plain `string` cannot reach it.

```typescript
const WEBHOOK_EVENTS = ['push', 'release'] as const;

// BAD (latent footgun): any value containing ' breaks out of the literal. With "b'c" drizzle-kit
// writes CHECK (event in ('a', 'b'c')) into the migration. Fine today, Critical the day a
// non-constant list is passed in.
const quoted = (vs: readonly string[]) => sql.raw(vs.map((v) => `'${v}'`).join(', '));
check('hooks_event_check', sql`${t.event} in (${quoted(WEBHOOK_EVENTS)})`);

// GOOD (schema DDL): double the quote, and refuse anything that is not a literal tuple
const inList = <const V extends readonly string[]>(
  values: V & (string extends V[number] ? never : unknown),
) => sql.raw(values.map((v) => `'${v.replace(/'/g, "''")}'`).join(', '));
check('hooks_event_check', sql`${t.event} in (${inList(WEBHOOK_EVENTS)})`);
// inList(req.body.events as string[]) is a compile error; the escaping covers the `as` cast

// GOOD (queries): values stay bound parameters
await db.execute(
  sql`select * from ${users} where ${users.role} in (${sql.join(roles.map((r) => sql`${r}`), sql`, `)})`,
);
await db.select().from(users).where(inArray(users.role, roles));   // simplest form
```

  The literal-type guard is compile-time only (`as string[]` defeats it), which is why the escaping
  stays. Doubling `'` is sufficient under Postgres's default `standard_conforming_strings = on`;
  never extend the helper to `E'...'` strings, and if a value could carry a backslash, validate
  against a charset (`/^[\w.:-]+$/`) instead.

  Detection:

```bash
grep -rnE "sql\.raw\(" --include="*.ts"                    # inventory
grep -rnE "sql\.raw\([^)]*[$][{]" --include="*.ts"         # interpolated: trace each argument
grep -rnE "'[$][{]\w+[}]'" --include="*.ts"                # quote-wrapping helpers
```

- **Identifiers built from request input were injectable even without `sql.raw()`.**
  `CVE-2026-39356` (`GHSA-gpj5-g38j-94v9`) — fixed 0.45.2 / 1.0.0-beta.20. Drizzle's
  dialect-specific `escapeName()` did not double the quote character, so a `"` (PostgreSQL,
  SQLite, Gel) or a backtick (MySQL, SingleStore) inside a `sql.identifier()` value or an `.as()`
  alias terminated the quoted identifier and injected SQL. Affected: drizzle-orm at or below
  0.45.1, and 1.0.0-beta.2 through 1.0.0-beta.19. Report builders and dynamic-sort endpoints are
  the typical sink. Upgrade **and** allow-list: the upgrade closes the escaping bypass, it does not
  make a user-chosen identifier a good idea.

```typescript
// BAD: the caller names the column and the alias — an identifier is not a bound parameter
const { column, label } = req.query;
await db.execute(
  sql`select ${sql.identifier(column)} as ${sql.identifier(label)} from ${users}`,
);

// GOOD: request input selects from a fixed map of column objects; the alias is a constant
const exportable = { email: users.email, name: users.name, createdAt: users.createdAt } as const;
const col = exportable[String(req.query.column) as keyof typeof exportable];
if (!col) throw new BadRequest("unknown column");
await db.select({ value: col }).from(users);
```

- **Dynamic `orderBy` or column selection from query params.** An identifier cannot be a bound
  parameter, so the fix is the same allow-list map as Prisma and SQLAlchemy — except here the map's
  values are Drizzle column objects, which the query builder escapes for you.

```typescript
// BAD: sort column and direction come straight off the query string
const rows = await db.select().from(users)
  .orderBy(sql.raw(`${req.query.sort} ${req.query.dir}`));

// GOOD: allow-list to column objects; direction to asc()/desc()
const SORT = { name: users.name, created: users.createdAt } as const;
const col = SORT[req.query.sort as keyof typeof SORT] ?? SORT.name;
const rows = await db.select().from(users)
  .orderBy(req.query.dir === 'asc' ? asc(col) : desc(col));
```

- **Build conditional queries with `$dynamic()`, not string pieces.** It is the supported way to
  add filters and pagination across function boundaries, and it keeps every fragment a query-builder
  call instead of a string an assistant can be tempted to interpolate into.

```typescript
let q = db.select().from(users).$dynamic();
if (parsed.role) q = q.where(eq(users.role, parsed.role));
q = q.limit(pageSize).offset((page - 1) * pageSize);
```

- **Use `sql.placeholder` for prepared statements.** Named placeholders stay bound parameters when
  the statement is reused; re-templating the value per call is how a prepared query quietly turns
  into string building.

```typescript
const byId = db.select().from(users)
  .where(eq(users.id, sql.placeholder('id'))).prepare('by_id');
const rows = await byId.execute({ id: parsed.id });
```

## Drizzle Write Paths: Unscoped Writes and Check-Then-Act Races

The select-only examples elsewhere in this skill are the easy half. `update` and `delete` are where
a missing predicate destroys data instead of leaking it, and where two concurrent requests turn a
correct-looking read-then-write into a double spend.

### Unscoped `update` / `delete`

Threat: a write whose `where` is missing, empty, or id-only touches every row, or another tenant's
row. Drizzle does not guard against it: `db.delete(t)` and `db.update(t).set(...)` with no
`.where()` run against the whole table (the delete docs introduce `db.delete(users)` with "You can delete all rows in the table"), and
there is no error and no warning.

```typescript
// BAD: no where() — every session row / every user is hit
await db.delete(sessions);
await db.update(users).set({ role: 'member' });

// BAD: id only — any caller can void any tenant's invoice
await db.update(invoices).set({ status: 'void' }).where(eq(invoices.id, id));

// BAD: and() of nothing is undefined, and .where(undefined) means "no filter" — verified:
// this compiles to `delete from "invoices"`
const filters: { id?: string } = parseFilters(req.query);
await db.delete(invoices).where(and(filters.id ? eq(invoices.id, filters.id) : undefined));

// GOOD: tenant from the server-verified session in the same where; the affected row is checked
const voided = await db.update(invoices).set({ status: 'void' })
  .where(and(eq(invoices.id, id), eq(invoices.orgId, session.orgId)))
  .returning({ id: invoices.id });
if (voided.length === 0) throw new NotFound();   // not found OR not yours: indistinguishable
```

- Build optional filters as an array and fail closed: `const conds = [...]; if (conds.length === 0)
  throw new Error('refusing unscoped write'); ...where(and(...conds))`.
- Check the affected rows (`.returning({ id })` and `.length`) so a miss is a 404, not a silent
  success. This is the same rule as the SQLite tenant example below and applies to every dialect;
  Prisma has the same hole with `update({ where: { id } })`: put the tenant in the `where` too, or use
  `updateMany({ where: { id, orgId } })` and check `count`.
- Postgres RLS (see `secaudit:postgres-security`) is the backstop for this, not a replacement: it
  only holds when the runtime role is neither the table owner nor `BYPASSRLS`.

Detection (multi-line aware; prints the statements to read):

```bash
# update/delete statements with no .where() at all
find . -name "*.ts" -not -path "*/node_modules/*" -print0 | xargs -0 perl -0ne \
  'while (/\b(?:db|tx)\.(?:update|delete)\(\s*\w+\s*\)[^;]*?;/g) { $m=$&; $m =~ s/\s+/ /g;
   print "$ARGV: $m\n" unless $m =~ /\.where\(/ }'

# .where() present but no tenant/owner column in it (edit the column names to match the schema);
# a hit that follows a tenant-scoped, locked read of the same row is fine
find . -name "*.ts" -not -path "*/node_modules/*" -print0 | xargs -0 perl -0ne \
  'while (/\b(?:db|tx)\.(?:update|delete)\(\s*\w+\s*\)[^;]*?;/g) { $m=$&; $m =~ s/\s+/ /g;
   print "$ARGV: $m\n" if $m =~ /\.where\(/ && $m !~ /(org|tenant|owner|user|workspace|team)Id/i }'
```

### Transactions and races

Threat: check-then-act. The handler reads a balance, quantity or counter, decides in JavaScript, then
writes. Under Postgres's default `READ COMMITTED` isolation two requests both read `100`, both pass
the check, both write: a double spend, an oversold item, a coupon redeemed twice. Wrapping the pair
in `db.transaction` alone does not stop this; the transaction has to lock the row or the write has
to be conditional. The same applies to a read-modify-write done in JS (`balance: acct.balance - amount`).

```typescript
// BAD: read, check in JS, write a JS-computed value — both requests see balance = 100
await db.transaction(async (tx) => {
  const [acct] = await tx.select().from(accounts).where(eq(accounts.id, id));
  if (!acct || acct.balance < amount) throw new InsufficientFunds();
  await tx.update(accounts).set({ balance: acct.balance - amount }).where(eq(accounts.id, id));
});

// BAD: the outer `db` inside the callback is a different connection — it is outside the
// transaction, does not see its uncommitted rows, and is not rolled back with it
await db.transaction(async (tx) => {
  await tx.update(accounts).set({ balance: 0 }).where(eq(accounts.id, id));
  await db.insert(auditLog).values({ accountId: id });
});
```

```typescript
// GOOD 1: lock the row for the length of the transaction (Postgres/MySQL), compute in SQL
await db.transaction(async (tx) => {
  const [acct] = await tx.select().from(accounts)
    .where(and(eq(accounts.id, id), eq(accounts.orgId, session.orgId)))
    .for('update');                       // other writers wait here until we commit
  if (!acct || acct.balance < amount) throw new InsufficientFunds();   // a throw rolls back
  await tx.update(accounts).set({ balance: sql`${accounts.balance} - ${amount}` })
    .where(eq(accounts.id, id));
  await tx.insert(auditLog).values({ accountId: id, delta: -amount });   // tx, never db
});

// GOOD 2: one conditional statement, no lock needed, portable to SQLite — and check the row count
const debited = await db.update(accounts)
  .set({ balance: sql`${accounts.balance} - ${amount}` })
  .where(and(eq(accounts.id, id), eq(accounts.orgId, session.orgId), gte(accounts.balance, amount)))
  .returning({ id: accounts.id });
if (debited.length === 0) throw new InsufficientFunds();

// GOOD 3: "only once" is a unique constraint, not an if
const claimed = await db.insert(redemptions).values({ couponId, userId })
  .onConflictDoNothing().returning();     // unique index on (couponId, userId)
if (claimed.length === 0) throw new AlreadyRedeemed();
```

- `.for('update')` takes `'update' | 'no key update' | 'share' | 'key share'` and a config
  `{ of, noWait } | { of, skipLocked }`; it is typed in the query builder but not described on the
  docs site, and exists on the Postgres and MySQL builders only. SQLite
  has no row locks: use the conditional `UPDATE` above, or `db.transaction(fn, { behavior: 'immediate' })`.
- Lock multiple rows in a consistent order (sort by id) so two transfers cannot deadlock.
- For multi-statement logic that cannot be one statement, `db.transaction(fn, { isolationLevel:
  'serializable' })` is the alternative; the caller must retry on SQLSTATE `40001`.
- Back the invariant in the database too: ``check('balance_nonneg', sql`${t.balance} >= 0`)`` turns
  a missed code path into a failed write instead of a negative balance.
- Inside the callback every query goes through the `tx` argument. The same applies to helper
  functions: pass `tx` down, do not let them import the module-level `db`.

Detection:

```bash
# read-modify-write computed in JS (balance: row.balance - n), then check-then-act on the same fields
grep -rnE "\.set\(\{[^}]*:\s*\w+\.(balance|quantity|stock|credits|count|remaining)\s*[-+]" --include="*.ts"
grep -rnE "if \(.*\.(balance|quantity|stock|credits|remaining)\s*[<>]=?" --include="*.ts"
# files that open transactions but never lock, never use a conditional where, never compute in SQL
grep -rlE "\.transaction\(" --include="*.ts" . | xargs grep -LE "\.for\(['\"](update|no key update)|gte\(|sql\`[^\`]*\s[-+]\s"
# the outer db used inside db.transaction(async (tx) => { ... })
find . -name "*.ts" -not -path "*/node_modules/*" -print0 | xargs -0 perl -0ne \
  'while (/\b(\w+)\.transaction\(\s*async\s*\(\s*(\w+)\s*\)\s*=>\s*(\{(?:[^{}]++|(?3))*\})/g) {
     ($o,$t,$b)=($1,$2,$3);
     while ($b =~ /\b\Q$o\E\.(select|insert|update|delete|execute|query)\b/g) {
       print "$ARGV: $o.$1 inside $o.transaction, use $t\n" } }'
```

## SQLite, Turso and D1

### Tenant isolation is application code

SQLite has no user or privilege system and no `GRANT`, so there is no row-level security to
fall back on (this is a consequence of its design as an embedded library, not a documented
feature toggle). The unit of access is the whole file (or, for Turso, the whole auth token), and it grants
everything in it. That is the same lesson as the Prisma section — see `secaudit:prisma-security` —
except there is no RLS to fall back on at all: every query carries its own tenant predicate, or
each tenant gets its own database.

```typescript
// BAD: the row is fetched by id alone, so any id belongs to any caller
const [invoice] = await db.select().from(invoices).where(eq(invoices.id, id));

// GOOD: tenant from the server-verified session, in the same where clause
const [invoice] = await db.select().from(invoices)
  .where(and(eq(invoices.id, id), eq(invoices.orgId, session.orgId)));
```

The same predicate belongs on every `update` and `delete`, on every dialect, not just SQLite — the
write forms are in "Drizzle Write Paths" above.

### The database file, and its siblings

A WAL-mode database is not one file. Alongside `app.db` SQLite maintains `app.db-wal` (committed
data not yet folded into the main file) and `app.db-shm`. Any rule that names only `*.db` leaks the
rest.

- **Gitignore `*.db`, `*.sqlite`, `*.sqlite3` and the `-wal` / `-shm` / `-journal` siblings.**
  Drizzle's SQLite quickstart puts `local.db` in the project root — exactly where `git add .` finds
  it. A committed dev database is a committed copy of whatever was in it.

```gitignore
# BAD: only the main file is ignored; the WAL sidecar with the newest rows still gets committed
*.db

# GOOD: the database and every sidecar SQLite may create next to it
*.db
*.db-wal
*.db-shm
*.db-journal
*.sqlite
*.sqlite3
*.sqlite-wal
*.sqlite-shm
```

Keep the file outside the web root and the repo entirely — for example `DATABASE_URL=file:/var/lib/app/app.db` — rather than relying on the ignore list alone.
- **Never inside `public/` or `static/`.** Those directories are served verbatim, so `GET /app.db`
  hands over the database; the `-wal` next to it hands over the newest writes.
- **Permissions:** the app user needs write access to the database file *and* to the directory
  holding it, because SQLite creates the `-wal` and `-shm` there. Nothing else should be able to
  read any of the three — with no in-database access control, file mode *is* the boundary.
- **A backup is not `cp app.db`.** sqlite.org is explicit that if a failure occurs while the file
  is being copied "the backup database may be corrupted following system recovery". Use
  `VACUUM INTO`, the `.backup` command, or the online backup API — and protect the output exactly
  like the live file, because it is the same data.
- **Read-only consumers:** open with the `mode=ro` URI parameter. `immutable=1` goes further but
  asserts the file cannot change at all (it skips locking and change detection), so reserve it for
  genuinely read-only media.

### Driver-level sinks

```typescript
// BAD: exec() takes a whole string and runs multiple statements — stacked-injection sink
db.exec(`UPDATE users SET name = '${name}' WHERE id = ${id}`);

// GOOD: prepare once, bind the values
db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, id);
```

better-sqlite3's own docs call `.exec()` "less safe than using prepared statements" and scope it to
SQL loaded from a trusted file. `db.pragma(userInput)` is the same sink in a different costume:
PRAGMAs run through the normal SQL path, so a reachable one lets an attacker change how the
database behaves (turning off `foreign_keys`, for instance).

- **Turso / libSQL:** `client.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] })` —
  never a template string. `TURSO_AUTH_TOKEN` is a bearer credential for an entire database with no
  per-row scoping, so treat it as a database password: never behind a `NEXT_PUBLIC_` / `VITE_` /
  `EXPO_PUBLIC_` prefix (see `secaudit:secrets`). Mint narrow tokens where you can —
  `turso db tokens create <db> --read-only --expiration 7d` — and on a suspected leak rotate the
  database's credentials (`db:rotate-creds`, which invalidates every outstanding SQL token), rather
  than only the token you know about.
- **Cloudflare D1:** `env.DB.prepare('SELECT * FROM Customers WHERE CompanyName = ?').bind(name)`.
  Interpolating into the `prepare()` string defeats the binding entirely. For binding scope and
  `wrangler` secrets, see `secaudit:cloudflare-workers-security`.

Detection:

```bash
grep -rn "sql\.raw(\|sql\.identifier(\|\.exec(" --include="*.ts" --include="*.js"
grep -rn "TURSO_AUTH_TOKEN" .          # any client-exposed prefix on it is a leak
git ls-files | grep -E "\.(db|sqlite|sqlite3)(-wal|-shm|-journal)?$"
find . \( -path "*/public/*" -o -path "*/static/*" \) \( -name "*.db*" -o -name "*.sqlite*" \)
```

## Input Validation

Validate all external input at system boundaries using a runtime schema validator (Zod, Yup, Joi,
etc.):

- API route handlers
- Server Actions
- Webhook handlers
- Form submissions
- URL parameters and query strings

Don't rely on TypeScript types alone — they're compile-time only and don't exist at runtime. An
attacker sending a malformed request bypasses all TypeScript checks.

```typescript
// TypeScript type provides NO runtime protection
type CreateUserInput = { name: string; email: string };

// Zod schema provides ACTUAL runtime validation
const CreateUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
});
```

## Mass Assignment

Don't spread request bodies directly into database operations. An attacker can add unexpected
fields:

```typescript
// BAD: attacker can add { isAdmin: true, credits: 99999 }
await db.users.update({ where: { id }, data: req.body });

// GOOD: pick only allowed fields
const { name, email } = validated.data;
await db.users.update({ where: { id }, data: { name, email } });
```

### Drizzle: `createInsertSchema` and spread bodies

Threat: a privileged column (`role`, `isAdmin`, `orgId`, `credits`, `passwordHash`) becomes
client-writable. Drizzle makes it easy in two ways:

1. **`createInsertSchema(table)` / `createUpdateSchema(table)` (drizzle-zod, or `drizzle-orm/zod` in
   v1) is a schema of every writable column.** Parsing a request body with it validates the types
   and then admits `role`, `isAdmin`, `orgId` and `credits`. Verified on drizzle-zod 0.8: the
   unpicked insert schema returned `orgId`, `role`, `isAdmin` and `credits` from an attacker body;
   the unpicked update schema returned `{ isAdmin: true, credits: 5 }`. Community guidance such as
   honra-io/drizzle-best-practices (`types-validators.md`) teaches `createInsertSchema(users)` and
   then `db.insert(users).values(parsed)` as the model pattern. Treat that as the anti-pattern for
   anything fed by a request: the generated schema is the table, not the API contract.
2. **A body or parsed object spread straight into `.values()` / `.set()`.**

```typescript
// BAD: the table's full insert shape accepts { role: 'admin', isAdmin: true, credits: 99999, orgId }
const InsertUser = createInsertSchema(users);
await db.insert(users).values(InsertUser.parse(await c.req.json()));
await db.update(users).set(createUpdateSchema(users).parse(req.body)).where(eq(users.id, id));

// BAD: spread of the raw body
await db.insert(users).values({ ...req.body });
await db.update(users).set(req.body).where(eq(users.id, id));

// GOOD: allow-list the columns the client may write; .strict() makes an attempt loud (a 400)
// instead of silently dropped. Server-owned columns are set after, from the verified session.
const SignupBody = createInsertSchema(users).pick({ name: true, email: true }).strict();
const ProfilePatch = createUpdateSchema(users).pick({ name: true }).strict();

const body = SignupBody.parse(await c.req.json());
await db.insert(users).values({ ...body, orgId: session.orgId });   // plus any other server-owned columns
await db.update(users).set(ProfilePatch.parse(req.body))
  .where(and(eq(users.id, session.userId), eq(users.orgId, session.orgId)));
```

- Prefer `.pick()` (an allow-list) over `.omit()` (a deny-list): with `.omit({ role: true })` the next
  sensitive column added to the table is writable by default. Both exist on the returned Zod object.
- Without `.strict()` a `z.object` strips unknown keys silently (verified), which is safe but hides
  the attack; with it, extra keys fail the parse.

Detection (each hit is a lead: trace the schema and the value that reaches `.values()` / `.set()`):

```bash
# generated schemas that are never narrowed (a .pick/.omit on the next line is a false positive)
grep -rnE "create(Insert|Update)Schema\(\w+[,)]" --include="*.ts" --include="*.tsx" . | grep -vE "\.(pick|omit)\("
# a body / parsed object handed to values() or set()
grep -rnE "\.(values|set)\(\s*(\{[^}]*\.\.\.\s*)?(req\.body|body|input|data|payload)\s*[,})]" --include="*.ts" .
```

### Python / Pydantic — the risk has a different shape

**Pydantic already ignores undeclared fields by default** (verified: an undeclared `is_admin` is
silently dropped), so Python's mass-assignment risk is *not* a spread operator. It is:

1. a privileged field **declared** on a request model, and
2. `Model(**body)` or a `setattr` loop over an ORM object.

```python
# BAD: is_admin is declared, so {"name":"x","is_admin":true} parses and survives to the DB write
class ProfileUpdate(BaseModel):
    name: str
    is_admin: bool = False

# GOOD: don't declare it, and make an attempt to send it loud rather than silent
class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")   # 422, error type "extra_forbidden"
    name: str
```

`extra="forbid"` turns a silent drop into an auditable 422 — worth it precisely because the
default is quiet.

Detection: `grep -rn "class.*BaseModel" -A15 --include="*.py" | grep -iE "is_admin|role|is_staff|is_superuser|credits|balance|permissions"`
and `grep -rn "(\*\*request\|(\*\*body\|(\*\*data\|setattr(" --include="*.py"`

## Sources

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html -- text(), bindparam(), TextClause.bindparams()
- https://pydantic.dev/docs/validation/latest/concepts/models/ -- extra='forbid' and undeclared-field handling
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html -- parameterized queries
- https://www.prisma.io/docs/orm/v7/prisma-client/using-raw-sql/raw-queries -- $queryRaw vs $queryRawUnsafe
- https://orm.drizzle.team/docs/sql -- the sql template's parameterization vs sql.raw()
- https://github.com/drizzle-team/drizzle-orm/security/advisories/GHSA-gpj5-g38j-94v9 -- identifier escaping (CVE-2026-39356)
- https://osv.dev/vulnerability/GHSA-gpj5-g38j-94v9 -- affected and fixed versions
- https://orm.drizzle.team/docs/dynamic-query-building -- $dynamic() for conditional queries
- https://orm.drizzle.team/docs/perf-queries -- sql.placeholder in prepared statements
- https://orm.drizzle.team/docs/zod -- createInsertSchema / createUpdateSchema generate a schema from the table's columns; Refinements
- https://zod.dev/api -- .pick() / .omit() / .strict() on the Zod object the generator returns
- https://orm.drizzle.team/docs/delete -- db.delete(table) with no where deletes all rows
- https://orm.drizzle.team/docs/update -- update().set().where() and returning()
- https://orm.drizzle.team/docs/transactions -- db.transaction(async (tx) => ...), tx.rollback(), isolationLevel config
- https://github.com/drizzle-team/drizzle-orm/blob/main/drizzle-orm/src/pg-core/query-builders/select.ts -- .for(strength, { of, noWait, skipLocked }) row locking (not documented on the docs site; verified in the 0.45 types)
- https://github.com/drizzle-team/drizzle-orm/blob/main/drizzle-orm/src/sqlite-core/session.ts -- SQLite transaction config `behavior: 'deferred' | 'immediate' | 'exclusive'`
- https://www.postgresql.org/docs/current/transaction-iso.html -- READ COMMITTED default; lost updates and serialization failures (40001)
- https://www.postgresql.org/docs/current/explicit-locking.html -- SELECT FOR UPDATE row-level locks
- https://github.com/honra-io/drizzle-best-practices/blob/main/references/types-validators.md -- teaches createInsertSchema(table) parsed straight into values() (the anti-pattern named above)
- https://github.com/honra-io/drizzle-best-practices/blob/main/references/query-error-handling.md -- shows the read-then-decrement inventory transaction without a lock (the race named above)
- https://sqlite.org/wal.html -- the -wal and -shm sibling files
- https://sqlite.org/backup.html -- why a file copy can be a corrupt backup
- https://sqlite.org/uri.html -- mode=ro and immutable=1
- https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md -- .prepare() binding vs .exec()
- https://docs.turso.tech/sdk/ts/reference -- libSQL execute() with args
- https://docs.turso.tech/cli/db/tokens/create -- --read-only and --expiration token flags
- https://developers.cloudflare.com/d1/worker-api/prepared-statements/ -- D1 prepare().bind()
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html -- allow-list fields
- https://zod.dev/ -- runtime schema validation at boundaries
