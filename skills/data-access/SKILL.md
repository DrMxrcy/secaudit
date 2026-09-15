---
name: data-access
description: Audits data access and input validation — SQL injection, ORM operator injection (e.g. Prisma filter injection and $queryRawUnsafe), Drizzle raw SQL and identifier injection (sql.raw(), sql.identifier()/.as() aliases, dynamic orderBy), SQLite/Turso/D1 specifics (no row-level security so tenant predicates are application code, database file and -wal/-shm exposure, auth tokens as secrets, prepared statements and bound params), runtime input validation at every boundary with a schema validator (Zod/Yup/Joi), and mass assignment from spread request bodies. Covers JS/TS (Prisma, Drizzle, better-sqlite3, libSQL, D1) and Python (SQLAlchemy text(), Pydantic). Use whenever writing or reviewing database queries, API handlers, Server Actions, webhook handlers, or form/URL input processing, or when auditing how untrusted input reaches the data layer.
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
- https://sqlite.org/wal.html -- the -wal and -shm sibling files
- https://sqlite.org/backup.html -- why a file copy can be a corrupt backup
- https://sqlite.org/uri.html -- mode=ro and immutable=1
- https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md -- .prepare() binding vs .exec()
- https://docs.turso.tech/sdk/ts/reference -- libSQL execute() with args
- https://docs.turso.tech/cli/db/tokens/create -- --read-only and --expiration token flags
- https://developers.cloudflare.com/d1/worker-api/prepared-statements/ -- D1 prepare().bind()
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html -- allow-list fields
- https://zod.dev/ -- runtime schema validation at boundaries
