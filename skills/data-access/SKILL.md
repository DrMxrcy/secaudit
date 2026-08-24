---
name: data-access
description: Audits data access and input validation — SQL injection, ORM operator injection (e.g. Prisma filter injection and $queryRawUnsafe), runtime input validation at every boundary with a schema validator (Zod/Yup/Joi), and mass assignment from spread request bodies. Covers both JS/TS (Prisma) and Python (SQLAlchemy text(), Pydantic). Use whenever writing or reviewing database queries, API handlers, Server Actions, webhook handlers, or form/URL input processing, or when auditing how untrusted input reaches the data layer.
license: MIT
---

# Data Access & Input Validation

## When to Use

- Writing or reviewing database queries (raw SQL or ORM).
- Handling external input in API routes, Server Actions, webhooks, forms, or URL params.
- Auditing how untrusted input reaches the data layer.

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
- https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries -- $queryRaw vs $queryRawUnsafe
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html -- allow-list fields
- https://zod.dev/ -- runtime schema validation at boundaries
