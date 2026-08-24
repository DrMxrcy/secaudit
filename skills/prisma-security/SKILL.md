---
name: prisma-security
description: Audits Prisma ORM on PostgreSQL, including pgvector. Prisma has NO row-level security of its own — every query must carry the tenant predicate, and Postgres RLS is silently bypassed when the app connects as the table owner. Covers tenant scoping and its extension/include blind spots, Prisma.raw injection inside "safe" $queryRaw, over-fetching secrets without global omit, DATABASE_URL TLS, destructive migrations, and pgvector RAG retrieval without an access-control WHERE clause. Use whenever the project has a prisma/schema.prisma, uses $queryRaw/$executeRaw, or runs vector similarity search on Postgres.
license: MIT
---

# Prisma Security

Prisma has one defining property: **it enforces no row-level security.**
`prisma.document.findMany()` returns every document in the table. There is no ambient tenant, no
policy engine, no default-deny — the only thing standing between tenant A and tenant B's rows is a
`where` clause that a human (or an AI assistant) remembered to write, on every query, forever.
Teams that reach for Postgres RLS to fix this usually make it worse, because under a typical
Prisma setup RLS is silently inert (§2).

This skill audits Prisma on PostgreSQL, including pgvector RAG stacks. For raw-SQL basics
(`$queryRawUnsafe`, operator injection, mass assignment) see `secaudit:data-access`; for the RAG
and prompt-injection layer above retrieval see `secaudit:ai-integration`; for `DATABASE_URL`
handling see `secaudit:secrets`; for object-level authorization patterns see `secaudit:web-vulns`.

## When to Use

- The project has a `prisma/schema.prisma`, or a `PrismaClient` is constructed anywhere.
- Any use of `$queryRaw`, `$queryRawUnsafe`, `$executeRaw`, `Prisma.raw`, or `Prisma.sql`.
- The app is multi-tenant, or any row is owned by a user, org, workspace, or team.
- Vector similarity search on Postgres (`<=>`, `<->`, `<#>`, pgvector, RAG retrieval).
- Reviewing `prisma/migrations/**/migration.sql` or the deploy command that applies them.

## 1. No Row-Level Security — Every Query Carries the Tenant Predicate

Every `findMany` / `findFirst` / `findUnique` / `aggregate` / `groupBy` / `count` must carry a
tenant or ownership predicate derived **server-side from the session**, never from a request
argument. A missing predicate is not a subtle bug: it returns the whole table.

```typescript
// BAD — the id came from the client; any tenant's document is returned
const doc = await prisma.document.findFirst({ where: { id: params.id } });

// GOOD — tenant comes from the verified session and is paired with the id
const { tenantId } = await requireSession(req);
const doc = await prisma.document.findFirst({ where: { id: params.id, tenantId } });
```

**The write trap worth calling out.** `update` / `delete` / `findUnique` accept only *unique* fields
in `where`, so a non-unique `tenantId` filter is a type error there. This is precisely why
AI-written code drops the tenant check on writes — the assistant hits the type error and removes
the predicate rather than changing the shape of the call. Use `updateMany` / `deleteMany`, which
take a full filter and report how many rows matched:

```typescript
// BAD — where on update can't take tenantId, so the guard silently disappears
await prisma.document.update({ where: { id }, data: { title } });

// GOOD — both predicates; count === 0 means "not yours" (return 404, not 403)
const { count } = await prisma.document.updateMany({ where: { id, tenantId }, data: { title } });
if (count === 0) throw new NotFoundError();
```

Or make the pair unique in the schema so `update` can enforce it at the type level:

```prisma
model Document {
  id       String @id @default(cuid())
  tenantId String
  @@unique([id, tenantId]) // enables update({ where: { id_tenantId: { id, tenantId } } })
}
```

Detection:

```bash
grep -rnE "prisma\.[a-zA-Z]+\.(update|delete)\(\s*\{\s*where:\s*\{\s*id\b" src/
grep -rnE "\.(findMany|findFirst|aggregate|groupBy|count)\(" src/ | grep -vE "tenantId|orgId|userId|workspaceId"
```

## 2. Postgres RLS Is Silently Inert When the App Connects as the Table Owner

The standard fix for §1 is to push isolation into the database. It usually does nothing. From the
PostgreSQL documentation, verbatim:

> "Superusers and roles with the BYPASSRLS attribute always bypass the row security system when
> accessing a table. Table owners normally bypass row security as well, though a table owner can
> choose to be subject to row security with ALTER TABLE ... FORCE ROW LEVEL SECURITY."

In a Prisma project, the `DATABASE_URL` role is almost always the role that ran `prisma migrate` —
i.e. the **owner of every table it created**. So policies exist, `\d+` shows them, the isolation
test passes when run as a third role, and the application bypasses all of it. Zero isolation, full
confidence.

```sql
-- BAD — policy exists, app role owns the table, every policy is bypassed
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON documents
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- GOOD — force RLS even for the owner, and run the app as a separate non-owner role
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
CREATE ROLE app_user LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
```

Point `DATABASE_URL` at `app_user` and give migrations their own owner role via Prisma's
`directUrl` / `DIRECT_URL`. Verify what the app actually connects as — run this **through the
app's own connection string**, not from psql as yourself:

```sql
SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;
-- both must be false; if either is true, every policy on every table is decoration
```

**The existence oracle.** Even correct, forced RLS leaks. Same source, verbatim:

> "Referential integrity checks, such as unique or primary key constraints and foreign key
> references, always bypass row security to ensure that data integrity is maintained."

Concretely: tenant A inserts a row whose `slug`, `email`, or external ID collides with a row that
RLS hides from them, and Postgres raises a unique-violation — confirming a row they cannot see
exists. An FK reference to another tenant's hidden ID succeeds instead of failing. Both are
working existence oracles over another tenant's data (enumerate customer emails, invite codes,
subdomains). Flag it: scope uniqueness per tenant (`@@unique([tenantId, slug])`) and map
constraint errors to a generic message rather than echoing the constraint name.

Detection: `grep -rn "ROW LEVEL SECURITY" prisma/migrations/ | grep -v FORCE`

## 3. `set_config` Outside a Transaction Leaks Tenant Context Across Pooled Connections

RLS policies read the tenant from a GUC that the app sets per request. The third argument to
`set_config` is `is_local`. From the PostgreSQL documentation, verbatim:

> "If is_local is true, the new value will only apply during the current transaction. If you want
> the new value to apply for the rest of the current session, use false instead."

With `FALSE`, the value sticks to the **pooled connection**. The request ends, the connection
returns to the pool, and the next request — a different tenant, or an unauthenticated background
job — inherits it. This is a cross-tenant read that appears only under concurrency, so it survives
every test suite.

```typescript
// BAD — session-scoped GUC on a pooled connection; the next request inherits this tenant
await prisma.$executeRaw`SELECT set_config('app.tenant_id', ${tenantId}, FALSE)`;
return prisma.document.findMany();

// GOOD — transaction-local, and the queries run on that same transaction's connection
return prisma.$transaction(async (tx) => {
  await tx.$executeRaw`SELECT set_config('app.tenant_id', ${tenantId}, TRUE)`;
  return tx.document.findMany();
});
```

Prisma's documented extension form applies the same pattern to every model operation:

```typescript
const forTenant = (tenantId: string) =>
  prisma.$extends({
    query: {
      $allModels: {
        async $allOperations({ args, query }) {
          const [, result] = await prisma.$transaction([
            prisma.$executeRaw`SELECT set_config('app.tenant_id', ${tenantId}, TRUE)`,
            query(args),
          ]);
          return result;
        },
      },
    },
  });
```

Note `current_setting('app.tenant_id', true)` returns NULL when the GUC was never set — the docs:
"If there is no such setting, current_setting throws an error unless missing_ok is supplied and is
true (in which case NULL is returned)." A policy comparing against NULL matches nothing, so an
unset context **fails closed**, which is correct — but it means a missing GUC looks like an empty
result set, not an error. Do not let anyone "fix" the empty results by widening the policy.

Detection: `grep -rn "set_config" src/ | grep -viE "true\s*\)|, *TRUE"`

## 4. A Tenant-Scoping Extension Never Reaches `include` or Raw Queries

This is the highest-value false-sense-of-safety bug on this stack: the team writes one Client
extension, believes tenancy is now structural, and stops writing predicates by hand. A query
extension **cannot mutate `include` or `select`** — Prisma documents this, because changing them
would change the operation's output type. So the extension fires for a top-level model call and is
skipped entirely for the same model reached through a parent's `include`.

```typescript
const db = prisma.$extends({
  query: {
    document: {
      async findMany({ args, query }) {
        args.where = { ...args.where, tenantId: getTenantId() };
        return query(args);
      },
    },
  },
});

await db.document.findMany();                                // scoped
await db.folder.findMany({ include: { documents: true } });  // NOT scoped — extension never runs
await db.$queryRaw`SELECT * FROM documents`;                 // NOT scoped — raw bypasses everything
```

Fixes: scope nested reads explicitly (`include: { documents: { where: { tenantId } } }`), and
treat forced database-level RLS (§2) — not the extension — as the real boundary. The extension
is defense in depth; the `include` path and every `$queryRaw` (§5, §8) are outside it by
construction.

Also flag `prisma.$use(...)`: Client **middleware is removed in Prisma 7**. A codebase whose only
tenant guard is a `$use` middleware breaks open on upgrade — the guard silently stops existing
while the queries keep working. Migrate those guards to `$extends` before upgrading, and re-run
the §1 greps afterwards.

Detection:

```bash
grep -rn "\$use(" src/                          # removed in Prisma 7
grep -rn "include:" src/ | grep -v "where:"     # nested reads with no predicate of their own
```

## 5. `Prisma.raw()` Re-opens Injection Inside the "Safe" `$queryRaw`

`secaudit:data-access` covers `$queryRawUnsafe`. The subtler finding is injection *inside* the
tagged template that everyone treats as safe. Assistants reach for `Prisma.raw()` because
identifiers, `ORDER BY`, and table names cannot be bound as parameters — and `Prisma.raw()`
interpolates verbatim, with no escaping whatsoever. Assigning to `query.values` after building a
`Prisma.sql` fragment defeats parameterization the same way.

```typescript
// BAD — Prisma.raw() inside $queryRaw is plain string interpolation
const rows = await prisma.$queryRaw`
  SELECT id, title FROM documents ORDER BY ${Prisma.raw(req.query.sort as string)}`;

// BAD — overwriting .values after the fact detaches params from the placeholders
const q = Prisma.sql`SELECT * FROM documents WHERE id = ${id}`;
q.values = [req.query.id];
await prisma.$queryRaw(q);
```

```typescript
// GOOD — identifiers/ORDER BY from a server-side allow-list, values as positional params
const SORT = { created: '"createdAt" DESC', title: '"title" ASC' } as const;
const orderBy = SORT[req.query.sort as keyof typeof SORT] ?? SORT.created;

const rows = await prisma.$queryRawUnsafe(
  `SELECT id, title FROM documents WHERE "tenantId" = $1 ORDER BY ${orderBy} LIMIT $2`,
  tenantId,
  limit,
);

// GOOD — IN clauses: Prisma.join emits one placeholder per value, never a joined string
const docs = await prisma.$queryRaw`
  SELECT id FROM documents WHERE "tenantId" = ${tenantId} AND id IN (${Prisma.join(ids)})`;
```

The allow-list must be a literal map keyed by client input, not a validated-string-passed-through:
`z.string().regex(/^\w+$/)` still lets a caller order by a column that leaks data
(`passwordHash`).

Detection: `grep -rnE "Prisma\.raw\(|\.values\s*=" src/`

## 6. Over-Fetching: No `select` / `omit` Ships Every Scalar Column

A Prisma query with no `select` or `omit` returns **every scalar field on the model**.
`res.json(user)` then ships `passwordHash`, `totpSecret`, `resetToken`, `stripeCustomerId`, and
internal flags to the browser — where they land in the response, the client cache, the SSR
payload, and any logging middleware. This is one line of code away from full account takeover via
a leaked reset token.

```typescript
// BAD — returns the whole row, including every credential column on the model
const user = await prisma.user.findUnique({ where: { id } });
res.json(user);

// GOOD (fail closed) — global omit at construction; these fields never leave the DB layer
const prisma = new PrismaClient({
  omit: { user: { passwordHash: true, totpSecret: true, resetToken: true } },
});

// GOOD (belt) — explicit select at the response boundary
const user = await prisma.user.findUnique({
  where: { id },
  select: { id: true, email: true, name: true },
});
```

Global `omit` has been GA since Prisma 5.16, so it is available in any project worth auditing.
Prefer it: it is the only form that protects the query someone adds next month. Fields still
needed server-side can be re-enabled per query with `omit: { passwordHash: false }`.

Detection: `grep -rnE "\.(findUnique|findFirst|findMany)\(" src/ | grep -vE "select:|omit:"`

## 7. `DATABASE_URL` TLS — `sslmode=require` Verifies Nothing

Prisma's PostgreSQL connector defaults `sslaccept` to `accept_invalid_certs`. The near-universal
`?sslmode=require` therefore gives an **encrypted channel to whoever answers on that address** —
no certificate validation, no hostname check. Anyone positioned on the path (a hostile network, a
hijacked DNS record, a compromised sidecar) terminates TLS with a self-signed cert and reads every
query, every result row, and the database credentials themselves. Encryption without
authentication is not transport security.

```bash
# BAD — encrypted, unauthenticated: any host that answers wins the connection
DATABASE_URL="postgresql://app:pw@db.example.com:5432/app?sslmode=require"

# GOOD — verify the server certificate against a pinned CA
DATABASE_URL="postgresql://app:pw@db.example.com:5432/app?sslmode=require&sslaccept=strict&sslrootcert=/etc/ssl/certs/db-ca.pem"
```

The node-postgres equivalent is `rejectUnauthorized: false`, which reads as a TLS *fix* in
AI-written code and is the same hole:

```typescript
// BAD
new Pool({ connectionString, ssl: { rejectUnauthorized: false } });

// GOOD — discrete fields, real CA
new Pool({
  host, port, user, password, database,
  ssl: { ca: fs.readFileSync("/etc/ssl/certs/db-ca.pem") },
});
```

Note the interaction: node-postgres **overwrites the `ssl` object** when the connection string
carries an `sslmode` parameter — so `new Pool({ connectionString, ssl: { ca } })` can silently
discard the CA you just configured. Pass discrete connection fields when you are pinning a CA, or
put the TLS settings in the connection string and nowhere else. See `secaudit:secrets` for how the
URL itself should be stored.

Detection:

```bash
grep -rn "sslmode=\|sslaccept=\|rejectUnauthorized" . --include=".env*" --include="*.ts"
```

## 8. pgvector — Retrieval Without an Access-Control Predicate

The highest-impact bug on a Prisma RAG stack. Prisma has no typed vector API, so similarity search
is **always** `$queryRaw` — which means retrieval runs outside every extension (§4), every
middleware, and every type check that guards the rest of the app. The result: tenant A asks a
question, the retriever returns tenant B's chunks by cosine distance, and the LLM helpfully
summarizes them into the answer. Nothing in the request looks like an attack, and nothing in the
logs looks like a breach.

```typescript
// BAD — ranked over every chunk in the table, from every tenant
const chunks = await prisma.$queryRaw`
  SELECT id, content FROM chunks
  ORDER BY embedding <=> ${vec}::vector
  LIMIT 8`;

// GOOD — access control in the WHERE clause, before ranking
const chunks = await prisma.$queryRaw`
  SELECT id, content FROM chunks
  WHERE "tenantId" = ${tenantId}::uuid
    AND "aclRoles" && ${roles}::text[]
  ORDER BY embedding <=> ${vec}::vector
  LIMIT ${topK}`;
```

**The HNSW trap that makes teams delete the fix.** With an HNSW index, a `WHERE` filter is applied
*around* the index scan: the index returns its candidate set (`hnsw.ef_search`, default 40), and the
filter then removes rows from it. A tightly filtered query therefore returns **fewer than `LIMIT`
rows** — sometimes zero — even though matching rows exist. Developers experience this as "the
tenant filter broke retrieval" and fix it by removing the filter. Fix it correctly instead:

```sql
-- Option A: partial index per tenant (best recall, one index per tenant)
CREATE INDEX ON chunks USING hnsw (embedding vector_cosine_ops) WHERE tenant_id = '...';

-- Option B: keep scanning until LIMIT is satisfied
SET hnsw.iterative_scan = strict_order;
```

Detection: `grep -rnE "<=>|<->|<#>" src/ | grep -viE "tenant|org|workspace|user_id|acl"`

## 9. Client-Controlled `topK` and Post-Retrieval Filtering

Filtering **after** retrieval is not access control. By the time the rows are in a JS array they
have already crossed the boundary: into query logs, APM traces, the tracing span attributes of
your LLM SDK, and often the prompt itself. A `.filter()` on the results only hides them from the
final response. And an interpolated client-supplied `topK` is simultaneously SQL injection and
denial-of-wallet — `topK: 100000` bills you for the embedding context and can OOM the process.

```typescript
// BAD — interpolated limit, tenancy enforced after the rows already left the database
const rows = await prisma.$queryRawUnsafe(
  `SELECT id, content, "tenantId" FROM chunks ORDER BY embedding <=> $1::vector LIMIT ${body.topK}`,
  vec,
);
return rows.filter((r) => r.tenantId === tenantId);

// GOOD — clamp server-side, bind as a parameter, filter in SQL
const topK = Math.min(Math.max(Number(body.topK) || 8, 1), 50);
return prisma.$queryRaw`
  SELECT id, content FROM chunks
  WHERE "tenantId" = ${tenantId}::uuid
  ORDER BY embedding <=> ${vec}::vector
  LIMIT ${topK}`;
```

Pair this with the spend and abuse limits in `secaudit:rate-limiting`, and the
untrusted-retrieved- content handling in `secaudit:ai-integration` — retrieved chunks are
attacker-authored text.

Detection: `grep -rnE "topK|top_k|LIMIT \$\{" src/`

## 10. Migrations Are an Ungoverned SQL Channel

`prisma/migrations/**/migration.sql` is checked-in SQL that runs with owner privileges against
production and that essentially nobody reads in review — reviewers skim the schema diff and
approve. A single migration containing `DISABLE ROW LEVEL SECURITY`, a `DROP POLICY`, a broad
`GRANT`, a role altered to `BYPASSRLS`, or a seeded admin user silently undoes everything in
§1–§3. Audit the migration directory as security-relevant code, not as generated output:

```bash
grep -rniE "disable row level security|drop policy|bypassrls|grant .* to |create role|superuser" prisma/migrations/
grep -rniE "insert into \"?(users|accounts|memberships)" prisma/migrations/
```

Production applies migrations with `prisma migrate deploy` and nothing else. `prisma db push` is
destructive (it reshapes the schema to match, dropping columns and their data), and `prisma
migrate dev` can prompt for a database reset — both belong to local development only. Check the
deploy script, Dockerfile entrypoint, and CI workflow:

```bash
grep -rnE "prisma (db push|migrate dev)" package.json Dockerfile* .github/ scripts/
```

## 11. Footgun Checklist

- A `where` without a tenant/owner predicate = the whole table. There is no default-deny.
- `update`/`delete` can't take a non-unique tenant filter — that's why the guard vanishes. Use
  `updateMany`/`deleteMany` and check `count`, or add `@@unique([id, tenantId])`.
- RLS policies + app connecting as the table owner = policies do nothing. `FORCE ROW LEVEL SECURITY`
  plus a non-owner, non-`BYPASSRLS` role, verified with `SELECT rolsuper, rolbypassrls`.
- Unique/FK violations bypass RLS and confirm hidden rows exist — an existence oracle.
- `set_config(..., FALSE)` leaks tenant context to the next request on a pooled connection.
- A query extension does not apply to nested `include`, and never to `$queryRaw`.
- `$use` middleware is removed in Prisma 7 — a `$use`-only tenant guard breaks open on upgrade.
- `Prisma.raw()` and assignment to `query.values` are injection, inside the "safe" API.
- No `select`/`omit` = `passwordHash` and reset tokens in the JSON response.
- `sslmode=require` alone does not verify the server certificate.
- Vector search is always raw SQL, therefore outside every guard — put the ACL in the `WHERE`.
- Post-retrieval `.filter()` is not access control; the rows already reached logs and prompts.
- `migration.sql` is unreviewed production SQL; `db push` / `migrate dev` never touch production.

## Sources

- https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries -- $queryRaw, Prisma.raw, Prisma.join
- https://www.prisma.io/docs/orm/prisma-client/client-extensions/query -- query extensions cannot mutate include/select
- https://www.prisma.io/docs/guides/upgrade-prisma-orm/v7 -- $use middleware removed in Prisma 7
- https://www.prisma.io/docs/orm/prisma-client/queries/excluding-fields -- global omit at client construction
- https://www.prisma.io/docs/orm/core-concepts/supported-databases/postgresql -- sslaccept defaults to accept_invalid_certs; directUrl
- https://www.prisma.io/docs/orm/more/best-practices -- migrate deploy in production
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html -- owners/BYPASSRLS bypass RLS; constraints bypass RLS
- https://www.postgresql.org/docs/current/functions-admin.html -- set_config is_local; current_setting missing_ok
- https://github.com/pgvector/pgvector -- HNSW filtering, hnsw.ef_search, iterative scan
- https://github.com/pgvector/pgvector-node -- vector types from Node clients
- https://node-postgres.com/features/ssl -- rejectUnauthorized; sslmode in the connection string overwrites ssl
