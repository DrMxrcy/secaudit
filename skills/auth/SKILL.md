---
name: auth
description: Audits authentication and authorization — JWT verification, why Next.js middleware is not a security boundary, Server Actions as public endpoints, session management, and the auth-vs-authorization distinction. Use whenever writing or reviewing login, sessions, JWTs, protected routes, Server Actions, or access-control checks, or when auditing whether the app can be accessed without proper authorization. For request throttling on these endpoints, see vibe-security:rate-limiting.
license: MIT
---

# Authentication & Authorization

## When to Use

- Writing or reviewing login, registration, sessions, or JWT handling.
- Protecting routes, Server Actions, Route Handlers, or RPC endpoints.
- Auditing whether the app authenticates AND authorizes (verifies ownership, not just login).
- (For throttling auth endpoints, see `vibe-security:rate-limiting`.)

## JWT Handling

- **Use `jwt.verify()`, never `jwt.decode()` alone.** `decode` reads the payload without checking
  the signature — an attacker can forge any payload.
- **Explicitly reject `"alg": "none"`.** Some JWT libraries accept unsigned tokens if the algorithm
  is set to `"none"`. Your verification must reject this.
- **Validate issuer, audience, and expiration** — not just the signature.

```typescript
// BAD: reads token without verifying signature
const payload = jwt.decode(token);

// GOOD: verifies signature, rejects tampered tokens
const payload = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'your-app',
});
```

## Next.js Middleware Is NOT a Security Boundary

**This is the #1 auth mistake in vibe-coded Next.js apps.**

Next.js middleware runs at the edge and is convenient for auth checks, but it is
**architecturally incapable of being a reliable sole auth layer**:

- **CVE-2025-29927 (CVSS 9.1):** Middleware completely bypassed via a spoofed
  `x-middleware-subrequest` header. Affected versions 11.1.4 through 15.2.2 (fixed in 12.3.5 /
  13.5.9 / 14.2.25 / 15.2.3). See `vibe-security:framework-versions`.
- **CVE-2025-55182 (React2Shell, CVSS 10.0):** React Server Components RCE — unrelated to
  middleware, but reinforces that framework-level protections have limits.

Always verify auth again in **every** server-side entry point:
- Server Actions (they compile to public POST endpoints)
- Route Handlers (`app/api/`)
- Data access functions / database queries
- Database-level policies (RLS)

Middleware should direct traffic and do a first pass — like a building's front door. But every
room inside must have its own lock.

## Server Actions Are Public Endpoints

Server Actions compile into public POST endpoints. Anyone can call them with `curl`. AI assistants
frequently generate Server Actions that assume they're only called by the UI:

```typescript
// BAD: no auth check, no input validation
'use server';
export async function deleteItem(id: string) {
  await db.items.delete({ where: { id } });
}

// GOOD: validates input, authenticates, and authorizes
'use server';
export async function deleteItem(input: unknown) {
  const parsed = schema.safeParse(input);
  if (!parsed.success) return { error: 'Invalid input' };

  const session = await auth();
  if (!session?.user) redirect('/login');

  // Authorize: verify ownership, not just login
  await db.items.deleteMany({
    where: { id: parsed.data.id, userId: session.user.id }
  });
}
```

Every Server Action needs three things at the top:
1. **Input validation** (Zod or similar runtime schema — see `vibe-security:data-access`)
2. **Authentication** (verify the user is logged in)
3. **Authorization** (verify the user owns the resource)

## Authentication vs Authorization

"Logged in" is not "allowed." Authentication confirms *who* the user is; authorization confirms
*what they may touch*. The most common vibe-coding bug is checking authentication and then acting
on a client-supplied ID without verifying ownership. Always scope mutations and reads to the
authenticated user's ID (derived from the session/token, never from the request body).
