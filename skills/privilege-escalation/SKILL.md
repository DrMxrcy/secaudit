---
name: privilege-escalation
description: Audits privilege escalation and the admin surface — vertical escalation (a normal user reaching admin functions), broken function-level authorization (OWASP API A05/BFLA), roles trusted from the client (JWT claims, request body, localStorage) instead of re-checked server-side, unprotected admin routes/pages/mutations, and mass-assignment of a role field. Use when reviewing anything with roles, admin panels, or an is-admin check, or when auditing whether a non-admin can perform an admin action.
license: MIT
---

# Privilege Escalation & the Admin Surface

Every privilege-escalation bug is the same mistake: the server decides *what* to do from
client-controlled input but never re-checks *who* is allowed to do it. AI-generated code reliably
produces the happy path — a working admin panel, a role field on the user — and omits the
server-side authorization guard on the sensitive action. The role check that exists in the UI is
cosmetic; the attacker never uses your UI.

This skill covers **vertical** escalation (a normal user gaining admin/higher-role powers) and
function-level authorization. **Horizontal** access to another user's object of the *same* role is
IDOR — see `secaudit:web-vulns`. The core authorization principles are in `secaudit:auth`; this
skill is the focused pass on roles and the admin surface.

## When to Use

- The app has roles, tiers, or any `role === "admin"` / `isAdmin` / `is_staff` check.
- There is an admin panel, dashboard, or admin-only API route / Server Action / mutation.
- A role, plan, or permission is read from a JWT claim, request body, cookie, or local storage.
- Auditing whether a non-admin user can reach an admin function by calling the endpoint directly.

Review grep heuristics: `isAdmin`, `role`, `is_staff`, `admin`, `/admin`, `requireAdmin`,
`hasRole`, and role reads from `req.body`/`searchParams`/`localStorage`/JWT payload.

## 1. Vertical escalation — unprotected admin endpoints

**What to look for:** admin API routes, Server Actions, RPCs, or mutations that perform the
privileged operation with **no server-side role check** — relying on the fact that the admin link
is only rendered in the UI for admins, or that middleware "protects" `/admin`. A hidden or
un-linked route is not protected; the attacker calls it directly (`curl`, refresh token, replay).

**Why it's exploitable:** the endpoint is internet-facing. Hiding the button in the frontend, or
gating the *page* in middleware, does nothing for a direct request to the underlying action.
Middleware is not a security boundary (see `secaudit:auth`); the check must live in the handler.

**Fix:** check the role from the trusted session inside every privileged handler, before the work.

```ts
// app/api/admin/users/[id]/route.ts — BEFORE: any authenticated user can delete any user
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await db.user.delete({ where: { id: params.id } });   // no role check
  return Response.json({ ok: true });
}

// AFTER: authorize the role from the session, in the handler itself
import { auth } from "@/lib/auth";
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (session?.user?.role !== "admin") return new Response("Forbidden", { status: 403 });
  await db.user.delete({ where: { id: params.id } });
  return Response.json({ ok: true });
}
```

## 2. Role trusted from the client

**What to look for:** the role/plan/permission is taken from a request body, query param, cookie,
`localStorage`, a hidden form field, or an **unverified** JWT payload — then trusted for an
authorization decision. Also: setting `role` on the client at signup, or a `?admin=true` style flag.

**Why it's exploitable:** anything the client sends, the client controls. `{"role":"admin"}` in a
request body, or editing a decoded-but-unverified JWT, grants admin instantly. A JWT is only
trustworthy after its signature is verified server-side (see `secaudit:cryptography` for alg
confusion); even then, the claim must have been set by the server, not the user.

**Fix:** derive role and identity from the server-side session or a signature-verified token, and
look up the authoritative role from the database — never from request input.

```ts
// BEFORE: role comes from the request body
const { userId, role } = await req.json();
if (role === "admin") await doAdminThing();          // attacker sends role:"admin"

// AFTER: ignore client-sent role; load it from the DB keyed on the session user
const session = await auth();
const me = await db.user.findUnique({ where: { id: session.user.id }, select: { role: true } });
if (me?.role !== "admin") return new Response("Forbidden", { status: 403 });
await doAdminThing();
```

## 3. Broken function-level authorization (BFLA)

**What to look for:** authorization enforced inconsistently across an object's operations — a
`GET` is guarded but the `POST`/`PATCH`/`DELETE`, the bulk endpoint, or a newer sibling route is
not; role checks copy-pasted per handler and missed in one place; a shared admin layout that
guards page render but not the data mutations it calls.

**Why it's exploitable:** attackers enumerate methods and routes. If one privileged operation
skips the check, the whole object is compromised regardless of the others. This is OWASP API
**A05: Broken Function Level Authorization**.

**Fix:** centralize the authorization check (a `requireRole("admin")` guard or middleware applied
at the route-group/router level) so it cannot be forgotten per-handler, and default-deny.

```ts
// lib/authz.ts — one guard, reused everywhere; default-deny
import { auth } from "@/lib/auth";
export async function requireRole(role: "admin" | "editor") {
  const session = await auth();
  if (!session) return { error: new Response("Unauthorized", { status: 401 }) };
  if (session.user.role !== role) return { error: new Response("Forbidden", { status: 403 }) };
  return { session };
}
// every admin handler starts by returning the guard's response on failure:
//   const { session, error } = await requireRole("admin");
//   if (error) return error;
```

## 4. Mass-assignment of the role field

**What to look for:** an update/create that spreads the whole request body into the DB write
(`db.user.update({ data: req.body })`, `Object.assign(user, req.body)`) where the model includes a
`role`/`isAdmin`/`plan` column. A profile-update endpoint becomes a privilege-escalation endpoint.

**Why it's exploitable:** the user adds `"role":"admin"` (or `"isAdmin":true`) to an otherwise
innocent profile update and self-promotes. The endpoint never intended to expose `role`, but the
spread does.

**Fix:** allowlist the writable fields explicitly; never spread untrusted input into a privileged
model. See `secaudit:data-access` for the general mass-assignment pattern.

```ts
// BEFORE: whole body written — role is writable
await db.user.update({ where: { id: session.user.id }, data: await req.json() });

// AFTER: pick only the fields this endpoint may change
const { name, avatarUrl } = await req.json();
await db.user.update({ where: { id: session.user.id }, data: { name, avatarUrl } });
```

## 5. Admin-object IDOR

Admin tools list and act on *other users'* objects by ID, so the "scope every query to the owner"
rule from IDOR does not apply — instead the whole tool must be gated behind the admin role (section
1), and any action that targets a specific record must still validate the record exists and log the
actor. Combine this skill's role gate with the ownership/lookup discipline in `secaudit:web-vulns`.

## Checklist

- Every admin route, Server Action, RPC, and mutation checks the role from the session in the
  handler — not only in middleware or the rendered UI.
- Role/plan/permission is read from the server session or a verified token, never from request
  body, query, cookie, or local storage.
- Authorization is centralized (a shared guard) and applied to **all** methods of an object.
- No endpoint spreads request input into a model that has a `role`/`isAdmin`/`plan` field.
- Admin actions are audit-logged with the acting user (see `secaudit:logging-monitoring`).

See also `secaudit:auth` (sessions, middleware-is-not-a-boundary), `secaudit:web-vulns` (IDOR /
object-level authorization), `secaudit:data-access` (mass assignment), and `secaudit:database`
(RLS as a second enforcement layer).

## Sources

- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ -- OWASP API A05 (BFLA)
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/ -- OWASP A01 Broken Access Control (privilege escalation)
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html -- authorization design, default-deny, centralized checks
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html -- mass assignment / allowlisting writable fields
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation -- WSTG privilege-escalation testing
