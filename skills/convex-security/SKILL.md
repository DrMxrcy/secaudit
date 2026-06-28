---
name: convex-security
description: Audits Convex backends, which have NO row-level security — every public query/mutation/action is an internet-facing endpoint, so all access control must live in the function body. Checks public vs internal functions, argument validators, ctx.auth identity (never trust args for identity), cron/scheduler and httpAction auth, and unauthenticated file-storage URLs. Use whenever the project has a convex/ directory or you are writing or reviewing Convex functions or schema.
license: MIT
---

# Convex Security

Convex has one defining property: **there is no row-level security.** Every `query`, `mutation`,
and `action` you write is a public HTTP endpoint callable by anyone with your deployment URL, with
whatever arguments they choose. All access control must be enforced inside the function body. This
is the root cause of nearly every Convex vibe-coding vulnerability.

## When to Use

- The project has a `convex/` directory (functions, schema, crons, http routes).
- Writing or reviewing Convex queries, mutations, actions, or HTTP actions.
- Auditing who can call which functions and whether identity/ownership is enforced.

## 1. Public vs Internal Functions

Every non-`internal` function is a public endpoint, and its name is visible in the client bundle.
Privileged logic (admin ops, billing grants, migrations, anything called from crons/scheduler or
another function) must use `internalQuery` / `internalMutation` / `internalAction`.

```typescript
// BEFORE — anyone can grant themselves a paid plan by calling api.plans.markPlanAsProfessional
export const markPlanAsProfessional = mutation({
  args: { planId: v.id("plans") },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.planId, { planType: "professional" });
  },
});

// AFTER — only callable from inside the verified payment action
export const upgrade = action({
  args: { planId: v.id("plans") },
  handler: async (ctx, args) => {
    const ok = await chargeCard(/* ... */);
    if (!ok) throw new Error("Payment failed");
    await ctx.runMutation(internal.plans.markPlanAsProfessional, { planId: args.planId });
  },
});

export const markPlanAsProfessional = internalMutation({ // internal: not client-callable
  args: { planId: v.id("plans") },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.planId, { planType: "professional" });
  },
});
```

Reference internal functions via `internal.*`, public ones via `api.*`. Audit tip:
`grep -rn "mutation(\|query(\|action(\|httpAction(" convex/` and confirm each is either `internal*`
or has both an auth check and argument validators.

## 2. Argument Validators (`v.*`)

Without validators, callers pass arbitrary shapes. A `v.any()` payload patched straight into
`ctx.db.patch` lets an attacker write fields they should never control (`role: "admin"`,
`planType`, `ownerId`).

```typescript
// BEFORE — attacker controls the entire update object
export const updateMovie = mutation({
  handler: async (ctx, { id, update }) => {
    await ctx.db.patch(id, update); // update could set any field
  },
});

// AFTER — narrow, explicit validators
export const updateMovie = mutation({
  args: {
    id: v.id("movies"),
    update: v.object({ title: v.string(), director: v.string() }),
  },
  handler: async (ctx, { id, update }) => {
    await ctx.db.patch(id, update);
  },
});
```

Use `v.id("table")` for IDs, `v.union(v.literal(...))` for enums, explicit `v.object({...})` for
nested updates — never `v.any()` for client input. Enforce with the
`@convex-dev/require-argument-validators` ESLint rule.

## 3. Authentication — `ctx.auth.getUserIdentity()`

Convex enforces nothing at the data layer. A query that returns a document returns it to anyone
unless the handler checks identity. Gate every public function on identity and handle `null`.

```typescript
export const getMyNotes = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (identity === null) throw new Error("Unauthenticated");
    return ctx.db.query("notes")
      .withIndex("by_author", q => q.eq("authorId", identity.subject))
      .collect();
  },
});
```

## 4. Authorization — Trust `ctx.auth`, Never `args` (the #1 Convex vibe-coding bug)

Arguments are fully attacker-controlled. Deriving identity from an argument lets anyone impersonate
any user.

```typescript
// BEFORE — impersonation: client picks the author
export const addNote = mutation({
  args: { note: v.string(), userId: v.id("users") },
  handler: async (ctx, args) =>
    ctx.db.insert("notes", { note: args.note, authorId: args.userId }),
});

// AFTER — author is the authenticated caller
export const addNote = mutation({
  args: { note: v.string() },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthenticated");
    await ctx.db.insert("notes", { note: args.note, authorId: identity.subject });
  },
});
```

For resource ownership and roles, verify membership with an indexed lookup before mutating — do not
assume "logged in" means "allowed." Only IDs that came from `ctx.auth` (or unguessable Convex IDs)
are trustworthy.

## 5. Authorization Patterns — convex-helpers

- **Custom functions** (`customQuery`/`customMutation`/`customAction` from
  `convex-helpers/server/customFunctions`) inject an authenticated `ctx.user` once, so every
  endpoint built from them is auth-checked by construction. Eliminates "forgot the auth check"
  drift; parameterize to enforce roles at the type level.
- **Row Level Security helpers** (`wrapDatabaseReader`/`wrapDatabaseWriter`) apply per-document
  rules to every `ctx.db` access. Use `{ defaultPolicy: "deny" }`. Treat RLS helpers as the last
  line of defense (catches bugs), not the primary one — keep explicit checks at the endpoint.

## 6. HTTP Actions (`httpAction`)

`.convex.site` endpoints are public and get no automatic auth or argument validation. Manually
authenticate (Bearer JWT via `ctx.auth.getUserIdentity()`, or verify webhook HMAC signatures),
parse/validate the body defensively, and scope CORS to your exact origin (never
`Access-Control-Allow-Origin: *` with credentials).

```typescript
http.route({
  path: "/webhook", method: "POST",
  handler: httpAction(async (ctx, request) => {
    const sig = request.headers.get("stripe-signature");
    const body = await request.text();
    if (!verifyStripeSignature(body, sig, process.env.STRIPE_WEBHOOK_SECRET!))
      return new Response("Invalid signature", { status: 401 });
    // ... only now trust the payload
    return new Response(null, {
      status: 200,
      headers: { "Access-Control-Allow-Origin": process.env.CLIENT_ORIGIN!, Vary: "origin" },
    });
  }),
});
```

Convex ships no built-in rate limiting — track per-IP/user in a table (or use the
`@convex-dev/rate-limiter` component) for abuse-sensitive endpoints.

## 7. Scheduled Functions & Crons

Scheduling a public function does not make it private — that same function is still directly
callable by clients. Schedule only `internal*` functions.

```typescript
// BEFORE
crons.daily("reminder", { hourUTC: 8, minuteUTC: 0 }, api.messages.sendMessage, { /* ... */ });
// AFTER
crons.daily("reminder", { hourUTC: 8, minuteUTC: 0 }, internal.messages.sendInternalMessage, { /* ... */ });
```

## 8. Environment Variables / Secrets

Convex env vars are server-only and never shipped to the client. Store API keys (Stripe, OpenAI,
etc.) in Convex Dashboard → Settings → Environment Variables (or via CLI); read with
`process.env.KEY` inside functions. Never hardcode secrets in `convex/*.ts` or accept them as
client arguments.

## 9. File Storage Access Control

Convex file URLs are **unauthenticated** — anyone with the URL can fetch the bytes. There is no
per-request access check on the storage URL. Treat storage IDs/URLs as secrets.

- Gate `generateUploadUrl` behind an authenticated mutation; validate metadata/size after upload.
- For private files, store the `storageId` in your DB, hand users an app-level ID, and serve bytes
  through an `httpAction` that checks permissions first.

```typescript
export const generateUploadUrl = mutation({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthenticated");
    return ctx.storage.generateUploadUrl();
  },
});
```

## 10. Footgun Checklist

- Everything is public by default — audit every `query`/`mutation`/`action`/`httpAction`.
- `v.any()` in args = trusting arbitrary client input.
- `args.userId` / `args.email` used as identity = impersonation; identity must come from `ctx.auth`.
- Public function referenced from `crons.ts` / scheduler / `ctx.runMutation` = should be `internal*`.
- `Access-Control-Allow-Origin: *` or unverified webhook signatures in any `httpAction`.
- File-storage URLs treated as private — they aren't.
- Unindexed `.filter()` over full tables = DoS via table scan (enforce with
  `@convex-dev/no-filter-in-query`).
- No built-in rate limiting — abuse-sensitive endpoints need a manual limiter.

## Sources

- https://docs.convex.dev/functions/internal-functions -- public vs internal functions
- https://docs.convex.dev/functions/validation -- argument validators
- https://docs.convex.dev/auth/functions-auth -- ctx.auth.getUserIdentity()
- https://docs.convex.dev/understanding/best-practices/ -- don't use a spoofable arg for access control
- https://docs.convex.dev/functions/http-actions -- httpAction is public, manual auth required
- https://docs.convex.dev/file-storage -- file URLs are unauthenticated
- https://stack.convex.dev/row-level-security -- no built-in RLS; wrapDatabaseReader/Writer
