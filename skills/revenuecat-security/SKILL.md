---
name: revenuecat-security
description: Audits RevenueCat in-app purchase and subscription flows — entitlements checked only on the device, servers that never independently verify with RevenueCat, webhook authenticity (optional HMAC signing and the shared-secret Authorization header, fail-closed comparison), event replay and idempotency, sandbox/Test Store purchases accepted in production, entitlement flags written to client-writable tables (Convex, Supabase, Firebase), App User ID trust and the anonymous-alias flow, public SDK key vs secret sk_ key, and refund/revocation handling. Use whenever the project depends on purchases-ios, purchases-android, react-native-purchases, purchases-flutter, or handles a RevenueCat webhook. For Stripe web checkout see secaudit:payments.
license: MIT
---

# RevenueCat Security

`secaudit:payments` assumes a Stripe-shaped world: your server creates the charge, and a webhook it
signature-verifies tells it what happened. Mobile in-app purchase inverts that. The purchase happens
between the user's device and Apple/Google, RevenueCat brokers the receipt, and your backend is an
*observer* — often an optional one. The default vibe-coded RevenueCat app has no server in the loop
at all: the SDK says `entitlements.active["pro"]` is present, and the app unlocks.

That is a client assertion, and the client is the attacker's machine. Everything below follows from
one rule: **entitlement is a server-derived fact, not a value the app reports.** This is OWASP
`A01:2025` Broken Access Control wearing a billing costume.

## When to Use

- `package.json` / `Podfile` / `build.gradle` depends on `purchases-ios`, `purchases-android`,
  `react-native-purchases`, `purchases-flutter`, `purchases-capacitor`, or `@revenuecat/purchases-js`.
- Any code calls `Purchases.configure`, `Purchases.logIn`, `getCustomerInfo`, or reads
  `customerInfo.entitlements`.
- A route, `httpAction`, or Edge Function receives RevenueCat webhook events.
- Auditing whether a refunded, cancelled, sandbox, or never-paying user can reach paid features.

Review grep heuristics: `entitlements.active`, `getCustomerInfo`, `Purchases.logIn`,
`Purchases.configure`, `api.revenuecat.com`, `x-revenuecat-webhook-signature`, `app_user_id`,
`environment`, `is_sandbox`, `sk_`, `isPro`.

For Stripe web checkout use `secaudit:payments`; for the mobile bundle and key storage,
`secaudit:expo-security` and `secaudit:react-native-security`.

## 1. Entitlement Checked Only on the Client

**What to look for:** `customerInfo.entitlements.active["pro"]` (or `.isActive`) as the *only* gate
in front of something valuable — and especially in front of anything the server does.

**Why it's exploitable:** the SDK caches `CustomerInfo` on the device and re-serves it from cache.
A jailbroken/rooted device, a repackaged build, a patched binary, or an on-device MiTM proxy can
make that object say anything. Gating UI on it is fine; gating a *server capability* on it is not.
RevenueCat's own Trusted Entitlements feature exists because the transport can be attacked — but
read what it actually promises: it is **informational only**, it never blocks on its own, your code
must inspect `verificationResult` and decide, and that decision still runs on the attacker's device.
It raises the cost of tampering. It does not make the client authoritative.

```typescript
// BAD — the device decides, and the server takes its word for it
const info = await Purchases.getCustomerInfo();
const isPro = typeof info.entitlements.active["pro"] !== "undefined";
await fetch("/api/generate", {
  method: "POST",
  body: JSON.stringify({ prompt, isPro }), // server trusts this flag
});

// GOOD — the SDK drives UI only; the server re-derives entitlement from its own state
const info = await Purchases.getCustomerInfo();
setShowPaywall(!info.entitlements.active["pro"]); // presentation, nothing more
await fetch("/api/generate", {
  method: "POST",
  headers: { Authorization: `Bearer ${sessionToken}` }, // identity from the session
  body: JSON.stringify({ prompt }),                     // no entitlement claim in the body
});
```

Detect: `grep -rn "entitlements.active\|entitlements\[\|\.isActive" --include=*.ts --include=*.tsx \
--include=*.swift --include=*.kt .` then check every hit that is not purely rendering a paywall.
Also `grep -rniE "\"?(isPro|isPremium|isSubscribed|plan|tier)\"?\s*:" --include=*.ts .` for that
value being *sent* to a backend.

## 2. The Server Never Independently Verifies With RevenueCat

**What to look for:** no `api.revenuecat.com` call anywhere on the server, and no webhook handler —
the backend's only knowledge of who paid came from a client request.

**Why it's exploitable:** "the SDK told us" is not a source of truth for anything that costs you
money or grants server-side capability. Any paid server action (LLM calls, exports, higher rate
limits, storage) must resolve entitlement from a fact the client cannot forge: your own database,
populated by an authenticated webhook (§3–4), or a direct read from the RevenueCat REST API with a
secret key.

```typescript
// GOOD — server-side derivation; the sk_ key never leaves the backend
// RC_V1 is the REST v1 base URL: api.revenuecat.com/v1
async function activeEntitlements(appUserId: string): Promise<Set<string>> {
  const res = await fetch(
    `${RC_V1}/subscribers/${encodeURIComponent(appUserId)}`,
    { headers: { Authorization: `Bearer ${process.env.REVENUECAT_SECRET_KEY!}` } },
  );
  if (!res.ok) throw new Error(`RevenueCat ${res.status}`); // fail closed, never default to "pro"
  const { subscriber } = await res.json();
  const now = Date.now();
  return new Set(
    Object.entries(subscriber.entitlements as Record<string, { expires_date: string | null }>)
      // a null expiry is a lifetime/non-consumable grant; anything else must still be in the future
      .filter(([, e]) => e.expires_date === null || Date.parse(e.expires_date) > now)
      .map(([id]) => id),
  );
}
```

Two things auditors get wrong here. `GET /v1/subscribers/{app_user_id}` is documented as **get *or
create*** — a 200 with an empty `entitlements` object means "this customer now exists", not "this
customer paid", so never treat a successful response as authorization by itself. And a network
failure must deny, not fall through to a permissive default; cache the last *successful* answer with
a short TTL if you need resilience. The v2 equivalent is
`GET /v2/projects/{project_id}/customers/{customer_id}/active_entitlements`, which returns only
currently-active entitlements; v2 requires a v2 secret key (v1 keys are not accepted) and its own
read permission.

Detect: `grep -rn "api.revenuecat.com" --include=*.ts --include=*.py --include=*.go .` — no server
hit at all, combined with a paid feature, is the finding. Also
`grep -rn "REVENUECAT\|RC_SECRET\|sk_" .env* 2>/dev/null`.

## 3. Webhook Authenticity — Both Mechanisms Are Opt-In

**What to look for:** a webhook route that parses the body and acts on it with no verification, or a
verification that can pass when the secret is missing.

**Why it's exploitable:** unlike Stripe, RevenueCat does not sign by default. Two protections exist
and **both are optional dashboard settings**, so the common vibe-coded state is a fully
unauthenticated public endpoint that grants subscriptions to whoever POSTs to it:

- **HMAC signing** (preferred): enable it on the integration and every delivery carries
  `X-RevenueCat-Webhook-Signature: t=<unix_timestamp>,v1=<hmac_sha256_hex>`, where the HMAC-SHA256
  is computed over `"<timestamp>.<raw_json_body>"` with the integration's signing secret. Same
  raw-body discipline as Stripe (`secaudit:payments`): `JSON.parse` → `JSON.stringify` changes the
  bytes and breaks valid requests, so read the raw text first. The secret is shown once at creation
  or rotation and cannot be retrieved later.
- **Authorization header** (fallback, and all you get if signing is off): a caller-configured static
  string RevenueCat echoes on every request. The entire security of the channel is one shared secret
  compared in your handler — so compare it in constant time, and reject an unset or empty
  configured value *before* comparing, or an unset secret silently matches an absent header.

Either way the endpoint must be HTTPS-only (RevenueCat asks for an HTTPS URL; a plaintext hop leaks
the static header to anyone on path, and a static header, unlike a signature, is replayable forever
once seen). Verify signature/header **before** parsing, and return non-2xx on failure.

```typescript
// BAD — fails open, compares in variable time, and destroys the raw body
export async function POST(request: Request) {
  const auth = request.headers.get("authorization");
  if (auth !== `Bearer ${process.env.RC_WEBHOOK_SECRET}`) {  // unset env => "Bearer undefined",
    return new Response("Unauthorized", { status: 401 });    // which any attacker can just send
  }
  const { event } = await request.json();        // raw bytes gone; HMAC can no longer be checked
  await db.users.update({ where: { id: event.app_user_id }, data: { isPro: true } });
  return new Response(null, { status: 200 });
}

// GOOD — HMAC verified over the raw body, fail-closed, constant-time, replay-bounded
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

// timingSafeEqual throws on length mismatch; hashing both sides fixes the width safely.
const constantTimeEqual = (a: string, b: string) =>
  timingSafeEqual(createHash("sha256").update(a).digest(),
                  createHash("sha256").update(b).digest());

export async function POST(request: Request) {
  const secret = process.env.REVENUECAT_WEBHOOK_SIGNING_SECRET;
  if (!secret) return new Response("Not configured", { status: 500 }); // never verify with ""

  const raw = await request.text();                                     // raw bytes, unparsed
  const header = request.headers.get("x-revenuecat-webhook-signature") ?? "";
  const parts = new Map(header.split(",").map((p) => {
    const i = p.indexOf("=");
    return [p.slice(0, i), p.slice(i + 1)] as const;
  }));
  const t = parts.get("t"), v1 = parts.get("v1");
  if (!t || !v1) return new Response("Unsigned", { status: 401 });

  const expected = createHmac("sha256", secret).update(`${t}.${raw}`).digest("hex");
  if (!constantTimeEqual(expected, v1)) return new Response("Bad signature", { status: 401 });
  // t is when RevenueCat signed THIS attempt (re-signed on every retry), not the event time —
  // a few minutes of clock-skew tolerance is right; do not widen it to cover retry backoff.
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return new Response("Stale", { status: 401 });

  const { event } = JSON.parse(raw);
  // ... §4 onward
  return new Response(null, { status: 200 });
}
```

Detect: find the handler with `grep -rniE "revenuecat|revenue_cat" --include=*.ts --include=*.py \
--include=*.go . | grep -iE "webhook|hook|route|handler"`, then confirm it contains one of
`x-revenuecat-webhook-signature` / `createHmac` / `hmac` / a constant-time compare
(`timingSafeEqual`, `hmac.compare_digest`, `hash_equals`, `subtle.ConstantTimeCompare`):
`grep -rn "x-revenuecat-webhook-signature\|timingSafeEqual\|compare_digest\|hash_equals" .`
Zero hits next to a RevenueCat route is a critical finding.

## 4. Webhook Events Are Notifications, Not Authorization

**What to look for:** a handler that *applies a delta* from whatever event arrived —
`INITIAL_PURCHASE` sets `isPro = true`, `credits += 100`, `EXPIRATION` sets it false — with no
event-id bookkeeping and no re-derivation.

**Why it's exploitable:** RevenueCat guarantees *at-least-once* delivery and retries failures up to
five times with increasing delay, so duplicates are expected, not exotic. Retries reuse the same
payload `id` and `event_timestamp_ms`. Cancellation events can lag the user action by hours while a
renewal lands promptly, so ordering is not guaranteed either. A handler that increments credits per
`RENEWAL`, or that lets a late-arriving `EXPIRATION` clobber a newer `RENEWAL`, is wrong even with a
perfect signature check — and a replayed body (if you rely on the static header, which never
expires) is free money.

**Fix:** treat the event as a *trigger to re-read state*, exactly as RevenueCat recommends —
after any webhook, fetch the customer and rewrite entitlement to the returned value. Combine with
idempotency on `event.id` so duplicates are cheap no-ops. Absolute state, never a delta.

```typescript
// BAD — delta applied per event: duplicates double-credit, out-of-order flips the wrong way
switch (event.type) {
  case "INITIAL_PURCHASE":
  case "RENEWAL":
    await db.users.update({ where: { id: userId }, data: { credits: { increment: 100 } } });
    break;
  case "EXPIRATION":
    await db.users.update({ where: { id: userId }, data: { isPro: false } });
    break;
}

// GOOD — idempotent by event id, then re-derive absolute state from RevenueCat
const seen = await db.webhookEvents.createMany({
  data: [{ id: event.id, type: event.type }],
  skipDuplicates: true,            // unique PK on event.id makes replay a no-op
});
if (seen.count === 0) return new Response(null, { status: 200 }); // already processed

const entitlements = await activeEntitlements(event.app_user_id); // §2 — the source of truth
await db.users.update({
  where: { id: userId },
  data: { isPro: entitlements.has("pro") },   // absolute, recomputed, not incremented
});
```

Respond 200 quickly and defer heavy work — RevenueCat disconnects after 60s and treats any non-200
as a failure. Also handle unknown `event.type` values gracefully: RevenueCat documents that it may
add new event types without an API-version bump, so a `switch` with no `default` will silently drop
future events.

Detect: `grep -rn "event.id\|event\[.id.\]" --include=*.ts . | grep -iE "revenuecat|webhook"` — no
hit means no idempotency. And `grep -rnE "increment|decrement|\+=|-=" --include=*.ts . |
grep -iE "credit|token|balance|quota"` inside a webhook handler.

## 5. Sandbox and Test Store Purchases Accepted in Production

**What to look for:** a webhook handler that never reads `event.environment`, or server-side
derivation that ignores `is_sandbox` on the underlying transaction.

**Why it's exploitable:** anyone can create an App Store sandbox tester or a Google Play license
tester account and buy your subscription for free; a TestFlight build's purchases are sandbox
purchases too. RevenueCat marks these — webhook events carry `environment: "SANDBOX"` vs
`"PRODUCTION"`, and v1 subscriber transactions carry `is_sandbox`. Critically, RevenueCat has **no
sandbox/production split at the customer level**: the docs are explicit that the same App User ID
can hold both production and non-production receipts, so you cannot segregate by user or by
deployment — the check has to be per transaction, on the server.

Related and easy to miss: RevenueCat's **Test Store** is a built-in fake store with its own separate
API key, where purchases behave like real ones and grant entitlements. Shipping a build configured
with a Test Store key to production means every user can "buy" for free. The launch checklist is
explicit that production must use the platform-specific key.

```typescript
// BAD — environment ignored; a sandbox tester gets production entitlement
if (event.type === "INITIAL_PURCHASE") await grantPro(event.app_user_id);

// GOOD — allow-list the one environment that means real money
// (allow-list, not `!== "SANDBOX"`: RevenueCat may add values without an API-version bump)
if (process.env.NODE_ENV === "production" && event.environment !== "PRODUCTION") {
  console.info("rc: ignoring non-production event", { id: event.id, env: event.environment });
  return new Response(null, { status: 200 });   // acknowledge so RevenueCat stops retrying
}
```

When deriving from the REST API instead of the event, the v1 `entitlements` object does not itself
carry a sandbox marker — cross-check the backing entry under `subscriptions` / `non_subscriptions`
for `is_sandbox: true` before honouring it in production. Cleanest operational fix: configure
separate webhook integrations filtered to production and to sandbox, pointing at separate
environments, and keep the sandbox key out of release builds entirely.

Detect: `grep -rn "environment\|is_sandbox\|SANDBOX" --include=*.ts . | grep -iE "revenuecat|event"`
— absent in a webhook handler is the finding. For the key mix-up, check which key each build flavour
passes to `Purchases.configure`: `grep -rn "Purchases.configure\|configureWith\|PurchasesConfiguration" .`

## 6. Entitlement Written to a Database the Client Can Write

This is the highest-impact item in this skill, because it silently undoes every control above. You
can verify the webhook perfectly and still ship a one-call upgrade if the *write path* is reachable
from the client.

**Convex** — the sharp edge, because Convex has **no row-level security**: every `query`, `mutation`,
and `action` is a public internet-facing endpoint callable with arbitrary arguments by anyone with
your deployment URL, and its name is visible in the app bundle. A public `setProStatus` mutation is
a free subscription. The entitlement write must be an `internalMutation` invoked only from the
webhook `httpAction`. See `secaudit:convex-security` for the full model.

```typescript
// BAD — convex/billing.ts: public mutation, client picks both the user and the answer
export const setProStatus = mutation({
  args: { userId: v.id("users"), isPro: v.boolean() },
  handler: async (ctx, { userId, isPro }) => ctx.db.patch(userId, { isPro }),
});

// GOOD — convex/billing.ts: not client-callable; only the verified webhook can reach it
export const setProStatus = internalMutation({
  args: { appUserId: v.string(), isPro: v.boolean() },
  handler: async (ctx, { appUserId, isPro }) => {
    const user = await ctx.db
      .query("users").withIndex("by_app_user_id", (q) => q.eq("appUserId", appUserId)).unique();
    if (!user) return;
    await ctx.db.patch(user._id, { isPro });
  },
});

// convex/http.ts — verify (§3), re-derive (§2, §4), then call the internal mutation
http.route({ path: "/revenuecat", method: "POST", handler: httpAction(async (ctx, request) => {
  const event = await verifyRevenueCatWebhook(request);          // throws / 401 on bad signature
  if (!event) return new Response("Unauthorized", { status: 401 });
  const entitlements = await activeEntitlements(event.app_user_id);
  await ctx.runMutation(internal.billing.setProStatus, {
    appUserId: event.app_user_id, isPro: entitlements.has("pro"),
  });
  return new Response(null, { status: 200 });
})});
```

The same failure has a different shape on every backend, and the question is always "who can write
this column?":

- **Supabase** — an RLS policy that lets a user `UPDATE` their own `profiles` row usually lets them
  update *every* column of it, entitlement flag included. Keep entitlement in a separate table with
  no client `INSERT`/`UPDATE`/`DELETE` policy at all (writes only via the service-role key from your
  webhook), or add a column-level grant / trigger that rejects client changes to it. RLS is not
  enforced for the service role — so that key must never be in the app. See `secaudit:database`.
- **Firebase** — the Security Rule for the user document must deny writes to the entitlement field;
  a blanket `allow write: if request.auth.uid == userId` is a self-serve upgrade. Write it from a
  Cloud Function (Admin SDK bypasses rules) and deny it to clients.
- **Any backend** — an `updateProfile` / `PATCH /me` endpoint that spreads the request body into the
  update is the same bug by mass assignment (`secaudit:data-access`).

Detect (Convex): `grep -rn "mutation(" convex/ | grep -viE "internalMutation"` then read each for
entitlement fields. Cross-cut:
`grep -rniE "(isPro|isPremium|isSubscribed|subscriptionStatus|plan|tier|entitlement)" --include=*.ts \
--include=*.sql --include=*.rules .` and, for each hit, ask what the client is allowed to write.

## 7. App User ID Trust

**What to look for:** `Purchases.logIn(...)` (or `configure({ appUserID })`) fed an email address, a
sequential database integer, a device identifier, or any value the client picks.

**Why it's exploitable:** the App User ID *is* the subscriber identity. RevenueCat's own guidance is
blunt: IDs must not be guessable, because subscription status is served through the public API —
a guessable ID means anyone can query someone else's status, and calling `logIn` with a known ID
attaches the device to that subscriber record. Emails are called out explicitly as a bad choice (for
guessability and GDPR), as are IDFA/advertising IDs and, worst of all, a hardcoded string — which
makes every install the same customer and hands everyone the first buyer's entitlement. Use the
authenticated user id issued by your auth provider (an opaque UUID), never client-supplied input.

```typescript
// BAD — guessable, client-chosen, and PII in every webhook and export
await Purchases.logIn({ appUserID: user.email });
await Purchases.logIn({ appUserID: String(user.rowId) });        // 1, 2, 3, ...

// GOOD — opaque id from the verified session, taken from the server's answer, not local state
const { user } = await auth.getSession();                        // server-verified
if (user) await Purchases.logIn({ appUserID: user.id });         // e.g. a v4 UUID
```

**The alias flow is the subtle part.** Before login the SDK mints an anonymous ID prefixed
`$RCAnonymousID:`. Calling `logIn` from that anonymous ID *may* merge the two identities into one
customer — and whether it does depends on whether the target ID already exists and whether it
already has an anonymous alias; when it does not merge, the anonymous user is simply logged out and
no purchase transfer occurs. So: never assume a purchase made before login automatically follows the
user, and never key entitlement on `original_app_user_id` alone — after a merge that field holds
only one of the IDs and the rest arrive in the `aliases` array. On the server, resolve any incoming
`app_user_id` (and each entry of `aliases`) to *your* user record and re-derive (§2); treat a
`TRANSFER` event, whose `transferred_from` / `transferred_to` arrays move entitlements between App
User IDs, as a signal to recompute **both** sides — the webhook is only sent for the destination
user, so the source user's access will not be revoked unless you do it.

Detect: `grep -rn "logIn(\|appUserID\|appUserId\|app_user_id" --include=*.ts --include=*.tsx \
--include=*.swift --include=*.kt .` then check the provenance of each value —
`grep -rnE "logIn\((\"|')" .` finds hardcoded ones outright.

## 8. Public SDK Key vs Secret API Key (avoid the false positive)

**Do not flag the public key.** RevenueCat has two key types and only one is a secret:

- **Public API keys** (labelled *SDK API keys* in the dashboard, one per app, platform-specific) are
  *designed* to ship in the client and are the only thing `Purchases.configure` should ever receive.
  Finding one in an app bundle, in `app.json`, or behind an `EXPO_PUBLIC_` / `NEXT_PUBLIC_` prefix
  is **correct usage**, exactly like a Stripe publishable key. Reporting it as a leaked credential is
  a false positive that costs you the reader's trust; note it and move on.
- **Secret API keys**, prefixed **`sk_`**, are project-wide and can perform privileged operations —
  granting promotional entitlements, refunding and revoking purchases, deleting customers. One in a
  mobile bundle, in client-side JS, or committed to git is a critical finding: rotate it (revocation
  is immediate) and treat every entitlement it could have granted as suspect.

```typescript
// FINE — public SDK key in the client is the documented, intended configuration
await Purchases.configure({ apiKey: process.env.EXPO_PUBLIC_REVENUECAT_IOS_KEY! });

// CRITICAL — sk_ key in anything the user can download or read
await Purchases.configure({ apiKey: "sk_..." });                     // never
const res = await fetch(`${RC_V1}/subscribers/${id}`, {                        // from the app
  headers: { Authorization: `Bearer ${process.env.EXPO_PUBLIC_RC_SECRET!}` }, // never
});
```

Report any real key by **location and masked form** (`sk_…` plus last 4), never the literal value.
See `secaudit:secrets` for the general prefix rules and `secaudit:expo-security` for why an EAS
"Secret" variable inlined at build time is still public in the binary.

Detect: `grep -rn "sk_[A-Za-z0-9]" --include=*.ts --include=*.tsx --include=*.swift --include=*.kt \
--include=*.json . ` and `git log -p -S 'sk_' --all | head -50` for history. Cross-check against
`grep -rn "EXPO_PUBLIC_\|NEXT_PUBLIC_\|VITE_" . | grep -i revenuecat` — a `sk_` behind a public
prefix is the finding; a platform SDK key behind one is not.

## 9. Refunds, Revocations, Billing Issues, and Grace Periods

**What to look for:** a handler that grants on purchase events and has no branch that ever takes
entitlement away — or one that revokes on the wrong signal.

**Why it matters:** a refunded user who keeps premium forever is a direct, repeatable loss, and
refunds can arrive **long** after the purchase. RevenueCat does not emit a `REFUND` event type:
a refund surfaces as **`CANCELLATION`** with `cancel_reason` (`CUSTOMER_SUPPORT` for a
support-issued refund, alongside `UNSUBSCRIBE`, `BILLING_ERROR`, `DEVELOPER_INITIATED`,
`PRICE_INCREASE`, `UNKNOWN`), and a reversal arrives as **`REFUND_REVERSED`**. Because the naming
does not match intuition, handlers written from memory routinely miss it.

The traps in the other direction — revoking too eagerly — are just as common:

- **`CANCELLATION` is not expiry.** For a normal unsubscribe the user keeps access until the period
  ends; only `EXPIRATION` means access should be removed. But for a *refund* the money is already
  gone, and auto-renew may still be on.
- **`BILLING_ISSUE` is not expiry** either — a charge failed, the subscription may still be in a
  grace period (`grace_period_expires_date` in the REST response). RevenueCat notes you can ignore
  it entirely if you handle `CANCELLATION` with `cancel_reason=BILLING_ERROR`.
- **`SUBSCRIPTION_PAUSED` must not revoke.** The docs are explicit: revoke only on `EXPIRATION`
  whose `expiration_reason` is `SUBSCRIPTION_PAUSED`.

All of which is an argument for §4's design rather than a bigger `switch`: subscribe to *all*
lifecycle event types, and let every one of them trigger the same "re-read the customer, write the
absolute answer" path. Then the taxonomy above is RevenueCat's problem, not yours.

```typescript
// BAD — grants only, and mis-reads two of the three revocation signals
if (event.type === "INITIAL_PURCHASE" || event.type === "RENEWAL") await grantPro(userId);
if (event.type === "CANCELLATION" || event.type === "BILLING_ISSUE") await revokePro(userId);
// refund via CANCELLATION/CUSTOMER_SUPPORT leaves auto-renew on; a paused sub is revoked early;
// a grace-period user is cut off; REFUND_REVERSED never restores access

// GOOD — one path for every lifecycle event: re-derive and write the absolute answer
const LIFECYCLE = new Set([
  "INITIAL_PURCHASE", "RENEWAL", "CANCELLATION", "UNCANCELLATION", "NON_RENEWING_PURCHASE",
  "EXPIRATION", "BILLING_ISSUE", "PRODUCT_CHANGE", "SUBSCRIPTION_PAUSED",
  "SUBSCRIPTION_EXTENDED", "REFUND_REVERSED", "TRANSFER",
]);
if (LIFECYCLE.has(event.type)) {
  const entitlements = await activeEntitlements(event.app_user_id); // §2, honours expiry + grace
  await setEntitlement(userId, entitlements.has("pro"));            // absolute; grants AND revokes
}
```

Belt and braces: because a webhook can be missed entirely (misconfiguration, an outage on your side
after the five retries are exhausted, an integration added after users already subscribed), re-derive
on a schedule too — a nightly reconciliation over active subscribers, or a re-check on session start
for anything expensive. Persist `expires_date` and let it expire naturally rather than depending on
an `EXPIRATION` event ever arriving.

Detect: `grep -rn "REFUND_REVERSED\|CANCELLATION\|EXPIRATION\|cancel_reason\|expiration_reason" \
--include=*.ts .` — grant-side event types present with no revocation branch is the finding. Also
`grep -rn "grace_period_expires_date\|expires_date" --include=*.ts .` for expiry actually being
stored and enforced.

## Footgun Checklist

- Entitlement decided by `customerInfo.entitlements.active[...]` in front of a *server* capability.
- No `api.revenuecat.com` call and no webhook anywhere — the backend never learned who paid.
- Webhook with neither HMAC verification nor an `Authorization` check; or a check that passes when
  the configured secret is unset/empty, or compares with `===`.
- Body parsed before the signature is computed (raw bytes destroyed).
- No idempotency on `event.id`; state applied as a delta (`+=`) instead of re-derived absolutely.
- `event.environment` / `is_sandbox` never inspected; or a Test Store key in a production build.
- Entitlement column writable by the client — a public Convex `mutation`, a permissive Supabase RLS
  `UPDATE` policy, an open Firebase rule, or a spread-body `PATCH /me`.
- App User ID that is an email, a sequential integer, a device ID, or a hardcoded string.
- `sk_` key in the bundle, client JS, or git history. (A platform SDK key there is *fine*.)
- Grant path exists, revoke path does not; `REFUND_REVERSED` unhandled; `BILLING_ISSUE` or
  `SUBSCRIPTION_PAUSED` treated as expiry; no reconciliation job for missed webhooks.

See also `secaudit:payments` (Stripe webhooks, server-side prices, subscription status),
`secaudit:convex-security` (public vs internal functions), `secaudit:database` (Supabase RLS,
Firebase rules), `secaudit:secrets`, `secaudit:expo-security` and
`secaudit:react-native-security` (mobile bundle exposure), `secaudit:rate-limiting` (paid-feature
abuse), and `secaudit:data-access` (mass assignment).

## Sources

- https://www.revenuecat.com/docs/integrations/webhooks -- optional auth header, HMAC signing, retries, at-least-once delivery, idempotency by event id
- https://www.revenuecat.com/docs/integrations/webhooks/event-types-and-fields -- event types, environment, cancel_reason/expiration_reason, transfer fields
- https://www.revenuecat.com/docs/integrations/webhooks/sample-events -- full sample payloads
- https://www.revenuecat.com/docs/api-v1 -- GET /subscribers (get or create), is_sandbox, entitlements object
- https://www.revenuecat.com/docs/api-v2 -- active_entitlements endpoint, Bearer secret key, v1 keys not accepted
- https://www.revenuecat.com/docs/projects/authentication -- public SDK keys vs secret sk_ keys, rotation and revocation
- https://www.revenuecat.com/docs/customers/customer-info -- entitlements.active, cached CustomerInfo
- https://www.revenuecat.com/docs/customers/identifying-customers -- non-guessable App User IDs, no emails, logIn alias behaviour
- https://www.revenuecat.com/docs/customers/user-ids -- App User IDs and aliases as one customer
- https://www.revenuecat.com/docs/customers/trusted-entitlements -- response signature verification is informational only
- https://www.revenuecat.com/docs/getting-started/entitlements -- entitlement model
- https://www.revenuecat.com/docs/test-and-launch/sandbox -- Test Store vs platform sandboxes; same App User ID holds both
- https://www.revenuecat.com/docs/test-and-launch/sandbox/apple-app-store -- TestFlight and StoreKit local testing behaviour
- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ -- A01:2025 Broken Access Control
- https://supabase.com/docs/guides/database/postgres/row-level-security -- RLS policies; service role bypasses RLS
- https://firebase.google.com/docs/rules/basics -- Firebase Security Rules; Admin SDK bypasses rules
