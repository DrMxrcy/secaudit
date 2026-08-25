---
name: payments
description: Audits payment flows (Stripe and similar) — never trusting client-submitted prices, verifying webhook signatures against the raw request body, validating subscription status server-side on every request, and setting checkout metadata server-side. Use whenever writing or reviewing checkout, billing, subscriptions, or webhook handlers, or when auditing for price manipulation and payment bypass.
license: MIT
---

# Payment Security (Stripe)

## When to Use

- Writing or reviewing checkout, billing, subscription, or webhook code.
- Integrating Stripe (or a similar processor).
- Auditing for price manipulation, payment bypass, or forged webhook events.

## Never Trust Client-Submitted Prices

The #1 payment vulnerability in vibe-coded apps: the price comes from the client. An attacker can
set any amount, including $0.

```typescript
// BAD: price comes from the request body
const session = await stripe.checkout.sessions.create({
  line_items: [{
    price_data: {
      currency: 'usd',
      unit_amount: req.body.price, // attacker controls this
      product_data: { name: req.body.name },
    },
    quantity: 1,
  }],
});

// GOOD: look up the price server-side
const product = await db.products.findUnique({ where: { id: req.body.productId } });
if (!product) return new Response('Not found', { status: 404 });

const session = await stripe.checkout.sessions.create({
  line_items: [{ price: product.stripePriceId, quantity: 1 }],
});
```

Use Stripe Price IDs (created via the Stripe dashboard or API) rather than constructing prices
from your database. This way, prices are defined in Stripe and can't be manipulated.

## Webhook Signature Verification

Stripe webhooks must have their signatures verified. This requires the **raw request body** —
parsing the body as JSON first destroys the signature.

```typescript
// Express: webhook route MUST use express.raw() BEFORE express.json()
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  // ... handle event
});

// Next.js App Router: use request.text(), NOT request.json()
export async function POST(request: Request) {
  const body = await request.text();
  const sig = request.headers.get('stripe-signature')!;
  const event = stripe.webhooks.constructEvent(body, sig, webhookSecret);
  // ... handle event
}
```

### A verified signature is not the whole check

Signature verification proves the payload came from Stripe. It does not prove this is the *first*
time you have seen it, or that it is *recent*. Four controls Stripe's own webhook docs call for
are routinely skipped, because the handler looks finished once `constructEvent` stops throwing.

**1. Replay — do not disable the recency check.** Stripe signs a timestamp into
`Stripe-Signature` so a captured payload cannot be re-sent indefinitely. The libraries default to
a 5-minute tolerance. Stripe's docs are blunt about the footgun: *"Don't use a tolerance value of
`0`. Using a tolerance value of `0` disables the recency check entirely."*

```typescript
// BAD: silences a "timestamp outside tolerance" error by removing the protection
stripe.webhooks.constructEvent(body, sig, secret, 0);

// GOOD: keep the default, or widen it only slightly and fix the clock instead
stripe.webhooks.constructEvent(body, sig, secret);   // 5 minutes
```

If you hit tolerance errors, the cause is almost always server clock drift — run NTP rather than
widening the window.

**2. Duplicates — be idempotent on `event.id`.** Stripe retries failed deliveries for up to three
days, and the docs note an endpoint *"might occasionally receive the same event more than once"*.
Without idempotency a retried `invoice.paid` grants the entitlement, or the credits, twice.

```typescript
// GOOD: record the event id first; a unique constraint makes the replay a no-op
const seen = await db.webhookEvent.createMany({
  data: [{ id: event.id }], skipDuplicates: true,
});
if (seen.count === 0) return new Response('ok');   // already processed
```

Also do not assume ordering — Stripe explicitly does not guarantee it, so a handler that requires
`customer.subscription.created` before `invoice.paid` will eventually be wrong.

**3. Verify the sender two ways.** Stripe's docs list IP allowlisting *and* signature verification
together, not as alternatives. Restrict the endpoint to Stripe's published webhook IP ranges at
the firewall or edge, and verify the signature in the handler.

**4. Rotate the signing secret.** Secrets should be rolled periodically, or immediately if one is
suspected compromised. During a roll an endpoint has **multiple active secrets** and Stripe signs
once per secret — so a handler hardcoded to exactly one secret fails during rotation, which is
how rotation gets abandoned. Read the secret from the environment and support a second one during
the overlap window.

**Operational note:** Stripe treats a `3xx` response to a webhook as a **failure**. An endpoint
sitting behind a redirect (a trailing-slash rule, an apex→www rewrite) silently receives nothing.
Register the URL the redirect resolves to. This presents as "payments stopped working" with no
error anywhere in your logs.

## Subscription Status Validation

Check subscription status **server-side on every protected request** using your database (kept in
sync via webhooks). Do not rely on:
- A cached session value from login time
- A client-side flag
- A JWT claim that was set at token creation and never refreshed

Subscriptions can be cancelled, expire, or change tier at any time. Your database (updated via
webhooks) is the source of truth.

## Checkout Session Metadata

Validate that checkout session metadata (user ID, plan, etc.) was set **server-side** when
creating the session, not passed from the client. If metadata comes from the client, an attacker
can claim to be a different user or select a different plan.

## Sources

- https://docs.stripe.com/webhooks/signature -- signature verification requires the raw body
- https://docs.stripe.com/webhooks -- constructEvent, endpoint secret, event handling
- https://docs.stripe.com/products-prices/how-products-and-prices-work -- server-side Price IDs, not client amounts
