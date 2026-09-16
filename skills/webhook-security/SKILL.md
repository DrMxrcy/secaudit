---
name: webhook-security
description: Audits inbound webhook handlers — the route that receives events from GitHub, Slack, Discord, Svix-backed senders (Clerk, Resend), Telegram, Twilio, Shopify, Linear, and Vercel. Covers per-sender signature verification (`X-Hub-Signature-256`, `X-Slack-Signature`, `X-Signature-Ed25519`, `svix-signature`, `X-Telegram-Bot-Api-Secret-Token`, `X-Twilio-Signature`, `X-Shopify-Hmac-SHA256`), raw-body-before-parsing, constant-time comparison, timestamp tolerance and replay/idempotency by delivery id, and failing closed when the signing secret is unset. Use whenever the project has a route under `/api/webhooks/`, `/interactions`, or similar that receives a third-party callback, or when writing or reviewing that handler. Stripe and RevenueCat webhook verification stay in `secaudit:payments` and `secaudit:revenuecat-security`; outbound webhooks your app sends to a user-supplied URL are `secaudit:web-vulns` (SSRF).
license: MIT
---

# Webhook Security (Inbound Verification)

A webhook route is a POST endpoint on the public internet with no session, no cookie, and no login
screen — the only thing separating "GitHub told me about a push" from "an attacker's curl command
told me about a push" is whatever signature check the handler performs. Every sender solves this the
same way in outline (sign the body with a shared secret, send the signature in a header, compare it
on receipt) and differently in the details that matter: which header, which algorithm, what exactly
gets signed, and whether a timestamp is included at all. Copy the wrong sender's recipe onto the
wrong route and the check silently verifies nothing.

The recurring AI-codegen failure mode is a handler that *works* against the sender's test payload
and skips the parts that only matter under attack: verifying against the framework's parsed JSON
instead of the raw body (the signature no longer matches anything, so the check is quietly disabled
by "helpfully" re-serializing), comparing signatures with `===` instead of a constant-time function,
and treating a payload that passed signature verification as fully trustworthy — including fields
the sender never actually vouches for. Findings here map to OWASP **A07:2025** (Authentication
Failures — the signature check *is* how you authenticate the sender), **A08:2025** (Software or Data
Integrity Failures — replay, and acting on data the signature never covered), and **A01:2025**
(Broken Access Control — an outbound webhook is an SSRF surface, §9).

`secaudit:payments` covers Stripe webhooks in full (replay tolerance, event-id idempotency, IP
allowlisting, secret rotation, the 3xx footgun) and `secaudit:revenuecat-security` covers RevenueCat's
opt-in HMAC and Authorization-header schemes — read those for those two senders specifically. This
skill covers every other sender you're likely to integrate, plus the cross-cutting rules that apply
regardless of which one you're implementing.

## When to Use

- Any route under `/api/webhooks/`, `/webhooks/`, `/interactions`, or a similarly named path that
  receives a POST from a third-party service.
- Writing or reviewing a handler for GitHub, Slack, Discord, Clerk, Resend, or any other Svix-backed
  sender, Telegram, Twilio, Shopify, Linear, or Vercel.
- Configuring a webhook URL at a sender's dashboard, or generating a signing/verification secret.
- Auditing whether a handler can be replayed, whether it trusts a field the sender didn't sign, or
  whether it fails open when a secret env var is missing.

Review grep heuristics:

```bash
grep -rniE 'x-hub-signature-256|x-slack-signature|x-signature-ed25519|svix-signature|svix-id|\
x-telegram-bot-api-secret-token|x-twilio-signature|x-shopify-hmac|linear-signature|x-vercel-signature' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rlnE '/webhooks?/|/interactions' --include='*.ts' --include='*.tsx' . \
  | xargs grep -LE 'timingSafeEqual|compare_digest|createHmac|verify\(' 2>/dev/null   # handlers with no visible crypto at all
grep -rnE 'express\.json\(\)|bodyParser\.json\(\)' --include='*.ts' . \
  | grep -B2 -A2 webhook   # JSON body-parser wired ahead of a webhook route
```

## 1. Cross-Cutting Rules — Apply to Every Sender Below

These eight rules recur across every provider section. Get them wrong once in a shared middleware
or helper and every webhook route behind it is wrong the same way.

**Raw body before JSON parsing.** Every signature below is computed over the exact bytes the sender
sent — whitespace, key order, everything. A body-parser that runs before the verification step (or
runs at all, framework-wide) re-serializes JSON into a *different* byte string with the same
meaning, so the signature no longer matches anything. This is the single most common reason a
"working" webhook silently stops verifying: someone adds global `express.json()` for the rest of the
app and the webhook route inherits it.

```ts
// BAD — app.use(express.json()) upstream already consumed and re-serialized the body
app.post('/webhooks/github', (req, res) => {
  const digest = crypto.createHmac('sha256', secret).update(JSON.stringify(req.body)).digest('hex');
  // req.body is a JS object; JSON.stringify(req.body) is not the bytes GitHub signed
});

// GOOD — this route gets the raw bytes, before any JSON body-parser touches them
app.post('/webhooks/github', express.raw({ type: 'application/json' }), (req, res) => {
  const digest = crypto.createHmac('sha256', secret).update(req.body).digest('hex'); // req.body: Buffer
});
```

Next.js App Router: `await req.text()`, never `await req.json()`, for the same reason (see §5 for the
framework-by-framework list Svix's docs give).

**`crypto.timingSafeEqual` throws on a length mismatch — check length first.** Node's docs are
explicit: "The `a` and `b` arguments must have the same byte length or an error is thrown." A naive
`try { return timingSafeEqual(a, b) } catch { return false }` works but is easy to get wrong under
refactoring; comparing lengths first is the clearer fix and avoids relying on exception flow for a
security decision.

```ts
function safeCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;   // check first — mismatched length throws, not `false`
  return crypto.timingSafeEqual(a, b);
}
```

**Fail closed when the secret env var is unset.** A webhook secret missing from the environment
(typo'd name, never set in this deploy target, wiped by a config migration) must stop the app from
serving that route at all, not silently skip verification. Read the secret once at startup and throw
if it's absent — do not let a per-request `if (secret) { verify }` become the fallback.

**No 3xx responses.** Every sender treats a redirect as delivery failure, not delivery-then-follow.
Stripe's docs put it in one line (quoted in `secaudit:payments`): *"We consider redirect responses
to webhook requests as failures."* Register the exact URL your app resolves to — not one behind a
trailing-slash rule or an apex→www rewrite — for every sender in this skill, not just Stripe.

**Don't act on unverified payload fields.** A valid signature proves the sender sent *this exact
body*; it says nothing about whether a field inside that body should be trusted as an authorization
decision on your side. Concretely: a webhook payload that includes a role name, a user id, an email,
or an "is_admin" flag is data the sender is relaying, often user-editable data (a GitHub display
name, a Slack profile field) — not a claim your access-control logic should honor. Look the
corresponding record up in your own database by a stable id instead of trusting the payload's
description of it.

**Webhook URLs with embedded tokens are secrets.** Some senders hand you a URL to *post to* (Slack
Incoming Webhooks, Discord's channel webhook URLs) rather than a header to verify on receipt — the
authorization is a token embedded in the URL path. That URL is a bearer credential exactly like an
API key: never commit it, never log it, never put it in client-side code, and rotate it the same way
you would a leaked key (`secaudit:secrets`).

**Dedupe by delivery/event id.** Every sender in this skill retries, and several document no signed
timestamp at all (§2, §6–8) — the only replay defense available is treating the delivery as a no-op
the second time you see its id. Record the id with a unique constraint before doing anything
side-effecting; a duplicate insert failing is your idempotency check.

```ts
const seen = await db.webhookEvent.createMany({ data: [{ id: deliveryId }], skipDuplicates: true });
if (seen.count === 0) return new Response('ok', { status: 200 });   // already processed
```

**Timestamp tolerance, where the sender signs one.** Slack, Svix/Standard-Webhooks-family senders,
and Linear sign a timestamp into the payload specifically so a captured request can't be replayed
indefinitely — treat a "timestamp outside tolerance" rejection as correct behavior to fix your clock
against (run NTP), never as friction to work around by widening or removing the window.

## 2. GitHub

**What to look for:** a handler that reads `X-Hub-Signature-256` but only verifies when the header is
present — `if (sig) { verify() }` — falling through to "allow" when it's absent; comparison with
`===` instead of a constant-time function; verification running against a JSON-parsed body (§1).

**Why it's exploitable:** GitHub documents that the header is sender-conditional: *"The
`X-Hub-Signature-256` header will not be present if you have not configured a secret for your
webhook."* That's about *GitHub's* configuration, not the attacker's — but a handler written to treat
"no header" as "nothing to check" accepts an unsigned POST from anyone the moment your own
`GITHUB_WEBHOOK_SECRET` is unset in a given environment (a preview deploy, a staging config that
never got the secret copied over). GitHub computes the signature as "an HMAC hex digest" — HMAC-SHA256
over the raw payload, value `sha256=<hex>` — and its own docs warn against `==`: *"Never use a plain
`==` operator. Instead consider using a method like `secure_compare`."*

**Fix:** require the secret at boot (§1), reject any request missing the header outright, and compare
with `timingSafeEqual` after a length check.

```ts
// BAD — absence of the header just skips the check; non-constant-time compare
app.post('/webhooks/github', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['x-hub-signature-256'] as string | undefined;
  if (sig) {
    const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(req.body).digest('hex');
    if (sig !== expected) return res.status(401).end();
  }
  handleEvent(JSON.parse(req.body));
});
```

```ts
// GOOD — missing header is a rejection, not a skip; constant-time compare
app.post('/webhooks/github', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['x-hub-signature-256'];
  if (typeof sig !== 'string') return res.status(401).end();
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(req.body).digest('hex');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).end();
  handleEvent(JSON.parse(req.body));
});
```

GitHub has no signed timestamp on this endpoint — replay defense is dedupe-by-id only (§1).

**Detection:**

```bash
grep -rnE "x-hub-signature-256" --include='*.ts' --include='*.js' .
grep -rnE "if\s*\(\s*(sig|signature)\s*\)\s*\{" --include='*.ts' .   # "verify only if present" shape
grep -rnE "sig\s*===?\s*expected|expected\s*===?\s*sig" --include='*.ts' .   # non-constant-time compare
```

## 3. Slack

**What to look for:** verification missing the request-body basestring construction entirely (just
hashing the body); no timestamp check, or a timestamp check with no window; use of `SLACK_SIGNING_SECRET`
absent from the environment with no startup check.

**Why it's exploitable:** Slack signs a *basestring*, not the body alone —
`v0:{timestamp}:{raw_body}` — computed "before any deserialization" of the body, then HMAC-SHA256
over that string with the Signing Secret, prefixed `v0=`, sent as `X-Slack-Signature` alongside
`X-Slack-Request-Timestamp`. Hashing only the body against a signature built from `v0:ts:body`
never matches, which means a naive re-implementation either always rejects (and gets "fixed" by
someone disabling it) or — worse — is copy-pasted with the timestamp silently dropped from the
basestring, which also breaks replay protection even if the hash otherwise passes. Slack's docs
require checking the timestamp is *"within five minutes of current time"* independently of the hash.

**Fix:** build the exact basestring, HMAC-SHA256 it, compare constant-time, and reject anything
outside the 5-minute window before you even look at the signature.

```ts
// GOOD
import crypto from 'node:crypto';

export function verifySlackRequest(rawBody: string, headers: Headers): boolean {
  const timestamp = headers.get('x-slack-request-timestamp');
  const signature = headers.get('x-slack-signature');
  if (!timestamp || !signature) return false;

  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > 60 * 5) return false;         // 5-minute tolerance

  const basestring = `v0:${timestamp}:${rawBody}`;
  const expected = 'v0=' + crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET!)
    .update(basestring).digest('hex');
  const a = Buffer.from(signature), b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

If the project uses Bolt (`@slack/bolt`), this is handled for you — Bolt for JS/Python/Java verify
automatically from `SLACK_SIGNING_SECRET`. The finding in that case is a hand-rolled verifier existing
*alongside* Bolt, or `SLACK_SIGNING_SECRET` simply not being set.

**Detection:**

```bash
grep -rn "x-slack-signature\|X-Slack-Signature" --include='*.ts' --include='*.js' .
grep -rn "v0:" --include='*.ts' .                       # basestring construction present at all
grep -rnE "SLACK_SIGNING_SECRET" . | grep -v '\.env'     # is it read anywhere?
```

## 4. Discord (Interactions Endpoint)

**What to look for:** an interactions endpoint that parses the body and dispatches before verifying;
verification against the parsed JSON object instead of the raw body string; no `401` on failure (any
other status, or a `200` with an error message); no handling of interaction `type: 1` (PING).

**Why it's exploitable:** Discord's interaction signature is Ed25519, not HMAC — a public-key scheme,
verified with the application's public key, over `timestamp + body` **concatenated as raw text**.
Discord's own security requirement is unambiguous: *"you must validate the request each time you
receive an interaction"*, and on failure *"your app should respond with a `401` error code."* Discord
also treats your endpoint as continuously monitored, not configure-once: it *"will also perform
automated, routine security checks against your endpoint"* and — separately from ordinary
interactions — sends a `type: 1` PING to which *"your app is expected to acknowledge the request by
returning a `200` response with a `PONG` payload."* An endpoint that fails either check (bad
verification, or no PONG) gets its interactions URL **removed** from the application, which reads in
production as "slash commands stopped working" with nothing in your own logs to explain why.

**Fix:** verify with the raw body before parsing, return `401` on any failure, and handle `type: 1`
as its own case before your real interaction logic runs.

```ts
// GOOD — Next.js Route Handler
import nacl from 'tweetnacl';

export async function POST(req: Request) {
  const signature = req.headers.get('x-signature-ed25519');
  const timestamp = req.headers.get('x-signature-timestamp');
  const rawBody = await req.text();                       // raw text — required for the digest
  if (!signature || !timestamp) return new Response('Bad request signature', { status: 401 });

  const isValid = nacl.sign.detached.verify(
    Buffer.from(timestamp + rawBody),
    Buffer.from(signature, 'hex'),
    Buffer.from(process.env.DISCORD_PUBLIC_KEY!, 'hex'),
  );
  if (!isValid) return new Response('Bad request signature', { status: 401 });

  const interaction = JSON.parse(rawBody);
  if (interaction.type === 1) return Response.json({ type: 1 });   // PING -> PONG, before real logic
  return handleInteraction(interaction);
}
```

Discord documents no tolerance window for the signed timestamp — treat replay defense here as
dedupe-by-id (§1) using the interaction's own `id` field.

**Detection:**

```bash
grep -rn "x-signature-ed25519\|X-Signature-Ed25519" --include='*.ts' --include='*.js' .
grep -rln "nacl.sign.detached.verify\|PyNaCl\|VerifyKey" .   # verification library actually present
grep -rn "type.*=== *1\|type.*== *1" --include='*.ts' . | grep -i interaction   # PING handling
```

## 5. Svix and the Standard Webhooks Spec (Clerk, Resend, and Others)

**What to look for:** manual header parsing that ignores the `v1,` version prefix on the signature,
or that only checks the first signature in the header and fails during a secret rotation when
multiple are present; the base64-decoded secret used without stripping the `whsec_` prefix;
verification wired to a framework's parsed-JSON body.

**Why it's exploitable:** Svix implements the open **Standard Webhooks** spec, and Clerk and Resend
both send Svix-formatted webhooks — *"Clerk uses Svix to send our webhooks"*, and Resend's docs
describe manually using *"the Svix libraries ... pass it the headers, body, and webhook secret"* —
so one verification recipe covers all three (and any other Svix/Standard-Webhooks sender). Three
headers arrive: `svix-id`, `svix-timestamp` (seconds since epoch), and `svix-signature` — a
**space-delimited list**, because a secret rotation leaves multiple valid signatures active at once,
each shaped `v1,<base64>`. The signed content is `{svix-id}.{svix-timestamp}.{body}` — id and
timestamp included, not just the body — HMAC-SHA256, key the base64-decoded secret with its
`whsec_` prefix stripped, output base64. Standard Webhooks' spec is blunt about fragility here:
*"even a stray space can cause the signature to be invalid."* Reject any timestamp *"more than five
minutes away (past or future) from the current time."*

**Fix:** use the vendor's SDK verifier (Svix, Clerk's `verifyWebhook`, or a Standard Webhooks
library) rather than hand-rolling the multi-signature parse — but if you must, split the header on
spaces, strip the `v1,` prefix from each candidate, and accept if *any* one matches.

```ts
// GOOD — Clerk (or any Svix sender) via the vendor SDK, raw body required
import { verifyWebhook } from '@clerk/nextjs/webhooks';

export async function POST(req: Request) {
  try {
    const event = await verifyWebhook(req);   // reads raw body + svix-* headers internally
    // ... handle event, dedupe on event id per §1
  } catch {
    return new Response('Verification failed', { status: 400 });
  }
}
```

```ts
// GOOD — manual Svix/Standard Webhooks verification when no SDK is available
import crypto from 'node:crypto';

function verify(rawBody: string, headers: Headers, secret: string): boolean {
  const id = headers.get('svix-id'), ts = headers.get('svix-timestamp');
  const sigHeader = headers.get('svix-signature');
  if (!id || !ts || !sigHeader) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 60 * 5) return false;   // 5-minute tolerance

  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const expected = crypto.createHmac('sha256', key).update(`${id}.${ts}.${rawBody}`).digest('base64');

  return sigHeader.split(' ').some(candidate => {
    const [, sig] = candidate.split(',');                       // strip the "v1," version prefix
    if (!sig) return false;
    const a = Buffer.from(sig, 'base64'), b = Buffer.from(expected, 'base64');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}
```

Framework raw-body notes straight from Svix's own docs: Express needs `bodyParser.raw()` not
`express.json()`; Next.js App Router needs `await req.text()`; NestJS needs `rawBody: true`; FastAPI
needs `await request.body()`; Django needs `request.body`.

**Detection:**

```bash
grep -rn "svix-signature\|svix-id\|svix-timestamp" --include='*.ts' --include='*.js' .
grep -rn "whsec_" . | grep -v '\.env'
grep -rn "\.split(' ')" --include='*.ts' . | grep -i signature   # multi-signature parsing present?
```

## 6. Telegram

**What to look for:** a `setWebhook` call with no `secret_token`, or a handler that never checks
`X-Telegram-Bot-Api-Secret-Token` at all; anyone treating this header as a cryptographic signature
rather than what it is.

**Why it's exploitable:** Telegram's mechanism is deliberately simpler than every other sender in
this skill — there is no HMAC and no signed timestamp. `secret_token` is *"a secret token to be sent
in a header `X-Telegram-Bot-Api-Secret-Token` in every webhook request"* — a **shared secret you
choose**, echoed back verbatim on every delivery, and it is optional: it's an optional parameter of
`setWebhook`. Skip it, and your webhook URL is the entire authorization — anyone who finds or guesses
it can POST fabricated bot updates with no proof of origin at all. Because it's a bare shared secret
rather than a signature over the body, the comparison has to be constant-time for the same reason a
password check does — but there is nothing here proving the *body* wasn't tampered with, only that
the caller knew the token.

**Fix:** always set `secret_token` when registering the webhook, require it be present and match on
every request, and fail closed if your own `TELEGRAM_WEBHOOK_SECRET` is unset.

```ts
// BAD — no secret_token configured at all; the URL is the only barrier
await fetch(`https://api.telegram.org/bot${TOKEN}/setWebhook?url=${WEBHOOK_URL}`);
```

```ts
// GOOD — shared secret set at registration, checked constant-time on receipt
await fetch(`https://api.telegram.org/bot${TOKEN}/setWebhook`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ url: WEBHOOK_URL, secret_token: process.env.TELEGRAM_WEBHOOK_SECRET }),
});

app.post('/webhooks/telegram', (req, res) => {
  const header = req.headers['x-telegram-bot-api-secret-token'];
  const expected = process.env.TELEGRAM_WEBHOOK_SECRET!;
  const a = Buffer.from(String(header ?? ''));
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).end();
  handleUpdate(req.body);
});
```

**Detection:**

```bash
grep -rn "setWebhook" . | grep -v secret_token          # registration missing the secret
grep -rn "x-telegram-bot-api-secret-token" --include='*.ts' --include='*.js' .
```

## 7. Twilio

**What to look for:** validation performed against `req.url` or a hardcoded base URL rather than the
exact URL Twilio was configured with; anything behind a reverse proxy or load balancer where the
handler doesn't reconstruct scheme/host/port the way Twilio saw them; POST params not sorted before
signing; validation skipped for `GET`-based callbacks.

**Why it's exploitable:** Twilio's signature is not just "HMAC the body" — it's HMAC over the **full
request URL with every POST parameter appended, alphabetically sorted**. Twilio's own steps, verbatim:
take *"the full URL of the request URL you specify ... from the protocol (https...) through the end
of the query string"*; if POST, *"sort all the POST parameters alphabetically (using Unix-style
case-sensitive sorting order)"*; *"iterate through the sorted list ... and append the variable name
and value (with no delimiters) to the end of the URL string"*; then *"sign the resulting string with
HMAC-SHA1 using your AuthToken as the key"* and base64-encode it, compared against
`X-Twilio-Signature`. Every piece of that string has to match *exactly* what Twilio itself
constructed — which is where this breaks in practice, not in the crypto: behind a proxy, the
scheme/host/port your app reconstructs from `req` frequently disagree with what Twilio was actually
configured to call (voice callbacks drop the port from the signed URL; SMS callbacks keep it; any
`user:pass@` in the URL is stripped before signing). A GET request signs the full URL with Twilio's
query params already appended — validating it the same way as a POST silently fails.

**Fix:** use Twilio's own SDK validator rather than reimplementing URL reconstruction — *"Twilio
recommends using the provided signature validation library from a Twilio SDK"* — and pass it the
exact external URL your Twilio phone number/app is configured to call, not `req.url`.

```ts
// GOOD — twilio's SDK does the URL + sorted-params reconstruction for you
import twilio from 'twilio';

app.post('/webhooks/twilio', express.urlencoded({ extended: false }), (req, res) => {
  const signature = req.headers['x-twilio-signature'] as string;
  const externalUrl = 'https://api.example.com/webhooks/twilio';   // exactly what Twilio calls — not req.url behind a proxy
  const valid = twilio.validateRequest(process.env.TWILIO_AUTH_TOKEN!, signature, externalUrl, req.body);
  if (!valid) return res.status(403).end();
  handleCallback(req.body);
});
```

JSON payloads carry an appended `bodySHA256` query parameter instead — validate those with the SDK's
JSON helper, not the standard param-sort path. No signed timestamp exists here either; TLS plus the
signature is the whole story, so treat replay defense as dedupe-by-id (§1) on Twilio's own message/
call SID.

**Detection:**

```bash
grep -rn "x-twilio-signature\|X-Twilio-Signature" --include='*.ts' --include='*.js' .
grep -rln "validateRequest\|RequestValidator" . || echo "no Twilio SDK validator found — check for a hand-rolled one"
grep -rn "req\.url\|req\.originalUrl" --include='*.ts' . | grep -i twilio   # proxy URL reconstruction hazard
```

## 8. Shopify, Linear, Vercel — Same Shape, Different Header

Three more senders that follow the raw-body HMAC pattern from §2–3 closely enough to cover together;
the finding to look for is the same non-constant-time comparison and raw-body ordering as everywhere
else, plus one vendor-specific trap each.

**Shopify** — `X-Shopify-Hmac-SHA256` (base64), HMAC-SHA256 over the raw request body, keyed with the
app's client secret. Shopify's docs state the ordering requirement directly: *"Always verify HMAC
before trusting payload contents"*, and the verification middleware must run **before** any
body-parsing middleware. No signed timestamp — dedupe on `X-Shopify-Webhook-Id` instead, and respond
within 5 seconds (1 second to connect) or the delivery is treated as failed and retried.

**Linear** — `Linear-Signature`, described as *"a hex-encoded HMAC-SHA256 signature of the raw body
contents, signed using the webhook's signing secret"*, alongside `Linear-Event`. Unlike the others in
this section, the timestamp isn't in a header — it's a `webhookTimestamp` (Unix ms) field **inside
the payload body**, and Linear's docs specify a **one-minute** window: verify *"it's within a minute
of the time your system sees it to guard against replay attacks."* Linear's own sample uses
`crypto.timingSafeEqual()` — a useful reference implementation to compare a hand-rolled one against.

**Vercel** — `x-vercel-signature`, HMAC-SHA1 hex over the raw body, keyed with the integration's
client secret. Flag this one specifically: Vercel's own published sample code compares the computed
digest with `===`, not a constant-time function — treat that as a documented anti-pattern to correct,
not a pattern to copy, the same way §1 requires everywhere else.

```ts
// GOOD — the shared pattern, applicable to Shopify and Linear alike (adjust header + encoding)
const digest = crypto.createHmac('sha256', secret).update(rawBody).digest();   // 'base64' for Shopify, hex for Linear
const provided = Buffer.from(req.headers['x-shopify-hmac-sha256'] as string, 'base64');
const ok = provided.length === digest.length && crypto.timingSafeEqual(provided, digest);
```

**Detection:**

```bash
grep -rn "x-shopify-hmac\|linear-signature\|x-vercel-signature" --include='*.ts' --include='*.js' -i .
grep -rn "x-vercel-signature" -A5 --include='*.ts' . | grep -E '===' # Vercel-sample-style unsafe compare
grep -rn "webhookTimestamp" --include='*.ts' .   # Linear's in-body timestamp actually checked?
```

## 9. Outbound Webhooks You Send — SSRF Hand-off

Everything above is about a webhook arriving at your app. The reverse case — your app lets a user
configure a URL that *you* POST events to (a customer-facing "notify my endpoint on X" feature) — is
not a signature-verification problem at all. It's your server making an outbound request to an
attacker-influenced destination: internal service discovery, cloud metadata endpoints, and
`localhost` are all reachable this way unless the fetcher is constrained. That failure mode, the
allowlist/DNS-resolution/redirect-handling fix, and the detection grep for it belong to
`secaudit:web-vulns` §2 (SSRF) — treat any "outgoing webhook" or "custom notification URL" feature
as triggering that skill, not this one.

## Webhook Verification Footgun Checklist

- A framework-wide JSON body-parser runs ahead of the webhook route — the signature no longer
  matches anything the sender actually sent.
- `===`/`==` comparing a signature instead of `crypto.timingSafeEqual` (or the language equivalent),
  or `timingSafeEqual` called without checking lengths first — it throws, it doesn't return `false`.
- A missing signature header treated as "nothing to verify" instead of an automatic rejection.
- The signing/verification secret unset in an environment and the handler quietly proceeds anyway.
- A `3xx` response anywhere on the route's path — every sender in this skill treats that as failure.
- Signed timestamp tolerance widened, zeroed, or removed to silence "expired" errors instead of
  fixing server clock drift.
- No idempotency on delivery/event id — a retried delivery re-runs a side effect a second time.
- A role name, user id, or permission flag taken straight from the payload body and used as an
  authorization decision, instead of looked up server-side by a stable id.
- A webhook URL with an embedded token (Slack Incoming Webhook, Discord channel webhook) logged,
  committed, or handed to client-side code.
- Twilio's signature validated against `req.url` behind a proxy instead of the exact configured
  external URL.
- Vercel's `===`-comparison sample code copied verbatim instead of swapped for constant-time compare.
- An "outgoing webhook" / "custom notification URL" feature reviewed under this skill instead of
  `secaudit:web-vulns` (SSRF) — it's an outbound request problem, not a verification problem.

## Cross-References

- `secaudit:payments` — Stripe webhook verification in full: replay tolerance, event-id idempotency,
  IP allowlisting, secret rotation during overlap, the 3xx failure mode this skill reuses by
  reference.
- `secaudit:revenuecat-security` — RevenueCat's webhook authenticity model, where both the HMAC
  signature and the Authorization header are opt-in rather than always-on.
- `secaudit:web-vulns` — SSRF for outbound webhooks/custom notification URLs (§9); this skill is
  inbound verification only.
- `secaudit:secrets` — treating a webhook signing secret or an embedded-token webhook URL as a
  credential: env-var hygiene and what to do once one leaks.
- `secaudit:rate-limiting` — a webhook endpoint is still a public POST route; cap retries/abuse the
  same as any other unauthenticated-until-verified surface.

## Sources

- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries -- `X-Hub-Signature-256`, HMAC-SHA256 hex, header absent when no secret configured, `secure_compare` guidance
- https://docs.slack.dev/authentication/verifying-requests-from-slack/ -- `X-Slack-Signature`/`X-Slack-Request-Timestamp`, `v0:` basestring, 5-minute tolerance, Bolt auto-verification
- https://docs.discord.com/developers/interactions/overview -- `X-Signature-Ed25519`/`X-Signature-Timestamp`, Ed25519 over timestamp+body, 401 on failure, PING/PONG, endpoint removal on repeated failure
- https://docs.svix.com/receiving/verifying-payloads/how-manual -- manual Svix verification: `svix-id`/`svix-timestamp`/`svix-signature`, `id.timestamp.body`, `v1,` prefix, `whsec_` secret
- https://docs.svix.com/receiving/verifying-payloads/how -- framework raw-body notes (Express, Next.js, NestJS, FastAPI, Django)
- https://docs.svix.com/receiving/verifying-payloads/why -- why raw-body and constant-time comparison matter
- https://www.standardwebhooks.com/ -- Standard Webhooks spec overview; Svix implements this spec
- https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md -- `webhook-id`/`webhook-timestamp`/`webhook-signature`, tolerance requirement, "a stray space" fragility quote
- https://clerk.com/docs/guides/development/webhooks/overview -- "Clerk uses Svix to send our webhooks", `verifyWebhook` helper
- https://resend.com/docs/webhooks/verify-webhooks-requests -- Resend's Svix-backed webhooks, raw-body requirement
- https://core.telegram.org/bots/api -- `setWebhook` `secret_token` parameter: optional, echoed via `X-Telegram-Bot-Api-Secret-Token`, shared secret not a signature
- https://www.twilio.com/docs/usage/webhooks/webhooks-security -- Twilio webhook security overview, SDK validator recommendation
- https://www.twilio.com/docs/usage/security -- full URL + sorted POST params + HMAC-SHA1 + base64 steps, GET vs POST, proxy URL reconstruction hazards
- https://shopify.dev/docs/apps/build/webhooks/verify-deliveries -- `X-Shopify-Hmac-SHA256`, verify-before-parsing, `X-Shopify-Webhook-Id` dedupe, 5s response window
- https://linear.app/developers/webhooks -- `Linear-Signature`/`Linear-Event`, in-body `webhookTimestamp`, 1-minute replay window, `crypto.timingSafeEqual()` sample
- https://vercel.com/docs/webhooks/webhooks-api -- `x-vercel-signature`, HMAC-SHA1 over raw body; sample compares with `===`
- https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b -- `timingSafeEqual` is constant-time; throws on unequal byte length
- https://docs.stripe.com/webhooks -- reused by reference in §1 for the 3xx-as-failure rule; full detail lives in `secaudit:payments`
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025, where per-sender signature verification (§2-8) lands
- https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/ -- A08:2025, where replay/idempotency and unverified-field trust (§1) land
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where outbound-webhook SSRF (§9) lands
