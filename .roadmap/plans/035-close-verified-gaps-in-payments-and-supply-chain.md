---
id: 35
title: Close verified gaps in payments and supply-chain
type: feature
version: 3.8.0
status: done
created: 2026-08-25
---

# Plan 35: Close verified gaps in payments and supply-chain
> Type: feature · Target: v3.8.0

## 🎯 Target Scope & Boundaries

Two gaps that earlier research surfaced and I dropped without tracking. Both re-verified today
against primary sources before writing.

### `payments` — the webhook handler is verified, then trusted forever

`payments` covers signature verification with the raw body, which is the big one. Read against
Stripe's own webhook documentation, four further controls that doc calls for are absent — grep
confirms zero hits for `tolerance`, `replay`, `idempot`, `duplicate`, `allowlist`, and `roll`:

1. **Replay.** A valid payload plus its signature can be re-sent. Stripe signs a timestamp into
   `Stripe-Signature` precisely so you can reject stale ones, and the docs are explicit:
   *"Don't use a tolerance value of 0. Using a tolerance value of 0 disables the recency check
   entirely."* A handler that verifies the signature and ignores the timestamp accepts replays.
2. **Duplicates.** *"Webhook endpoints might occasionally receive the same event more than
   once"*, and Stripe retries for up to three days. Without idempotency on `event.id`, a retried
   `invoice.paid` grants the entitlement twice.
3. **Sender verification is two controls, not one.** The docs list IP allowlisting *and*
   signature verification together, not as alternatives.
4. **Secret rotation.** Signing secrets should be rolled periodically; during a roll an endpoint
   has multiple active secrets and Stripe signs once per secret, so a handler that assumes a
   single secret breaks or fails open during rotation.

Also worth one line: Stripe treats a `3xx` response to a webhook as a **failure**, so an endpoint
behind a redirect silently never receives events — a availability failure that looks like "no
payments happening".

### `supply-chain` — `lockfile-lint` is recommended without its most important flag

The skill runs `lockfile-lint --path package-lock.json --type npm --allowed-hosts npm`. Verified
by running `npx lockfile-lint --help` today, there is also:

    -s, --validate-https    validates the use of HTTPS as protocol

Without it, a lockfile entry pointing at an `http://` or `git://` resolved URL passes. That is
the exact substitution the lockfile is supposed to prevent.

### Deliberately excluded

Earlier research also suggested documenting Stripe's `constructEventAsync` for edge/Workers
runtimes. **Stripe's webhook documentation does not mention it**, and I could not verify it from
a primary source, so it is omitted rather than asserted — the same rule applied to the LLM Top 10
numbering and the ChainDrop provenance claim.

## 🏗️ Architectural Blueprint

- **Modified:** `skills/payments/SKILL.md` — extend `Webhook Signature Verification` with replay
  tolerance, idempotency, IP allowlisting, secret rotation, and the 3xx note.
- **Modified:** `skills/supply-chain/SKILL.md` — add `--validate-https` to the recommended
  invocation and say what it catches.
- **Modified:** `SOURCES.md`.

## ✅ Acceptance

- Every added claim traces to a primary source checked today.
- Nothing is asserted about `constructEventAsync`.
- `python3 scripts/check-freshness.py` exits 0.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Extend the payments webhook section with the four controls plus the 3xx note
  -> target: `skills/payments/SKILL.md`
- [x] Step 2: Add `--validate-https` to the lockfile-lint invocation -> target:
  `skills/supply-chain/SKILL.md`
- [x] Step 3: Add sources and verify the freshness check stays green -> target: `SOURCES.md`
