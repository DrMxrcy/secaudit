---
id: 45
title: Generalize payments webhook section into webhook-security: Discord Ed25519, Slack, GitHub, Svix, Telegram verification and replay
type: feature
version: 3.9.0
status: planned
created: 2026-09-15
---

# Plan 45: Generalize payments webhook section into webhook-security: Discord Ed25519, Slack, GitHub, Svix, Telegram verification and replay
> Type: feature · Target: v3.9.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/webhook-security/` generalising inbound-webhook verification beyond Stripe: per-sender verification recipes — GitHub (`X-Hub-Signature-256` HMAC-SHA256), Slack (`X-Slack-Signature` v0 + `X-Slack-Request-Timestamp`, 5-min window), Discord interactions (Ed25519 over timestamp+body, `X-Signature-Ed25519`), Svix-style (`svix-id/timestamp/signature`, used by Clerk, Resend and others), Telegram (`X-Telegram-Bot-Api-Secret-Token`), Twilio (`X-Twilio-Signature` over full URL + params), generic shared-secret-in-URL anti-patterns; cross-cutting rules — raw body before JSON parsing, constant-time compare, timestamp tolerance and replay/idempotency on event id, fail-closed when the secret is unset, no 3xx, don't act on unverified payload fields (role names, user ids), webhook URLs are secrets, outbound webhook SSRF hand-off to `web-vulns`.
- **Out of scope:** Stripe and RevenueCat details (stay in `payments` / `revenuecat-security`; this skill cross-refs them).

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/webhook-security/SKILL.md`.
- **Files to modify:** `skills/audit/SKILL.md` (Tier 2), `skills/payments/SKILL.md` (cross-ref from the webhook section), `README.md`, `.claude-plugin/plugin.json`, `SOURCES.md`.

## ✅ Acceptance
- **Passes when:** the skill fires on any route receiving a third-party webhook and gives a verified recipe (header names and algorithm exactly as the sender's docs state) for GitHub, Slack, Discord, Svix, Telegram and Twilio, plus the cross-cutting rules.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** a version, advisory ID or provider capability is asserted that OSV or the provider's docs do not confirm; or the freshness check reports drift.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Write the skill, verifying every advisory ID, fixed version and provider claim against OSV / live docs -> target: `skills/webhook-security/SKILL.md`
- [ ] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json description/keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
