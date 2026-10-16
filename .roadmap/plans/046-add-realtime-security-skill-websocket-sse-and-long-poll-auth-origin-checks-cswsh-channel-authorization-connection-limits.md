---
id: 46
title: Add realtime-security skill: WebSocket, SSE and long-poll auth, Origin checks (CSWSH), channel authorization, connection limits
type: feature
version: 3.10.0
status: done
created: 2026-10-16
---

# Plan 46: Add realtime-security skill: WebSocket, SSE and long-poll auth, Origin checks (CSWSH), channel authorization, connection limits
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/realtime-security/` for long-lived connections: WebSocket (ws, Socket.IO, Hono `upgradeWebSocket`, Next.js custom servers), Server-Sent Events (Hono `streamSSE`, `EventSource`) and long-poll endpoints. Covers: Cross-Site WebSocket Hijacking (browsers send cookies on the upgrade; no CORS/SOP on WebSocket, so the server must allowlist `Origin`); authentication at handshake vs bearer tokens in the query string (`EventSource` cannot set headers, tokens leak to access logs/Referer; prefer a short-lived single-use ticket); connections outliving the session (re-check on revocation/logout, periodic re-auth, close on role change); per-subscription/channel authorization (subscribing to another tenant's channel id, room-join IDOR); per-message authorization and input validation on inbound frames; `Last-Event-ID` / long-poll cursor replay across tenants; resource limits (max payload, per-user/IP connection caps, idle timeouts, backpressure, heartbeat) and denial of service; proxies buffering SSE and sticky sessions; fan-out from a shared pub/sub (Postgres LISTEN/NOTIFY, Redis) filtering per subscriber.
- **Out of scope:** transport-level TLS/proxy config (stays in `deployment` / `proxy-trust`); Postgres LISTEN/NOTIFY internals (handed off to `postgres-security`).

## 🏗️ Architectural Blueprint
- **Files to create:** `skills/realtime-security/SKILL.md`
- **Files to modify:** `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator dispatches to it for projects using the covered technology.

## ✅ Acceptance
- **Passes when:** the skill fires on any WebSocket/SSE/long-poll endpoint and gives a concrete check + fix for each covered risk, with library API names (ws `verifyClient`/`handleUpgrade`, Socket.IO `allowRequest`/`cors`/`maxHttpBufferSize`, ws `maxPayload`, Hono `upgradeWebSocket`/`streamSSE`) exactly as their docs state.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default, version, advisory ID or provider capability is asserted that the vendor docs, RFC or OSV do not confirm; or the freshness check reports drift; or content duplicates a sibling skill instead of cross-referencing it.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Research primary sources (vendor docs, RFCs, OSV/GHSA) and write the skill; every API name, header, default and advisory ID verified live -> target: `skills/realtime-security/SKILL.md`
  > evidence: verifier PARTIAL→fixed: 12 advisories, RFC/WHATWG/OWASP/ws/Socket.IO/Hono/nginx facts confirmed; same-origin missing-Origin handling, async upgrade/message rejection crashes, int64 cursor regex (node-tested), ticket/Origin ordering, Redis pattern wording fixed; 649 lines (2026-10-16) (2026-10-16)
- [x] Step 2: Register the skill: audit tier + OWASP map, README table, plugin.json/marketplace.json description and keywords, cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
  > evidence: registered in audit Tier 2, OWASP map, README, plugin/marketplace keywords; SOURCES.md merged; check-freshness All current (2026-10-16) (2026-10-16)
- [x] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
  > evidence: registered in audit Tier 2, OWASP map, README, plugin/marketplace keywords; SOURCES.md merged; check-freshness All current (2026-10-16) (2026-10-16)
