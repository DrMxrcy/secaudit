---
id: 4
title: Dynamic verification against the running app
type: feature
version: 3.2.0
status: planned
created: 2026-07-17
---

# Plan 4: Dynamic verification against the running app
> Type: feature · Target: v3.2.0

## 🎯 Target Scope & Boundaries
- **Core objective:** A new optional domain skill, `secaudit:dynamic-verification`, that — when
  a running instance of the target app is available and the user has authorized active testing —
  uses the Playwright MCP to *confirm or refute* a defined set of findings and to catch
  runtime-only issues that static reading cannot see. Output upgrades a static "suspected"
  finding to **Confirmed** (with reproduction evidence) or drops it, cutting false positives and
  the token burn spent reasoning about whether a suspected issue is real.
- **Probe set (read-only by default):** live security headers (CSP/HSTS/X-Frame-Options),
  CORS reflection, routes that respond without authentication, IDOR (request another user's
  object id and observe access), and reflected XSS (payload echoed unescaped). Each probe maps
  back to an existing static domain (deployment, web-vulns, auth).
- **Out of scope / hard guardrails:** No destructive actions (no create/update/delete probes by
  default), no load/DoS testing, no automated exploit-chain generation. The skill **must** open
  with an authorization gate: confirm the target is the user's own app, in a non-production or
  consented environment, before any request. Authenticated/multi-tenant IDOR testing is
  documented as a guided manual setup, not fully automated.

## 🏗️ Architectural Blueprint
- **Files to create:**
  - `skills/dynamic-verification/SKILL.md` — new skill (auto-loads; skills are directory-based,
    no manifest edit needed). Authorization gate, when-to-use, Playwright MCP driving, and the
    Confirmed/Refuted verdict format.
  - `skills/dynamic-verification/references/probes.md` — concrete Playwright recipes per probe
    (headers, CORS, unauth route, IDOR, reflected XSS), each citing the matching OWASP WSTG test.
- **Files to modify:**
  - `skills/audit/SKILL.md` — add an optional final "Dynamic verification" phase, gated on a
    running app URL + authorization; teach the output format to label findings
    Confirmed vs Suspected.
  - `README.md` — add the skill to the Skills table.
  - `SOURCES.md` — add OWASP Web Security Testing Guide (WSTG) references.
- **Schema/interface changes:** Output format gains a Confirmed/Suspected label on findings.
- **Downstream impact:** Orchestrator output; no change to the static domain skills themselves.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Write `dynamic-verification/SKILL.md` — authorization gate first, when-to-use,
  Playwright MCP usage, Confirmed/Refuted verdict format -> target: `skills/dynamic-verification/SKILL.md`
- [ ] Step 2: Write `references/probes.md` — Playwright recipes for headers, CORS, unauth
  routes, IDOR, reflected XSS, each mapped to an OWASP WSTG test id -> target: `skills/dynamic-verification/references/probes.md`
- [ ] Step 3: Wire the optional Dynamic verification phase into the orchestrator and add the
  Confirmed/Suspected label to the output format -> target: `skills/audit/SKILL.md`
- [ ] Step 4: Add the skill to the README Skills table and WSTG to `SOURCES.md` -> target: `README.md`, `SOURCES.md`
- [ ] Step 5: Verify the skill loads as `secaudit:dynamic-verification` and the authorization
  gate is the first thing it does -> target: manual verification
