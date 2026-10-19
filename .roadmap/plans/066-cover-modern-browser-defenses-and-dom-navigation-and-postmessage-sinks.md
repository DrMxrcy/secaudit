---
id: 66
title: Cover modern browser defenses and DOM navigation and postMessage sinks
type: feature
version: 3.12.0
status: done
created: 2026-10-17
---

# Plan 66: Cover modern browser defenses and DOM navigation and postMessage sinks
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** bring header/DOM guidance up to Google's current web-security guidance (https://github.com/GoogleChrome/modern-web-guidance-src/tree/main/guides/security — official Chrome DevRel, active 2026-10). Today deployment/SKILL.md:67 recommends allowlist `script-src 'self'`, which Google rates bypassable; zero hits for strict-dynamic, object-src, base-uri, Trusted Types, postMessage, window.open.
- **deployment (headers):**
  1. Strict CSP: per-request nonce (random bytes, base64) or hashes + `'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`, optional `form-action 'self'`; flag allowlist-only `script-src`, `'unsafe-inline'` without nonce, static/constant nonce, nonce from `crypto.randomUUID()` string reuse. Rollout order: report-only (`Content-Security-Policy-Report-Only` + `Reporting-Endpoints`/`report-to`) → enforce. Rank CSP + Trusted Types as highest leverage.
  2. Trusted Types: `require-trusted-types-for 'script'` + `trusted-types <names>`; flag pass-through policies `createHTML: (s) => s`.
  3. Fetch Metadata resource isolation: middleware rejecting cross-site non-navigation requests via `Sec-Fetch-Site`/`Sec-Fetch-Mode`, `Vary: Sec-Fetch-Site`.
  4. COOP `same-origin` (or `same-origin-allow-popups` when OAuth popups are used) on documents; CORP `same-origin` on authenticated JSON.
  5. SRI: external `<script src="https://…">` without `integrity` + `crossorigin`.
- **web-vulns (XSS/DOM):**
  6. postMessage: `addEventListener('message', …)` without exact `event.origin ===` check; `origin.includes/startsWith/indexOf` checks; `postMessage(data, '*')` carrying sensitive data.
  7. Navigation sinks: `location.href =`, `location.assign/replace`, `window.open`, `router.push/replace`, `<a href={…}>` with user-controlled URL → `javascript:` XSS / open redirect. **Triage rule:** a server-built same-origin path plus typed/enum or numeric segments is not exploitable (SAST tools report these as High); exploitable when any part of scheme/host/whole URL is user-controlled; fix = allowlist or `new URL(x, location.origin)` + origin/protocol check.
  8. Sanitizer API: `setHTMLUnsafe`/`parseHTMLUnsafe` are sinks; `setHTML` is safe; flag sanitize → serialize → reparse into `innerHTML` (mXSS).
- **Out of scope:** passkeys rpId, Local Network Access, Connection-Allowlist (parked as ideas).

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/deployment/SKILL.md (security headers section ~L60-90), skills/web-vulns/SKILL.md (XSS section ~L25-62: DOM sinks subsection), skills/cloudflare-workers-security/SKILL.md (check ~L214-218 consistency, pointer only), SOURCES.md (Google guide URLs, web.dev strict-csp, MDN Trusted Types / Sanitizer API / Fetch Metadata — verify each).

## ✅ Acceptance
- **Passes when:** deployment's example CSP is a strict nonce + strict-dynamic policy (with object-src/base-uri), the allowlist example is labelled bypassable, checks 1-8 each have a grep/config heuristic; navigation triage rule present; freshness clean.
- **Fails if:** Next.js-specific nonce wiring contradicts current Next docs (proxy.ts in 16), or Cloudflare skill now contradicts deployment.

## 🚶 Step-by-Step Checklist
- [x] Step 1: deployment: strict CSP, Trusted Types, Fetch Metadata, COOP/CORP, SRI, rollout order -> target: skills/deployment/SKILL.md
  > evidence: check-freshness.py: All current; strict CSP/Trusted Types/Fetch Metadata/COOP/Next 16 nonce wiring verified vs Google guide, MDN, nextjs.org; safeInternalUrl tested in node vs //, /\, /.//, javascript:, data:, lookalike hosts; built in worktree (sonnet); combined review PARTIAL -> parent fixed TT typed-param grep (BSD-tested), navigate() sink, PPR caveat, Cloudflare sample label (2026-10-19)
- [x] Step 2: web-vulns: postMessage, navigation sinks + triage rule, Sanitizer API -> target: skills/web-vulns/SKILL.md
  > evidence: check-freshness.py: All current; strict CSP/Trusted Types/Fetch Metadata/COOP/Next 16 nonce wiring verified vs Google guide, MDN, nextjs.org; safeInternalUrl tested in node vs //, /\, /.//, javascript:, data:, lookalike hosts; built in worktree (sonnet); combined review PARTIAL -> parent fixed TT typed-param grep (BSD-tested), navigate() sink, PPR caveat, Cloudflare sample label (2026-10-19)
- [x] Step 3: Cross-links + sources; freshness green -> target: skills/cloudflare-workers-security/SKILL.md, SOURCES.md
  > evidence: check-freshness.py: All current; strict CSP/Trusted Types/Fetch Metadata/COOP/Next 16 nonce wiring verified vs Google guide, MDN, nextjs.org; safeInternalUrl tested in node vs //, /\, /.//, javascript:, data:, lookalike hosts; built in worktree (sonnet); combined review PARTIAL -> parent fixed TT typed-param grep (BSD-tested), navigate() sink, PPR caveat, Cloudflare sample label (2026-10-19)
