---
id: 49
title: Extend auth with multi-host sessions, cross-host handoff tokens and custom-domain verification
type: feature
version: 3.10.0
status: active
created: 2026-10-16
---

# Plan 49: Extend auth with multi-host sessions, cross-host handoff tokens and custom-domain verification
> Type: feature · Target: v3.10.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `auth` section(s) for apps that serve several hosts (portal, per-community subdomains, customer custom domains): host-only cookies (`__Host-` prefix, no `Domain=`), why a parent-domain cookie lets any subdomain read/plant sessions (cookie tossing); single-use cross-host handoff tokens (high entropy, hashed at rest, atomic consume e.g. `DELETE ... RETURNING`, TTL in seconds, bound to user + target host, delivered by POST or URL fragment rather than query string because of Referer/logs, return-URL allowlist against verified hosts, replay and fixation); logout and revocation propagating across hosts; custom-domain verification (random per-domain TXT token, re-verification, removing domains on delete to avoid dangling-CNAME takeover, worker HTTP checks as an SSRF/DNS-rebinding surface handed off to `web-vulns`); opaque session tokens stored as hashes.
- **Out of scope:** OAuth provider flow details (in `oauth-oidc-security`); proxy Host-header trust (in `proxy-trust`, cross-referenced).

## 🏗️ Architectural Blueprint
- **Files to create:** none
- **Files to modify:** `skills/auth/SKILL.md`, `skills/audit/SKILL.md` (tier + OWASP map), `README.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `SOURCES.md`
- **Schema/interface changes:** none (Markdown skill content only).
- **Downstream impact:** the `audit` orchestrator dispatches to it for projects using the covered technology.

## ✅ Acceptance
- **Passes when:** an auditor can review a multi-host login handoff and custom-domain onboarding using only this section and finds a concrete check + fix for each risk listed, with cookie-attribute behaviour quoted from RFC 6265bis/MDN.
- **Passes when:** `python3 scripts/check-freshness.py` is all-current.
- **Fails if:** an API name, default, version, advisory ID or provider capability is asserted that the vendor docs, RFC or OSV do not confirm; or the freshness check reports drift; or content duplicates a sibling skill instead of cross-referencing it.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Research primary sources and write the new section(s); every API name, parameter, default and advisory ID verified live -> target: `skills/auth/SKILL.md`
  > evidence: verifier PARTIAL→fixed: RFC 6265bis/9700/9110, OWASP, Postgres, Microsoft, Cloudflare, Caddy quotes verified; open-redirect in resolveTarget sample, timingSafeEqual length throw, premature nonce-cookie delete fixed; return-URL check node-tested (//evil.net rejected) (2026-10-16) (2026-10-16)
- [ ] Step 2: Update the skill description/frontmatter, audit dispatch notes, README and plugin.json keywords; cross-references from sibling skills -> target: `skills/audit/SKILL.md`, `README.md`, `.claude-plugin/plugin.json`
- [ ] Step 3: Add cited sources and confirm `python3 scripts/check-freshness.py` is all-current -> target: `SOURCES.md`
