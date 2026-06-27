# Vibe Security v3.1 — Comprehensive + Sourced — Design

**Date:** 2026-06-27
**Status:** Approved design, pending spec review
**Author:** DrMxrcy (with Claude)
**Builds on:** [v3.0 plugin restructure](2026-06-27-vibe-security-plugin-design.md)

## Summary

Make the v3.0 plugin **comprehensive and verifiable**: fact-check every existing skill, cite
real primary sources throughout, and add the coverage needed to span the full OWASP Top 10 (2021)
in addition to the OWASP LLM and Mobile lists already covered.

Minor, additive release: **v3.1.0**.

## Goals

1. **Verify** — fact-check all 14 existing skills against current primary sources; fix anything
   fabricated or outdated (the rejected `CVE-2025-66478` proved this is necessary).
2. **Source** — every skill cites the primary sources behind its claims; a central `SOURCES.md`
   indexes them; the 5 carried-over skills are independently verified and cited.
3. **Cover** — close the OWASP gaps so the plugin is genuinely comprehensive for vibe-coded apps.

## Non-goals

- No change to the v3.0 plugin packaging, naming, or dispatch architecture.
- No multi-platform variants; no upstream PRs; no agents/hooks/test-harness.
- Not chasing vulnerabilities irrelevant to the target audience (web + mobile apps built with
  Next.js / Supabase / Vercel / Expo / Convex and similar). Infra/container/GraphQL/WebSocket
  depth is out of scope for v3.1 (candidates for the Idea Incubator).

## OWASP Top 10 (2021) coverage target

| OWASP 2021 | After v3.1 | Skill |
|---|---|---|
| A01 Broken Access Control | covered | `database`, `auth`, `convex-security`, `web-vulns` (IDOR) |
| A02 Cryptographic Failures | covered NEW | `cryptography` |
| A03 Injection | covered | `data-access` (SQLi/ORM), `web-vulns` (XSS), `logging-monitoring` (command injection) |
| A04 Insecure Design | partial | `rate-limiting`, `payments` (business logic) — acceptable |
| A05 Security Misconfiguration | covered | `deployment`, `secrets` |
| A06 Vulnerable Components | covered | `framework-versions`, `supply-chain` |
| A07 Auth Failures | covered (expanded) | `auth` (+ cookies/CSRF/passkeys/session/enumeration) |
| A08 Data Integrity Failures | covered | `supply-chain`, `expo-security` (OTA signing), `logging-monitoring` (deserialization) |
| A09 Logging & Monitoring Failures | covered NEW | `logging-monitoring` |
| A10 SSRF | covered NEW | `web-vulns` |
| OWASP LLM Top 10 | covered | `ai-integration` |
| OWASP Mobile Top 10 | covered | `react-native-security`, `expo-security` |

## Workstream A — Verification pass

For each of the 14 existing skills, re-check factual claims (CVE IDs, version numbers, API key
formats, statistics, library behavior) against current primary sources. Fix errors inline and note
the source. Deliverable: corrected skills + a short verification log of what changed. This reuses
the parallel-research approach from v3.0 (one focused agent per skill or per cluster).

## Workstream B — Sourcing

- **Per-skill `## Sources` section.** Each skill ends with `## Sources` listing
  `- <primary URL> — what it backs`. Mirrors the existing `## References` convention. Prefer
  official docs, advisories (NVD/GitHub), OWASP, and primary research over blog aggregators.
- **Central `SOURCES.md`** at repo root: a grouped index of every cited source, so the whole
  plugin's evidence base is auditable in one place.
- **Verify + cite the 5 carried-over skills** (`auth`, `payments`, `rate-limiting`, `deployment`,
  `data-access`) against current docs (OWASP cheat sheets, Stripe docs, MDN, Zod) — they were
  migrated from the prior fork without fresh sourcing.

## Workstream C — Coverage additions

### NEW skill: `web-vulns`
- **XSS** — stored / reflected / DOM-based; framework escaping, raw-HTML render sinks
  (React/Vue), sanitization (DOMPurify), CSP as defense-in-depth.
- **SSRF** — user-supplied URLs, webhooks, image/link fetchers, PDF/screenshot generators; block
  private/link-local ranges (incl. cloud metadata `169.254.169.254`), allowlist hosts, HTTPS-only.
- **File upload + path traversal** — content-type/size validation, store outside webroot, generated
  filenames, reject `../` and absolute paths in any user-controlled path.
- **IDOR** — named treatment of object-level authorization; verify ownership on every
  object reference (cross-links `auth` and `database`).
- Sources: OWASP Cheat Sheets (XSS Prevention, SSRF Prevention, File Upload, IDOR), MDN, PortSwigger.

### NEW skill: `cryptography`
- Password storage (bcrypt / argon2 / scrypt; never md5/sha1/plaintext), per-user salts.
- Secure randomness (CSPRNG: `crypto.randomBytes` / `crypto.getRandomValues`, not weak PRNGs)
  for tokens, session IDs, reset links.
- Weak/legacy algorithms (DES, RC4, ECB mode), hardcoded keys/IVs.
- JWT algorithm confusion (`alg: none`, HS/RS confusion) — cross-links `auth`.
- Encryption-at-rest basics and key management hygiene.
- Sources: OWASP Password Storage / Cryptographic Storage Cheat Sheets, Node `crypto` docs.

### NEW skill: `logging-monitoring`
- Error responses leaking stack traces, env vars, internal paths (info disclosure).
- Secrets / PII in logs and crash reporters (cross-links `secrets`, `react-native-security`).
- Missing audit logging for security events (logins, permission changes, payments).
- **Insecure deserialization** (A08) and **command/code injection** (shell-exec and dynamic-eval
  primitives invoked with user input) (A03) folded in here.
- Sources: OWASP Logging / Error Handling Cheat Sheets, OWASP A09/A08 references.

### EXPAND `auth`
- Cookie security: `httpOnly`, `SameSite`, `Secure`, scoping.
- CSRF: tokens / double-submit; Server Actions and state-changing endpoints.
- Passkeys / WebAuthn as phishing-resistant auth.
- Session fixation (rotate session ID on login) and account enumeration (uniform responses,
  timing) on login / reset / register.

### Fold-ins
- **Clickjacking** -> `deployment` (X-Frame-Options / CSP `frame-ancestors`).
- Consolidate scattered **open-redirect** guidance with a clear cross-reference.

### Orchestrator update (`audit`)
- Add `web-vulns`, `cryptography`, `logging-monitoring` to the dispatch list.
- Include the OWASP Top 10 mapping so the sweep is provably complete.

## Skill conventions

Unchanged from v3.0 (flat frontmatter, `## When to Use`, before/after fixes, no em dashes in
README only). New skills follow the same internal shape; all skills gain `## Sources`.

## Result

17 skills total (orchestrator + 16 domains). OWASP Top 10 + LLM + Mobile covered. Every skill
cites primary sources; `SOURCES.md` indexes them.

## Versioning

`v3.1.0` — minor, additive. README skill list and version updated.

## Process note

Tracked via the roadmap as item #2 (target v3.1.0), built phase by phase like v3.0, continuing on
the `v3-plugin-restructure` branch (v3.0 is not yet released/merged).
