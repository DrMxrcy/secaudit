# Vibe Security Plugin (v3.0) — Design

**Date:** 2026-06-27
**Status:** Approved design, pending spec review
**Author:** DrMxrcy (with Claude)

## Summary

Fork and restructure the current single `vibe-security` skill into an installable
Claude Code **plugin** composed of one orchestrator skill plus focused per-domain
skills. Deepen the security content using verified, current (2025-2026) sources.

This is a structural major version: **v3.0**.

## Goals

1. **Installable plugin** — package as a proper Claude Code plugin (`plugin.json` +
   `marketplace.json`) so it installs via `/plugin marketplace add`, not by copying a folder.
2. **Split into focused skills** — break the monolithic skill into one orchestrator
   plus 13 domain skills, each with a precise, non-overlapping trigger.
3. **Deepen content quality** — refresh CVEs and best practices against verified sources;
   add dedicated Expo, React Native, and Convex security coverage.

## Non-goals (explicitly out of scope for v3.0)

- **No upstream contributions.** Expo/RN/Convex skills live in *our* plugin only — no PRs to
  `expo/skills` or `get-convex/convex-agent-plugins`.
- **No multi-platform variants.** Claude Code only. No `.codex-plugin` / `.cursor-plugin`.
- **No extra infra.** No sub-agents, hooks, or test harness in v3.0 (can be a later version).

## Platform

Claude Code only.

## Repo layout

Single-plugin, root-level layout (not the nested `plugins/<name>/` multi-plugin marketplace
layout that Expo uses):

```
.claude-plugin/
  plugin.json          # manifest: name "vibe-security", version "3.0.0"
  marketplace.json     # makes it installable via /plugin marketplace add DrMxrcy/<repo>
skills/
  audit/SKILL.md                    # orchestrator — the full sweep
  framework-versions/SKILL.md
  secrets/SKILL.md
  database/SKILL.md
  convex-security/SKILL.md          # NEW
  auth/SKILL.md
  rate-limiting/SKILL.md
  payments/SKILL.md
  supply-chain/SKILL.md
  react-native-security/SKILL.md    # refocused from old `mobile`
  expo-security/SKILL.md            # NEW
  ai-integration/SKILL.md
  deployment/SKILL.md
  data-access/SKILL.md
README.md
CONTRIBUTING.md
LICENSE
```

The current top-level `vibe-security/` folder is **retired**. Its `SKILL.md` becomes
`skills/audit/SKILL.md`; each `references/*.md` migrates into the matching domain skill.
Clean break — no backward-compat shim for the old folder path.

## Skill inventory (14 skills)

Each domain skill is self-contained: it owns its detection patterns and before/after fixes,
and carries a precise `description` (the trigger surface). Sharp boundaries prevent the
fine-grained skills from fighting over the same context.

| Skill | Trigger scope | Source / change |
|---|---|---|
| `audit` | "audit my app", "is this secure", full security review | orchestrator; from old `SKILL.md` |
| `framework-versions` | known-vulnerable framework versions / CVE checks in `package.json`, lockfiles | from `framework-versions.md` + verified CVEs |
| `secrets` | API keys, tokens, `.env`, client-exposed env prefixes, default creds | from `secrets-and-env.md` |
| `database` | Supabase RLS, Firebase rules, SQL injection, ORM misuse | from `database-security.md` minus Convex |
| `convex-security` | `convex/` functions & schema: public vs internal fns, arg validators, auth in handlers | **NEW** |
| `auth` | authentication, authorization, sessions, JWT, middleware-as-boundary | from `authentication.md` |
| `rate-limiting` | abuse prevention, request throttling, counter tampering | from `rate-limiting.md` |
| `payments` | Stripe, webhooks, client-side price manipulation, subscription status | from `payments.md` |
| `supply-chain` | phantom/hallucinated deps, slopsquatting, unpinned versions, lockfile hygiene | from `supply-chain.md` |
| `react-native-security` | RN core: secure storage, deep links, native bridge, WebView, network/ATS | refocused from `mobile.md` |
| `expo-security` | Expo/EAS: `EXPO_PUBLIC_` inlining, EAS secrets, expo-secure-store, OTA code signing, config plugins | **NEW** |
| `ai-integration` | LLM key exposure, usage caps, prompt injection, MCP security, output sanitization | from `ai-integration.md` |
| `deployment` | security headers, source maps, preview isolation, env separation | from `deployment.md` |
| `data-access` | input validation/sanitization (non-DB), general injection | from `data-access.md` |

### Trigger boundary rules (to avoid collisions)

- `auth` = authentication/authorization logic itself. `rate-limiting` = throttling/abuse, even on
  auth endpoints. They reference each other but do not overlap.
- `database` = Supabase/Firebase/SQL/ORM. `convex-security` = anything in `convex/` (Convex has
  no RLS; access control lives in function bodies — a fundamentally different model).
- `react-native-security` = framework-agnostic RN. `expo-security` = anything touching the
  Expo/EAS toolchain (`EXPO_PUBLIC_`, `eas.json`, `app.config.*`, `expo-updates`, config plugins).
- `secrets` = key/env handling generally. `framework-versions` = vulnerable *versions*.
  `supply-chain` = phantom/untrusted *packages*.

## Orchestrator dispatch model (single source of truth)

To avoid duplicating content between the orchestrator and the 13 domain skills:

- **`audit` owns the cross-cutting layer**: the "never trust the client" core principle, the
  ordered audit process, the severity model (Critical → High → Medium → Low), the output format,
  and the tooling / next-steps recommendations.
- **Domain skills own the detection patterns** (the actual "look for X, here's the fix").
- On "audit my app", `audit` walks the audit areas and, for each technology actually present in
  the codebase, invokes the matching `vibe-security:<domain>` skill for depth — skipping areas
  whose tech isn't present.

Each piece of knowledge lives in exactly one place. Tradeoff accepted: a full audit invokes
several skills sequentially (more tool calls) rather than one fat skill — worth it for
maintainability and for letting domain skills fire independently during targeted work and
proactive code generation.

## Content deepening (research-verified, 2025-2026)

All facts below were verified against primary sources during design research.

### framework-versions
- **Correct the cited CVE.** `CVE-2025-66478` is a **REJECTED duplicate**; the canonical active
  CVE is **`CVE-2025-55182`** (React2Shell, CVSS 10.0, pre-auth RCE in React Server Components,
  in CISA KEV). Fix branch for 15.1.x is **15.1.9** (also 15.0.5 / 15.2.6 / 15.3.6 / 15.4.8 /
  15.5.7 / 16.0.7). Note the rejected ID so a scanner isn't confused.
- **Add `CVE-2025-29927`** (Next.js middleware authorization bypass via `x-middleware-subrequest`,
  CVSS 9.1; fixed 14.2.25 / 15.2.3). Cross-link to `auth` (middleware is not a security boundary).
- **Add** `CVE-2025-49826` (Next.js 15.1.x cache-poisoning DoS, fixed 15.1.8), plus verified
  Express (`CVE-2024-29041`), path-to-regexp ReDoS (`CVE-2024-52798`), and Astro source-map
  exposure (`CVE-2024-56159`) as representative ecosystem examples.
- Frame the CVE list as "verify against the live advisory DB" rather than a frozen list.

### secrets / database
- **Supabase's new API key model.** Document publishable keys (`sb_publishable_...`, RLS-governed,
  client-safe) vs secret keys (`sb_secret_...`, `BYPASSRLS`, server-only). Legacy `anon`/`service_role`
  deprecated by end of 2026; new projects after 2025-11-01 don't get them. Supabase now rejects
  secret keys sent from a browser UA and auto-revokes secret keys found in public GitHub repos —
  but neither stops a leaked key used via curl. The danger framing stays: a secret/`service_role`
  key in a client bundle = full DB compromise.

### convex-security (NEW) — from official docs + Convex Stack blog
- Convex has **no row-level security**; every `query`/`mutation`/`action` is a public HTTP endpoint.
- Findings: public vs `internal*` functions; missing `v.*` arg validators / `v.any()` on public
  fns; missing `ctx.auth.getUserIdentity()` checks; **identity taken from `args` instead of `ctx.auth`**
  (the #1 vibe-coding bug — impersonation); scheduled/cron jobs referencing `api.*` instead of
  `internal.*`; `httpAction` without signature/auth verification or with `Access-Control-Allow-Origin: *`;
  unauthenticated file-storage URLs treated as private; unindexed `.filter()` table scans.
- Remediation: `convex-helpers` `customFunctions` for auth-by-construction, RLS helpers as last line
  of defense, `@convex-dev/eslint-plugin` rules (`require-argument-validators`, `no-filter-in-query`).

### expo-security (NEW) — from official Expo/EAS docs
- `EXPO_PUBLIC_*` is statically inlined into the bundle — never holds secrets.
- EAS "Secret" visibility protects dashboard/log access only, **not** the shipped app; secrets the
  running app needs must live behind a backend.
- `expo-secure-store` (Keychain/Keystore) vs AsyncStorage (plaintext) for tokens.
- EAS Update / OTA **code signing** (`expo-updates codesigning`, `--private-key-path`) to prevent
  malicious OTA injection.
- `app.json`/`app.config.js` `extra` exposure via `expo-constants`; config plugins run arbitrary
  code at prebuild (supply-chain risk); deep link validation in Expo Router; backend-proxy via
  `+api.ts` API routes.

### react-native-security (refocused) — from RN docs + OWASP MASVS / Mobile Top 10
- Secrets in the JS bundle (extractable; Hermes is not a boundary) → backend proxy.
- `react-native-keychain` vs AsyncStorage; MMKV needs an `encryptionKey`.
- Logging/crash-reporter leakage; deep link / custom-scheme hijack + Universal Links / App Links;
  OAuth PKCE via `react-native-app-auth`; network security (ATS, `usesCleartextTraffic`, SSL pinning);
  **WebView** (`onMessage`, `injectedJavaScript`, `originWhitelist`, file access); native bridge trust;
  jailbreak/root detection as defense-in-depth only.

### ai-integration — from OWASP LLM Top 10 (2025) + MCP security guidance
- LLM key exposure → backend proxy; **unbounded consumption** (LLM10) → rate limits + spend caps.
- Prompt injection (LLM01): direct, indirect (poisoned fetched content), and agentic/tool-based.
- **MCP risks**: tool poisoning/shadowing, over-permissioned/omnibus scopes, confused-deputy, token
  passthrough (forbidden), SSRF via OAuth metadata URLs, session hijacking, local-server RCE.
  Treat all model output as untrusted before it triggers an action; human-in-the-loop for high-risk ops.

### supply-chain — from USENIX 2025 "We Have a Package for You" + Snyk/Socket
- Slopsquatting: ~19.7% of AI-generated code referenced non-existent packages; 43% of hallucinated
  names recur across runs (predictable, pre-registrable). Real incident: hallucinated `huggingface-cli`
  drew 30k+ downloads.
- Detection: verify every AI-suggested package exists and is legitimate before install; pin + commit
  lockfiles; `npm ci` / `--frozen-lockfile`; scan with `npm audit`, Socket.dev, Snyk.

## Skill authoring conventions (adopted from Expo + Convex)

Verified by reading the actual `SKILL.md` files in `expo/skills` and
`get-convex/convex-agent-plugins`. We mirror their conventions so our plugin reads like a
first-class one:

- **Flat frontmatter** (Expo style), not a nested `metadata:` block:
  `name`, `description`, `version`, `license`. Author credit moves into the body or a flat
  `author` field. (The current skill's `metadata: { author, version, updated }` block is replaced.)
- **Trigger-rich `description`** (Expo style): multiple sentences packed with concrete scenarios
  and verbs ("Use whenever the user is …, running …, shipping …"). This is the primary lever for
  the right skill firing, and matters more with fine-grained skills. The current monolithic skill
  already writes descriptions this way — we keep that quality per domain skill.
- **`## When to Use`** bullet list near the top of every skill (both repos do this consistently).
  For our fine-grained split, this is where we draw the sharp inter-skill boundaries in prose,
  reinforcing the `description`.
- **`## References`** section (Expo style) pointing at relative `./references/*.md` with a short
  `--` description each — only for skills whose content is large enough to warrant a subfolder
  (candidates: `database`, `react-native-security`, `ai-integration`, `audit`). Smaller skills stay
  single-file like most Convex skills.
- **Inline before/after code with file-path comments** (Convex style: `// convex/schema.ts`),
  and explicit validators/`returns:` where relevant in the Convex skill.

## Internal structure of each domain skill

Within the conventions above, each domain skill's body follows a consistent shape:

1. **When to Use** — scenario bullets (boundary-setting).
2. **What to look for** — concrete code patterns / grep heuristics.
3. **Why it's exploitable** — concrete attacker impact, not abstract risk.
4. **Fix** — before/after code with file-path comments.
5. **Tooling** — automated checks specific to this domain.

Voice matches the existing skill; **no em dashes** (per repo convention).

## Migration plan (high level)

1. Scaffold `.claude-plugin/plugin.json` + `marketplace.json`.
2. Create `skills/audit/` from the current `SKILL.md`, trimmed to the cross-cutting layer +
   dispatch instructions.
3. Migrate each `references/*.md` into its domain `skills/<name>/SKILL.md`, writing a precise
   `description` for each.
4. Carve `convex-security` out of `database`; split `mobile` into `react-native-security` +
   `expo-security`.
5. Apply research-verified content updates.
6. Delete the old `vibe-security/` folder.
7. Update `README.md` (plugin install + skill list) and bump to v3.0.0.

## Versioning

`v3.0.0` — major, structural fork. README documents plugin install and the full skill list.

## Process note

The repo's `CLAUDE.md` mandates roadmap tracking (`/roadmap:*`) for new work, and the roadmap is
not yet initialized here. Per that instruction (which takes precedence over the default
writing-plans flow), implementation will be routed through `/roadmap:init` + `/roadmap:plan`
rather than superpowers writing-plans. Confirm at the transition point.
