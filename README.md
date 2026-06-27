# Vibe Security v3.0 - Installable Claude Code Plugin

> Fork of [fartiacht/vibe-security-skill](https://github.com/fartiacht/vibe-security-skill), itself a fork of the original by [Chris Raroque](https://github.com/raroque). v3.0 restructures the project into an installable Claude Code plugin with focused per-domain skills.

A security plugin that audits "vibe-coded" apps (projects built rapidly with AI assistance) for the vulnerabilities AI coding assistants consistently introduce: exposed secrets, broken database access control, missing auth, client-side trust, insecure payments, dependency supply-chain risks, and mobile/backend platform issues.

## What changed in v3.0

v2.0 was a single monolithic skill. v3.0 is a proper plugin: **one orchestrator skill plus 13 focused domain skills**, each with a precise trigger so the right one fires on its own during targeted work and code generation, while the orchestrator still runs the full sweep.

- **Installable as a plugin** via `/plugin marketplace add` (no more copying a folder).
- **Focused skills** that trigger independently: ask "check my Supabase RLS" and only the database skill loads.
- **New dedicated coverage** for Convex, Expo/EAS, and React Native security.
- **Research-verified content** (mid-2026): corrected CVE references, the new Supabase publishable/secret key model, current slopsquatting data, and the OWASP LLM Top 10 / MCP threat model.

> **Breaking change:** the old top-level `vibe-security/` skill folder is gone. If you installed v2.0 by copying that folder, re-install as a plugin (below). Skills are now namespaced as `vibe-security:<name>`.

## Installing

In Claude Code:

```
/plugin marketplace add DrMxrcy/vibe-security-skill
/plugin install vibe-security@vibe-security
```

That registers the marketplace from this repo and installs the plugin. All skills auto-load.

## Using it

Ask naturally and the right skill fires:

- "audit my app for security" or "is this safe?" runs the full sweep (`vibe-security:audit`).
- "check my Supabase RLS" loads only `vibe-security:database`.
- "is my Convex backend secure?" loads only `vibe-security:convex-security`.

The orchestrator skips areas whose technology you do not use. If you have no Stripe, it skips payments; no Firebase, it skips Firebase rules.

## Skills

| Skill | Covers |
|-------|--------|
| `vibe-security:audit` | Orchestrator: runs the full security sweep and dispatches to the domain skills |
| `vibe-security:framework-versions` | Known-vulnerable framework versions and critical CVEs (Next.js, React, and more) |
| `vibe-security:secrets` | Hardcoded keys, client-exposed env prefixes, default credentials, `.gitignore` hygiene |
| `vibe-security:database` | Supabase RLS, Firebase Security Rules, storage policies, Edge Functions, the new key model |
| `vibe-security:convex-security` | Convex: public vs internal functions, validators, auth in handlers, file-storage access |
| `vibe-security:auth` | JWT verification, why middleware is not a security boundary, Server Actions, sessions |
| `vibe-security:rate-limiting` | Where limits are required, tamper-proof counters, billing and spend caps |
| `vibe-security:payments` | Client-side price manipulation, webhook signature verification, subscription validation |
| `vibe-security:supply-chain` | Slopsquatting / hallucinated packages, lock-file hygiene, weak default secrets |
| `vibe-security:react-native-security` | RN core: secure storage, deep links, WebView, native bridge, network/ATS, PKCE |
| `vibe-security:expo-security` | Expo/EAS: `EXPO_PUBLIC_` inlining, EAS secrets, secure-store, OTA code signing, config plugins |
| `vibe-security:ai-integration` | AI key exposure, usage caps, prompt injection, MCP threat model, output sanitization |
| `vibe-security:deployment` | Production config, security headers, source maps, preview-deployment isolation |
| `vibe-security:data-access` | SQL injection, ORM operator injection, runtime input validation, mass assignment |

## Why a security plugin for AI-generated code

AI assistants reliably get a recurring set of security patterns wrong, which leads to real breaches: stolen API keys, drained billing accounts, and fully exposed databases. The core principle running through every skill: **never trust the client.** Every price, user ID, role, subscription status, and rate-limit counter must be validated or enforced server-side.

The content is based on published research, official security advisories, and documented real-world breaches. If you spot gaps, outdated patterns, or mistakes, please open an issue or PR.

## Credits

- Original skill by [Chris Raroque](https://github.com/raroque) and the team at [Aloa](https://aloa.co).
- v2.0 content updates by the [fartiacht](https://github.com/fartiacht) fork.
- Research sources include the Supabase Security Retro 2025, Next.js and React security advisories, the OWASP Top 10 for LLM Applications (2025), the MCP security best-practices guidance, and the USENIX 2025 study on package hallucinations.

## License

MIT, same as the original.
