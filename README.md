# Secaudit v3.1 - Installable Claude Code Plugin

> Fork of [fartiacht/vibe-security-skill](https://github.com/fartiacht/vibe-security-skill), itself a fork of the original by [Chris Raroque](https://github.com/raroque). v3.x restructures the project into an installable Claude Code plugin with focused, fully-sourced per-domain skills.

A security plugin that audits "vibe-coded" apps (projects built rapidly with AI assistance) for the vulnerabilities AI coding assistants consistently introduce: exposed secrets, broken database access control, missing auth, client-side trust, insecure payments, dependency supply-chain risks, web vulnerabilities, cryptographic failures, and mobile/backend platform issues.

## What changed

v2.0 was a single monolithic skill. v3.x is a proper plugin: **one orchestrator skill plus 16 focused domain skills**, each with a precise trigger so the right one fires on its own during targeted work and code generation, while the orchestrator still runs the full sweep.

- **Installable as a plugin** via `/plugin marketplace add` (no more copying a folder).
- **Focused skills** that trigger independently: ask "check my Supabase RLS" and only the database skill loads.
- **Comprehensive coverage**: the full OWASP Top 10 (2021), plus the OWASP LLM and Mobile Top 10s. Dedicated skills for Convex, Expo/EAS, and React Native.
- **Every claim is sourced.** Each skill cites primary sources (official docs, NVD/GitHub advisories, OWASP); see [`SOURCES.md`](SOURCES.md). Content was research-verified in mid-2026 (which caught and corrected a rejected CVE reference).

> **Breaking change:** the old top-level `vibe-security/` skill folder is gone. If you installed v2.0 by copying that folder, re-install as a plugin (below). Skills are now namespaced as `secaudit:<name>`.

## Installing

In Claude Code:

```
/plugin marketplace add DrMxrcy/secaudit
/plugin install secaudit@secaudit
```

That registers the marketplace from this repo and installs the plugin. All skills auto-load.

## Using it

Ask naturally and the right skill fires:

- "audit my app for security" or "is this safe?" runs the full sweep (`secaudit:audit`).
- "check my Supabase RLS" loads only `secaudit:database`.
- "is my Convex backend secure?" loads only `secaudit:convex-security`.

The orchestrator skips areas whose technology you do not use. If you have no Stripe, it skips payments; no Firebase, it skips Firebase rules.

## Skills

| Skill | Covers |
|-------|--------|
| `secaudit:audit` | Orchestrator: runs the full security sweep and dispatches to the domain skills |
| `secaudit:framework-versions` | Known-vulnerable framework versions and critical CVEs (Next.js, React, and more) |
| `secaudit:secrets` | Hardcoded keys, client-exposed env prefixes, default credentials, `.gitignore` hygiene |
| `secaudit:database` | Supabase RLS, Firebase Security Rules, storage policies, Edge Functions, the new key model |
| `secaudit:convex-security` | Convex: public vs internal functions, validators, auth in handlers, file-storage access |
| `secaudit:auth` | JWT verification, why middleware is not a security boundary, Server Actions, sessions |
| `secaudit:rate-limiting` | Where limits are required, tamper-proof counters, billing and spend caps |
| `secaudit:payments` | Client-side price manipulation, webhook signature verification, subscription validation |
| `secaudit:supply-chain` | Slopsquatting / hallucinated packages, lock-file hygiene, weak default secrets |
| `secaudit:react-native-security` | RN core: secure storage, deep links, WebView, native bridge, network/ATS, PKCE |
| `secaudit:expo-security` | Expo/EAS: `EXPO_PUBLIC_` inlining, EAS secrets, secure-store, OTA code signing, config plugins |
| `secaudit:ai-integration` | AI key exposure, usage caps, prompt injection, MCP threat model, output sanitization |
| `secaudit:deployment` | Production config, security headers, source maps, preview-deployment isolation, clickjacking |
| `secaudit:data-access` | SQL injection, ORM operator injection, runtime input validation, mass assignment |
| `secaudit:web-vulns` | XSS, SSRF, file upload + path traversal, IDOR (broken object-level authorization) |
| `secaudit:cryptography` | Password hashing, secure randomness, weak algorithms/modes, hardcoded keys, JWT alg confusion |
| `secaudit:logging-monitoring` | Error info disclosure, secrets in logs, audit logging, insecure deserialization, command injection |

## Why a security plugin for AI-generated code

AI assistants reliably get a recurring set of security patterns wrong, which leads to real breaches: stolen API keys, drained billing accounts, and fully exposed databases. The core principle running through every skill: **never trust the client.** Every price, user ID, role, subscription status, and rate-limit counter must be validated or enforced server-side.

The content is based on published research, official security advisories, and documented real-world breaches. If you spot gaps, outdated patterns, or mistakes, please open an issue or PR.

## Credits

- Original skill by [Chris Raroque](https://github.com/raroque) and the team at [Aloa](https://aloa.co).
- v2.0 content updates by the [fartiacht](https://github.com/fartiacht) fork.
- Research sources include the Supabase Security Retro 2025, Next.js and React security advisories, the OWASP Top 10 for LLM Applications (2025), the MCP security best-practices guidance, and the USENIX 2025 study on package hallucinations.

## License

MIT, same as the original.
