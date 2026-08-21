---
id: 17
title: Add 2026 Next.js middleware-bypass wave and CISA KEV entries
type: feature
version: 3.4.0
status: done
created: 2026-08-21
---

# ✨ Plan 17: Add 2026 Next.js middleware-bypass wave and CISA KEV entries

> Type: feature · Target: v3.4.0

## 🎯 Target Scope & Boundaries

`framework-versions` documents `CVE-2025-29927` as the canonical middleware-bypass example and
stops there. Through 2026 a whole wave of successors landed, and two actively-exploited flaws in
ecosystems this plugin already ships skills for are absent entirely.

All of the following were verified against the OSV API and the CISA KEV feed on 2026-08-21.

**The 2026 Next.js wave** — same root lesson as 29927, so they belong beside it:

| CVE | What | Fixed |
|---|---|---|
| `CVE-2026-44573` | Middleware/Proxy bypass, Pages Router (from 12.2.0) | 15.5.16 / 16.2.5 |
| `CVE-2026-44574` | Middleware/Proxy bypass via dynamic routes | 15.5.16 / 16.2.5 |
| `CVE-2026-44575` | Middleware/Proxy bypass, App Router (from 15.2.0) | 15.5.16 / 16.2.5 |
| `CVE-2026-45109` | Incomplete fix for -44575 | — |
| `CVE-2026-64642` | Middleware/Proxy bypass, App Router + Turbopack | — |
| `CVE-2026-64643` | Unauthenticated disclosure of internal Server Function endpoints (from 13.0.0) | 15.5.21 / 16.2.11 |
| `CVE-2026-64649` | SSRF in Server Actions | — |
| `CVE-2026-29057` | HTTP request smuggling in rewrites (from 9.5.0) | 15.5.13 / 16.1.7 |
| `CVE-2026-44581` | XSS in App Router | — |

Note `CVE-2026-64643` is fixed exactly at **15.5.21 / 16.2.11** — the clean floors plan 12
established. That is not a coincidence and is worth stating: it is the advisory that sets the
floor.

**Two CISA KEV entries in this plugin's own domains, currently unmentioned anywhere:**

- `CVE-2025-11953` — `@react-native-community/cli` Metro dev server binds externally and exposes
  an OS-command-injection endpoint. Unauthenticated RCE. **KEV-listed 2026-02-05** (vendor
  "React Native Community/CLI"). Fixed 18.0.1 / 19.1.2 / 20.0.0, and the same ranges apply to
  `@react-native-community/cli-server-api`.
- `CVE-2025-31125` — Vite `server.fs.deny` bypass. **KEV-listed 2026-01-22**. Fixed
  4.5.11 / 5.4.16 / 6.0.13 / 6.1.3 / 6.2.4. Note `vite@6.2.3` carries 11 advisories in total,
  several of them further `server.fs.deny` bypasses — a repeat-offender surface worth flagging
  as a class, not just one CVE.

**Out of scope:** adding coverage for frameworks the plugin does not currently handle (Nuxt,
React Router/Remix, Astro's 2026 advisories, Node.js). Those are a separate item — this one
extends existing entries only.

## 🏗️ Architectural Blueprint

- **Files to modify:**
  - `skills/framework-versions/SKILL.md` — a subsection under the existing `CVE-2025-29927`
    entry for the 2026 wave, and KEV entries for the RN CLI and Vite flaws.
  - `skills/react-native-security/SKILL.md` — pointer to the Metro dev-server CVE, since that is
    where a reader auditing an RN app will look.
  - `SOURCES.md` — advisory URLs and the CISA KEV feed.
- **Framing:** the wave reinforces the file's existing thesis rather than replacing it. Nine
  successors to 29927 in one year is the argument for "middleware is not a security boundary" —
  present it that way, not as nine more rows to memorize.
- **Downstream impact:** version checks on Next.js, React Native, and Vite projects gain
  concrete, current advisories to match against.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Add the 2026 middleware-bypass wave under the existing `CVE-2025-29927` entry,
  framed as reinforcing the "not a security boundary" lesson -> target:
  `skills/framework-versions/SKILL.md`
- [x] Step 2: Add the two CISA KEV entries (RN CLI Metro RCE, Vite `server.fs.deny`) with their
  KEV listing dates and fixed versions -> target: `skills/framework-versions/SKILL.md`
- [x] Step 3: Cross-reference the Metro dev-server CVE from `react-native-security` -> target:
  `skills/react-native-security/SKILL.md`
- [x] Step 4: Add advisory and KEV URLs to `SOURCES.md` -> target: `SOURCES.md`
- [x] Step 5: Verify — every CVE ID resolves on OSV, every stated fixed version matches the
  advisory ranges, both KEV dates match the CISA feed, and all new URLs return 200 -> target:
  manual verification
