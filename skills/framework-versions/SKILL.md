---
name: framework-versions
description: Checks package.json and lock files for known-vulnerable framework versions (Next.js, React, Express, and similar) and cross-references them against critical CVEs. Use when reviewing dependencies, upgrading a framework, setting up a project, or auditing for vulnerable versions — and whenever you see a package.json with a pinned framework version. A vulnerable framework version is often the single highest-impact issue in an audit.
license: MIT
---

# Framework Version Security

AI-generated projects frequently pin outdated framework versions or inherit them from starter
templates. A vulnerable framework version is often the single highest-impact issue in an audit.

## When to Use

- Reviewing or auditing `package.json` / lock files for vulnerable versions.
- Upgrading a framework (Next.js, React, etc.) or setting up a new project.
- A reported issue smells like a known CVE (RCE, auth bypass, DoS).
- Cross-referencing installed versions against current advisories.

## Check Process

1. Read `package.json` (and `package-lock.json` or equivalent) for framework versions.
2. Cross-reference against the critical CVEs below **and the live advisory database** — treat the
   list here as a starting point, not a frozen source of truth. Verify against GitHub Advisories
   / NVD and run `npm audit`.
3. Flag any match as **High** or **Critical** severity.

## Next.js / React — Critical CVEs

### CVE-2025-55182 — React Server Components deserialization RCE (CVSS 10.0, Dec 2025)

"React2Shell." A pre-auth Remote Code Execution via unsafe deserialization of Server Function
payloads in React Server Components. Actively exploited (listed in CISA KEV).

- **Canonical ID:** `CVE-2025-55182` (the React advisory). The Next.js-side ID `CVE-2025-66478`
  was **rejected by NVD as a duplicate** — cite `CVE-2025-55182` so scanners aren't confused.
- **Affected (React):** `react-server-dom-*` 19.0.0, 19.1.0–19.1.1, 19.2.0.
- **Fixed (React):** 19.0.1, 19.1.2, 19.2.1.
- **Fixed (Next.js):** 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7.
- **Action:** Upgrade immediately. Also `CVE-2025-55183` (source exposure) and
  `CVE-2025-55184` (DoS) are fixed in the same releases.

### CVE-2025-29927 — Next.js middleware authorization bypass (CVSS 9.1, Mar 2025)

Adding the `x-middleware-subrequest` header bypasses all middleware logic, including auth checks.

- **Affected:** 11.1.4–12.3.4, 13.0.0–13.5.8, 14.0.0–14.2.24, 15.0.0–15.2.2.
- **Fixed in:** 12.3.5, 13.5.9, 14.2.25, 15.2.3.
- **Action:** Upgrade AND stop relying on middleware as the sole auth layer (see
  `vibe-security:auth`). Vercel-hosted apps were not affected; self-hosted deployments were.

### CVE-2025-49826 — Next.js cache poisoning DoS (15.1.x)

Cache poisoning of HTTP 204 responses can serve blank pages (denial of service).

- **Affected:** 15.1.0–15.1.7. **Fixed in:** 15.1.8.

## Other ecosystems (verify against live advisories)

- **Express:** `CVE-2024-29041` (open redirect in `res.location`/`res.redirect`, fixed 4.19.0);
  `path-to-regexp` ReDoS `CVE-2024-52798` (fixed via Express 4.21.2 / path-to-regexp 0.1.12).
- **Astro:** `CVE-2024-56159` (server source-code exposure via public `.map` files, fixed
  4.16.18 / 5.0.8).
- **Vue 2:** EOL — `vue-template-compiler` XSS (`CVE-2024-6783`); migrate to Vue 3.

## What to Check

```bash
# Check Next.js version
cat package.json | grep '"next"'

# Check React version
cat package.json | grep '"react"'

# Check for all known vulnerabilities in dependencies
npm audit
```

## The Deeper Lesson

These CVEs reinforce a critical architectural principle: **middleware is NOT a security
boundary.** It is a convenience layer for routing and edge-level decisions. Auth checks must be
duplicated in:

- Server Actions
- Route Handlers (`app/api/`)
- Data access functions
- Database-level policies (RLS)

Think of middleware as a building's front door: it directs traffic and does a first pass, but
every room inside must still have its own lock. See `vibe-security:auth`.
