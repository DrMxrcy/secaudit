---
name: framework-versions
description: Checks package.json and lock files for known-vulnerable framework versions (Next.js, React, Astro, Nuxt, Vite, Express, Hono, Fastify, Koa, Elysia, TanStack Start, Auth.js/next-auth, Drizzle ORM, and the Traefik proxy in front of them) and cross-references them against critical CVEs. Use when reviewing dependencies, upgrading a framework, setting up a project, or auditing for vulnerable versions — and whenever you see a package.json with a pinned framework version. A vulnerable framework version is often the single highest-impact issue in an audit.
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
2. **Look up live advisories for the exact installed versions** — this is the authoritative
   step. Query OSV.dev (or run `osv-scanner` / `npm audit`) for the packages found, so a CVE
   disclosed after this skill was last edited is still caught. Full procedure and a worked
   OSV.dev example: `./references/live-advisory-lookup.md`.
3. **Check whether the runtime itself is EOL** (see *Runtime end-of-life* below). An EOL runtime
   never gets a patch, which outranks any individual CVE.
4. **Look up EPSS for the CVEs you found** (see *Ranking by exploitation probability*), so the
   upgrade order reflects what is actually being exploited rather than only what scores badly.
5. Use the known high-impact examples below as a fast first pass and sanity check, **not** as the
   source of truth. If a live result and an example disagree, the live result wins.
6. Flag any match as **High** or **Critical** severity, and always report the **fixed version**
   to upgrade to (from the live advisory, not a guess).

## Between audits — continuous monitoring

Everything in this skill runs when someone invokes an audit. A new advisory can land against an
already-pinned version at any time, with nothing in the repo changing, so an app is only as
current as its last sweep.

`scripts/monitor-deps.py` plus the reusable workflow in `docs/monitoring.md` run the same
OSV → EPSS → KEV → EOL pass on a schedule against an app's own lockfile and open an issue when
something crosses the threshold. It is a prioritisation layer over Dependabot rather than a
replacement: Dependabot says what has an advisory, this says which one is being exploited today.

## Ranking by exploitation probability (EPSS)

CVSS measures *potential impact*. CISA KEV records *confirmed* exploitation but is deliberately
small, so almost every CVE a real project hits is absent from it. Between those two sits the
question a user actually needs answered: **is this one likely to be used against me?**

EPSS (FIRST.org) gives the probability a CVE is exploited in the wild within 30 days. Free, no key,
batched:

```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2025-55182,CVE-2024-29041" \
  | python3 -m json.tool
```

Why it changes the report — three CVEs this skill already covers:

| CVE | CVSS shape | EPSS | Percentile |
|---|---|---|---|
| `CVE-2025-55182` React2Shell RCE | Critical | **0.998** | 99.96th |
| `CVE-2025-29927` middleware bypass | Critical | **0.992** | 99.93rd |
| `CVE-2024-29041` Express open redirect | Moderate | **0.008** | 53rd |

All three are real. Only two are being used. Without EPSS the third gets patched with the same
urgency, which is how upgrade backlogs lose credibility.

**Decision rule — do not invent a composite score:**

- **On CISA KEV** → **Critical**, whatever CVSS and EPSS say. Confirmed exploitation ends it.
- **High CVSS + high EPSS** → patch now.
- **High CVSS + low EPSS** → real, but schedulable. Say so — this is the case that gets
  over-escalated today.
- **Low CVSS + high EPSS** → do not dismiss; frequently a chain component.
- **EOL runtime** → Critical on its own. There will never be a patch.

EPSS is a 30-day forecast and it moves. **Re-derive it at audit time; never quote a score from
memory or cache one into a skill file** — same rule as version floors.

## Runtime end-of-life

An end-of-life runtime receives **no security patches at all**, so it outranks any single CVE —
and no advisory database will tell you, because there is no CVE to file. OSV indexes packages, not
runtimes: an `ecosystem: "Node.js"` query returns HTTP 400.

Use endoflife.date (free, no key):

```bash
curl -s https://endoflife.date/api/nodejs.json | python3 -m json.tool | head -40
# also: python, django, postgresql, php, ruby, laravel, dotnet
```

Compare the running major's `eol` date against today. Examples as of writing — **re-derive these,
do not trust the line you are reading**:

- `Node 25` → eol 2026-06-01 → **already EOL**, still widely deployed
- `Python 3.9` → eol 2025-10-31 → **already EOL**

Check the runtime *and* the framework: Django, Laravel and .NET all have EOL cycles here too, and
a supported framework on an EOL language runtime is still unpatched underneath.

## Known high-impact examples (verify live)

> **These version numbers expire.** Every hardcoded version below is re-checked against OSV
> monthly by `scripts/check-freshness.py`, which fails if a version named as a safe target has
> acquired an advisory. That catches rot after the fact — it does not make the numbers current
> at the moment you are reading them. The median gap between `next` advisories is ~31 days, so
> **step 2's live lookup remains authoritative and this list never is.**

These are frequently-seen, high-impact CVEs — a quick first pass. Always confirm the current
picture with the live lookup in step 2; treat this list as examples, not an exhaustive or
frozen source of truth.

### Next.js / React

### CVE-2025-55182 — React Server Components deserialization RCE (CVSS 10.0, Dec 2025)

"React2Shell." A pre-auth Remote Code Execution via unsafe deserialization of Server Function
payloads in React Server Components. Actively exploited (listed in CISA KEV).

- **Canonical ID:** `CVE-2025-55182` (the React advisory). The Next.js-side ID `CVE-2025-66478`
  was **rejected by NVD as a duplicate** — cite `CVE-2025-55182` so scanners aren't confused.
- **Affected (React):** `react-server-dom-*` 19.0.0, 19.1.0–19.1.1, 19.2.0.
- **Patched by (React):** 19.0.1, 19.1.2, 19.2.1.
- **Patched by (Next.js):** 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7.
- **Do not stop there.** These are the releases that fixed *this* CVE, not versions that are
  safe today — later advisories landed on the same lines. As of 2026-08-21, OSV reports 28 open
  advisories for `next@15.5.7` and 33 for `next@16.0.7`. Current clean floors: **`next@15.5.24`**
  or **`next@16.3.3`**, and **`react-server-dom-*@19.2.8`**. Re-derive these from step 2 — do
  not trust the numbers on this line to still be clean when you read them.
- **2026-09-08 pair of unauthenticated RCEs** moved the floor from 15.5.21 / 16.2.11:
  `GHSA-2xp9-vwfh-vxw4` (RCE in the Image Optimization API when an AVIF file is processed,
  affects 10.0.0+) and `CVE-2026-75604` (RCE on Windows-hosted servers, affects 13.4.0+). Both
  fixed in **15.5.24 / 16.3.3**. Astro shipped an AVIF image-optimization RCE the same day
  (see below) — when one framework's image pipeline gets a CVE, check the others.
- **Sibling CVEs are patched one release later**, so upgrading to the -55182 fix leaves both
  open: `CVE-2025-55183` (source exposure) and `CVE-2025-55184` (DoS) are fixed in
  **19.0.2 / 19.1.3 / 19.2.2**, not 19.0.1 / 19.1.2 / 19.2.1.
- **Action:** Upgrade immediately, to a current clean floor rather than to the minimum patch.

### CVE-2025-29927 — Next.js middleware authorization bypass (CVSS 9.1, Mar 2025)

Adding the `x-middleware-subrequest` header bypasses all middleware logic, including auth checks.

- **Affected (patched lines):** 12.0.0–12.3.4, 13.0.0–13.5.8, 14.0.0–14.2.24, 15.0.0–15.2.2.
- **Fixed in:** 12.3.5, 13.5.9, 14.2.25, 15.2.3.
- **11.x is also vulnerable and has no patch.** The advisory's ranges start at 12.0.0, so there
  is no fixed release to upgrade to on 11.x. An 11.x app must move to a supported major, or
  strip the `x-middleware-subrequest` header at the proxy as a stopgap.
- **Action:** Upgrade AND stop relying on middleware as the sole auth layer (see
  `secaudit:auth`). Vercel-hosted apps were not affected; self-hosted deployments were.

### The 2026 middleware-bypass wave — why upgrading is not the fix

`CVE-2025-29927` was not a one-off. Through 2026 a run of successors landed on the same surface,
several of them auth bypasses:

| CVE | What | Fixed in |
|---|---|---|
| `CVE-2026-44573` | Middleware/Proxy bypass, Pages Router (affects from 12.2.0) | 15.5.16 / 16.2.5 |
| `CVE-2026-44574` | Middleware/Proxy bypass via dynamic routes | 15.5.16 / 16.2.5 |
| `CVE-2026-44575` | Middleware/Proxy bypass, App Router (from 15.2.0) | 15.5.16 / 16.2.5 |
| `CVE-2026-45109` | Incomplete fix for `-44575` | see advisory |
| `CVE-2026-64642` | Middleware/Proxy bypass, App Router + Turbopack | see advisory |
| `CVE-2026-64643` | Unauthenticated disclosure of internal Server Function endpoints (from 13.0.0) | 15.5.21 / 16.2.11 |
| `CVE-2026-64649` | SSRF in Server Actions | see advisory |
| `CVE-2026-29057` | HTTP request smuggling in rewrites (from 9.5.0) | 15.5.13 / 16.1.7 |
| `CVE-2026-44581` | XSS in App Router with CSP nonces | see advisory |

**Read this as one finding, not nine.** A single middleware bypass is a bug; nine in a year on
the same surface is a structural argument. An app whose only authorization check lives in
middleware is one advisory away from being open, permanently — the patch treadmill is not a
control. Enforce authorization at the data-access layer, where no routing-layer bypass can
skip it. Middleware is an optimistic redirect, not a boundary. (See `secaudit:auth`.)

Note `CVE-2026-64643` is fixed exactly at **15.5.21 / 16.2.11** — that advisory is what sets the
clean floors named above.

### CISA KEV — actively exploited, in ecosystems this plugin covers

Being on the CISA Known Exploited Vulnerabilities catalog means confirmed exploitation in the
wild, not theoretical risk. Treat a KEV match as **Critical** regardless of its CVSS score.

- **`CVE-2025-11953`** — `@react-native-community/cli` Metro development server binds to external
  interfaces and exposes an endpoint that runs arbitrary OS commands. Unauthenticated RCE against
  any developer machine on a shared or public network. **KEV-listed 2026-02-05.** Affects
  `@react-native-community/cli` and `@react-native-community/cli-server-api`; fixed **18.0.1 /
  19.1.2 / 20.0.0**. (See `secaudit:react-native-security`.)
- **`CVE-2025-31125`** — Vite `server.fs.deny` bypass, allowing reads of files the dev server was
  configured to refuse. **KEV-listed 2026-01-22.** Fixed **4.5.11 / 5.4.16 / 6.0.13 / 6.1.3 /
  6.2.4**. `server.fs.deny` is a repeat-offender surface — `CVE-2025-32395` and `CVE-2025-46565`
  are further bypasses of the same control, so check the installed version against *all* of them
  rather than this one CVE.

Both are dev-server flaws, which teams routinely dismiss as "not production". They are
exploitable against developer and CI machines, which hold source, credentials, and cloud tokens.

### CVE-2025-49826 — Next.js cache poisoning DoS (15.1.x)

Cache poisoning of HTTP 204 responses can serve blank pages (denial of service).

- **Affected:** `>=15.0.4-canary.51 <15.1.8` — canary builds below 15.1.0 are in range too, so a
  pinned canary is not off the hook. **Fixed in:** 15.1.8.

## Other ecosystems (verify against live advisories)

- **Express:** `CVE-2024-29041` (open redirect in `res.location`/`res.redirect`, fixed **4.19.2**
  — not 4.19.0, which is still in range; `5.0.0-beta.3` on the 5.x line). Note 4.19.2 is *not* a
  clean floor: `CVE-2024-43796` (XSS via `res.redirect()`) is still open there, and so is the
  `path-to-regexp` ReDoS `CVE-2024-52798`. Current clean 4.x floor is **4.21.2**
  (path-to-regexp 0.1.12), which closes all three.
- **Astro:** `CVE-2024-56159` (server source-code exposure via public `.map` files) was patched by
  4.16.18 / 5.0.8. **Those are not safe versions today** — as of 2026-08-24 OSV reports **17 open
  advisories** for each, including middleware auth bypasses via URL encoding. The 5.x line never
  becomes clean: `5.20.0` still carries 8. Current clean floor is **`astro@7.2.8`**. Astro accrues
  advisories faster than most of this list, so re-derive from step 2 rather than trusting this line.
- **Astro, 2026-09-08:** `7.1.0` was the clean floor until two advisories landed the same day as
  the Next.js pair above. `GHSA-26w7-cxv4-gfx2` is an unauthenticated RCE through AVIF image
  optimization, fixed 7.2.8.
- Same day: `CVE-2026-84376`, an authorization bypass from a missing path-segment boundary check
  when stripping the configured `base` (so `/admin` protection can be skipped via
  `/adminX`-style paths), fixed 7.2.4.
- **Vue 2:** EOL — `vue-template-compiler` XSS (`CVE-2024-6783`); migrate to Vue 3.
- **Nuxt:** 21 advisories, **16 of them published in 2026** — an actively-hunted surface, not a
  dormant entry. Server Islands are the hot spot: `CVE-2026-71320` (server-side RCE via runtime
  template injection in island props), `CVE-2026-71318` (unauthorized component instantiation via
  island props), `CVE-2026-71321` (unauthenticated CPU exhaustion parsing island payloads). Also
  `CVE-2026-72744`, where the dev server discloses the project root and workspace UUID. Current
  clean floor **`nuxt@4.5.1`** — 4.4.7 still carries 7 open advisories and 4.4.6 carries 11, so
  "on the latest 4.4.x" is not good enough.
- **React Router / Remix:** 20 advisories, **18 published in 2026**. Open redirects
  (`CVE-2026-53668` leading to XSS, `CVE-2026-53669` via a backslash in `<Link>`/`useNavigate`),
  CSRF in action and document request processing (`CVE-2026-22030`, `CVE-2026-53663`, plus an
  RSC-mode CSRF bypass), and unauthenticated DoS via inefficient route matching
  (`CVE-2026-55685`). Current clean floor **`react-router@7.18.2`** or **`react-router@8.3.0`**.
  **Check `@remix-run/*` too** — those packages carry the same advisories under a different name,
  so a Remix app is in scope and a grep for "react-router" alone will miss it.
- **Vite:** `server.fs.deny` is a repeat-offender control, and that pattern is the finding rather
  than any single CVE. Beyond the KEV-listed `CVE-2025-31125` above, the same guard has been
  bypassed by `CVE-2025-32395`, `CVE-2025-46565`, and `CVE-2026-53571` (Windows alternate paths);
  `CVE-2026-39365` is a path traversal in optimized-deps `.map` handling. Current clean floors
  **`vite@7.3.5`** or **`vite@8.0.16`** (8.0.5 still carries 2). Treat a project relying on
  `server.fs.deny` to protect anything sensitive as a design problem, not a patching problem.
- **Node.js (the runtime, not a package):** check `node --version` against the official security
  releases. **No version is named here on purpose** — OSV indexes npm packages, not the Node.js
  runtime (an `ecosystem: "Node.js"` query returns HTTP 400), so the automated freshness check
  cannot police a hardcoded Node version and it would silently rot. Read the current advisory
  from <https://nodejs.org/en/blog/vulnerability/> and confirm the running major is still
  supported; an EOL major receives no patches at all, which is the more common finding.

## Server frameworks and libraries (verify against live advisories)

- **Hono:** 50 advisories and a fast-moving surface. The 2026-09-08 trio `CVE-2026-84363`
  (the query parser reads parameters after the URL fragment, poisoning cache keys and proxy
  routing), `CVE-2026-84364` (unbounded dot-notation nesting in `parseBody()` exhausts memory)
  and `CVE-2026-84365` (`toSSG()` writes files outside the output directory) is fixed 4.13.5;
  the 2026-08-07 trio including `CVE-2026-71850` (`memo()` retains SSR output across requests,
  so one user's rendered page is served to another) is fixed 4.12.34. `hono@4.11.7` is a trap:
  it is the version blog posts name as the answer to the `CVE-2026-24473` serve-static
  environment-key disclosure on the Cloudflare Workers adapter, and it still carries 33 open
  advisories. Current clean floor **`hono@4.13.5`**.
- **Auth.js / NextAuth:** the July 2026 set lands on `next-auth` and `@auth/core` together.
  `CVE-2026-73419` is the one that matters: OAuth `state`, `nonce` and PKCE check cookies are
  not bound to the provider that issued them, so a flow started with one provider can be
  completed with another and account linking hands over the account; fixed 4.24.15 /
  5.0.0-beta.32, and 0.41.3 on `@auth/core`. `CVE-2026-73418` (`getToken()` throws an uncaught
  exception on a malformed `Bearer` header) and `CVE-2026-73420` (the email normalizer validates
  before Unicode normalization) ship on the same releases, while `CVE-2026-73421` — config
  errors make existence-based auth checks fail open — is fixed only in 5.0.0-beta.32. Current
  clean floors **`next-auth@4.24.15`** or **`next-auth@5.0.0-beta.32`**, with
  **`@auth/core@0.41.3`** underneath. Detection guidance lives in the Auth.js section of
  `secaudit:auth`.
- **Drizzle ORM:** `CVE-2026-39356` — `escapeName()` does not escape identifiers in any SQL
  dialect, so a user-controlled value reaching `sql.identifier()` or `.as()` is SQL injection,
  in an ORM most people assume is parameterised end to end; fixed 0.45.2, and 1.0.0-beta.20 on
  the beta line. Current clean floors **`drizzle-orm@0.45.2`** and
  **`drizzle-orm@1.0.0-beta.20`**. See `secaudit:data-access`.
- **Koa:** `CVE-2026-27959` — `ctx.hostname` trusts the `Host` header, so a poisoned host flows
  into password-reset links and cache keys; fixed 2.16.4 / 3.1.2. The `back` redirect helper is
  a repeat offender underneath it: `CVE-2025-32379` XSS via `ctx.redirect()` fixed 2.16.1,
  `CVE-2025-8129` open redirect fixed 2.16.2 / 3.0.1, `CVE-2025-62595` open redirect via a
  trailing `//` fixed 2.16.3 / 3.0.3. Current clean floors **`koa@2.16.4`** and **`koa@3.1.2`**.
- **Fastify:** three of the four headline issues are trust-boundary bugs, not memory bugs.
  `CVE-2026-16732` — `X-Forwarded-*` spoofing when `trustProxy` is set to a hop count; fixed
  5.12.1. `CVE-2026-3635` — `request.protocol` and `request.host` are spoofable via
  `X-Forwarded-Proto` / `X-Forwarded-Host` sent by an untrusted peer; fixed 5.8.3.
  `CVE-2026-18504` — schema validation bypass via a root primitive coercion mismatch; fixed
  5.12.1. `CVE-2025-32442` — a leading space in `Content-Type` defeats content-type parsing and
  the validation attached to it; fixed 5.8.5. Current clean floor **`fastify@5.12.1`**. The
  proxy-header pair is a configuration finding as much as a version one — see
  `secaudit:proxy-trust`.
- **Elysia:** `CVE-2026-31865` — cookie value prototype pollution; fixed 1.4.27.
  `CVE-2026-30837` — ReDoS in the string URL format validator; fixed 1.4.26. `CVE-2025-66457` —
  arbitrary code injection through the cookie config; fixed 1.4.18. Current clean floor
  **`elysia@1.4.27`**.
- **TanStack Start:** the only advisory against `@tanstack/react-start` is a supply-chain
  incident, not a code defect — `CVE-2026-45321` (OSV also tracks it as `MAL-2026-3468`), the May 2026 malware
  releases in which 42 `@tanstack/*` packages were republished with code that exfiltrates cloud
  credentials, GitHub tokens and SSH keys; fixed 1.167.72 on this package, with sibling packages
  republished across their own lines. A lockfile is no defence here: `npm ci` reinstalls the
  malicious release faithfully, so the check is which version resolved, not whether the install
  was reproducible. Current clean floor **`@tanstack/react-start@1.168.54`**. The old package
  name `@tanstack/start` shows zero advisories and is deprecated — read that as unmaintained,
  not safe. See `secaudit:supply-chain` and `secaudit:ci-cd-security`.
- **Traefik** (Go module `github.com/traefik/traefik/v3`, normally deployed as a container, so
  `npm audit` and lockfile scanners never see it): ForwardAuth has taken a wave of pre-auth
  bypasses. `CVE-2026-35051` — a spoofed `X-Forwarded-Prefix` skips the auth decision even with
  `trustForwardHeader=false`; fixed 2.11.43 / 3.6.14. `CVE-2026-39858` — the same bypass via
  underscore alias headers; fixed 2.11.43 / 3.6.14. `CVE-2026-54764` — `X-Forwarded-Port`
  spoofing through an untrusted `X-Forwarded-Proto`; fixed 2.11.51 / 3.6.22 / 3.7.6.
  `CVE-2026-71326` — a BasicAuth singleflight key collision serves one authenticated user as
  another; fixed 3.6.25 / 3.7.10. `CVE-2026-88011` — ForwardAuth identity spoofing via a
  dot-form header alias; fixed 2.11.56 / 3.7.12. Current clean floor is **Traefik 3.7.13**
  (3.7.10 still carries 6 open GHSAs, 3.7.12 carries 4) — pin the image by digest, and
  re-derive from OSV with `ecosystem: "Go"` and package `github.com/traefik/traefik/v3`; an npm
  query returns nothing for it, which reads as clean and is not, and this repo's freshness
  script only re-derives npm floors, so the floor on this line is not machine-checked (the
  fixed versions are). Five bypasses of one middleware is the same
  lesson as the Next.js wave: an identity header from a proxy is an assertion, not a
  boundary — see `secaudit:proxy-trust`.

### The shared image pipeline

Next.js and Astro both shipped an unauthenticated RCE in image optimization on 2026-09-08,
both triggered by an AVIF file. Same day, same input format, two advisories — because most
JS frameworks' optimizers are a thin wrapper over the same `sharp` / `libvips` decode path.
One malformed-input bug downstream surfaces as a separate advisory per framework, each on its
own release schedule, so patching the one that was announced leaves the rest open.

**When any framework's image optimizer gets a CVE, check every other image-processing
dependency in the tree** — `sharp`, `@img/sharp-*`, `libvips`, ImageMagick bindings, and each
framework wrapping them. An app that accepts and resizes user uploads is exposed for as long as
its slowest wrapper takes to ship, whichever framework's name was on the advisory.

## What to Check

```bash
# Check Next.js version
cat package.json | grep '"next"'

# Check React version
cat package.json | grep '"react"'

# Check for all known vulnerabilities in dependencies against LIVE advisory data
npm audit
osv-scanner scan source --lockfile package-lock.json   # if installed; see references below
```

## References

- `./references/live-advisory-lookup.md` -- How to look up live CVE/advisory data for the exact
  installed versions (OSV.dev API worked example, `osv-scanner`, `npm audit`, GitHub Advisories,
  firecrawl/WebSearch fallback). The authoritative step 2 of the check process.

## The Deeper Lesson

These CVEs reinforce a critical architectural principle: **middleware is NOT a security
boundary.** It is a convenience layer for routing and edge-level decisions. Auth checks must be
duplicated in:

- Server Actions
- Route Handlers (`app/api/`)
- Data access functions
- Database-level policies (RLS)

Think of middleware as a building's front door: it directs traffic and does a first pass, but
every room inside must still have its own lock. See `secaudit:auth`.

## Sources

- https://nvd.nist.gov/vuln/detail/cve-2025-55182 -- React2Shell RSC RCE (CVSS 10.0)
- https://nvd.nist.gov/vuln/detail/cve-2025-66478 -- confirms the Next.js-side ID is a rejected duplicate
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog -- CISA KEV (React2Shell actively exploited)
- https://github.com/advisories/GHSA-f82v-jwr5-mffw -- CVE-2025-29927 middleware bypass advisory
- https://github.com/advisories/GHSA-67rr-84xm-4c7r -- CVE-2025-49826 cache-poisoning DoS advisory
- https://nextjs.org/blog -- official Next.js security releases
- https://github.com/advisories/GHSA-925w-6v3x-g4j4 -- CVE-2025-55183 source exposure, fixed 19.0.2 / 19.1.3 / 19.2.2 (one patch later than CVE-2025-55182)
- https://github.com/advisories/GHSA-2m3v-v2m8-q956 -- CVE-2025-55184 DoS, same one-patch-later fix line
- https://github.com/advisories/GHSA-rv95-896h-c2vc -- CVE-2024-29041 Express open redirect, fixed 4.19.2 (not 4.19.0) and 5.0.0-beta.3
- https://github.com/advisories/GHSA-36qx-fr4f-26g5 -- CVE-2026-44573 middleware/proxy bypass, Pages Router
- https://github.com/advisories/GHSA-492v-c6pp-mqqv -- CVE-2026-44574 middleware/proxy bypass via dynamic routes
- https://github.com/advisories/GHSA-267c-6grr-h53f -- CVE-2026-44575 middleware/proxy bypass, App Router
- https://github.com/advisories/GHSA-26hh-7cqf-hhc6 -- CVE-2026-45109 incomplete fix for CVE-2026-44575
- https://github.com/advisories/GHSA-6gpp-xcg3-4w24 -- CVE-2026-64642 middleware/proxy bypass, App Router + Turbopack
- https://github.com/advisories/GHSA-955p-x3mx-jcvp -- CVE-2026-64643 unauthenticated Server Function endpoint disclosure; sets the 15.5.21 / 16.2.11 floors
- https://github.com/advisories/GHSA-89xv-2m56-2m9x -- CVE-2026-64649 SSRF in Server Actions
- https://github.com/advisories/GHSA-ggv3-7p47-pfv8 -- CVE-2026-29057 HTTP request smuggling in rewrites
- https://github.com/advisories/GHSA-ffhc-5mcf-pf4q -- CVE-2026-44581 XSS in App Router with CSP nonces
- https://github.com/advisories/GHSA-399j-vxmf-hjvr -- CVE-2025-11953 React Native CLI Metro dev-server RCE (CISA KEV 2026-02-05)
- https://github.com/advisories/GHSA-4r4m-qw57-chr8 -- CVE-2025-31125 Vite server.fs.deny bypass (CISA KEV 2026-01-22)
- https://github.com/advisories/GHSA-qwww-vcr4-c8h2 -- React Router RSC-mode CSRF bypass
- https://github.com/advisories/GHSA-crvj-82cr-hjcx -- CVE-2026-84363 Hono query parser reads past the URL fragment; the 2026-09-08 trio sets the 4.13.5 floor
- https://github.com/advisories/GHSA-f23p-vx2j-j53r -- CVE-2026-71850 Hono `memo()` cross-user SSR disclosure, fixed 4.12.34
- https://github.com/advisories/GHSA-w332-q679-j88p -- CVE-2026-24473 Hono serve-static env-key read; its fix release 4.11.7 still carries 33 open advisories
- https://github.com/advisories/GHSA-x445-f3h2-j279 -- CVE-2026-73419 Auth.js OAuth check cookies not bound to the provider (account-linking takeover)
- https://github.com/advisories/GHSA-8fpg-xm3f-6cx3 -- CVE-2026-73421 NextAuth config errors make existence-based auth checks fail open (5.x only)
- https://github.com/advisories/GHSA-gpj5-g38j-94v9 -- CVE-2026-39356 Drizzle ORM identifier injection via `escapeName()` in every SQL dialect
- https://github.com/advisories/GHSA-7gcc-r8m5-44qm -- CVE-2026-27959 Koa Host header injection via `ctx.hostname`
- https://github.com/advisories/GHSA-3m5p-2c4r-xxw2 -- CVE-2026-16732 Fastify `X-Forwarded-*` spoofing under trustProxy hop-count
- https://github.com/advisories/GHSA-444r-cwp2-x5xf -- CVE-2026-3635 Fastify request.protocol/host spoofable from an untrusted peer
- https://github.com/advisories/GHSA-8hq9-phh3-p2wp -- CVE-2026-31865 Elysia cookie value prototype pollution
- https://github.com/advisories/GHSA-g7cv-rxg3-hmpx -- CVE-2026-45321 malware in 42 @tanstack/* releases (credential/token/SSH-key exfiltration)
- https://github.com/advisories/GHSA-6384-m2mw-rf54 -- CVE-2026-35051 Traefik ForwardAuth bypass via X-Forwarded-Prefix
- https://github.com/advisories/GHSA-5m6w-wvh7-57vm -- CVE-2026-39858 Traefik forwarded alias-header bypass (same middleware)
- https://github.com/advisories/GHSA-3q9r-p662-5j8m -- CVE-2026-54764 Traefik ForwardAuth X-Forwarded-Port spoofing
- https://github.com/advisories/GHSA-6765-c87h-8mrf -- CVE-2026-71326 Traefik BasicAuth singleflight identity spoof
- https://github.com/advisories/GHSA-2xp9-vwfh-vxw4 -- Next.js AVIF image-optimization RCE, 2026-09-08
- https://github.com/advisories/GHSA-26w7-cxv4-gfx2 -- Astro AVIF image-optimization RCE, same day; the shared sharp/libvips pipeline
