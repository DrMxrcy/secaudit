---
name: deployment
description: Audits deployment and production configuration — disabling debug mode and source maps, blocking exposed .git directories, separating environments so preview deployments never use production keys, setting security headers (strict nonce + strict-dynamic CSP, Trusted Types, Fetch Metadata, COOP/CORP, SRI, HSTS, X-Frame-Options), and locking down CORS. Use when configuring deploys (Vercel and similar), reviewing environment separation, setting response headers, or auditing what a production or preview build exposes.
license: MIT
---

# Deployment Security

## When to Use

- Configuring a deploy (Vercel, Netlify, self-hosted) or reviewing build settings.
- Setting up environment separation (production vs preview vs development).
- Adding or reviewing security headers and CORS.
- Auditing what a production or preview deployment exposes publicly.

## Production Configuration

- **Disable debug mode** in production. Debug pages often leak stack traces, environment
  variables, and internal paths.
- **Disable source maps** in production. Source maps expose your entire source code to anyone who
  opens DevTools.
- **Verify `.git` directory is not accessible** in production. If `https://yoursite.com/.git/HEAD`
  returns content, your entire source code and commit history (including any secrets ever
  committed) are exposed.

## Environment Separation

Use separate environment variables for each environment in Vercel (or equivalent):

| Environment | Purpose |
|-------------|---------|
| Production | Live users, real keys |
| Preview | PR previews, should use test/staging keys |
| Development | Local dev, uses local/test keys |

Preview deployments should **never** use production API keys, database credentials, or payment
keys. A preview deployment is often accessible to anyone with the URL.

### Preview Deployments Are Public by Default

**This is a critical gap in vibe-coded projects on Vercel.** By default, every PR or branch push
generates a preview URL that is publicly accessible. If preview deployments use production
environment variables:

- Production database is exposed via the preview app
- Real Stripe keys process test payments against live accounts
- AI API keys get burned through preview usage

**Mitigations:**
1. In Vercel Dashboard → Settings → Environment Variables, scope production secrets to
   "Production" only — never "Preview"
2. Enable Vercel Deployment Protection (Settings → Deployment Protection) to require
   authentication for preview URLs
3. Use separate Supabase projects or branches for preview environments
4. Never share preview URLs publicly — treat them as semi-private

### Check for Leaked Preview URLs

Search Slack, email, and project management tools for Vercel preview URLs that may have been
shared externally. Each one is a potential entry point if it uses production credentials.

## Security Headers

Set these on all responses. The CSP below is a **strict** policy (per-request nonce plus
`'strict-dynamic'`); the host-allowlist form many tutorials still show is bypassable — see §1.

```
Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic' 'report-sample'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp
Reporting-Endpoints: csp="https://reports.example.com/csp"
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin-allow-popups
```

Google's current web-security guidance ranks an enforced strict CSP (§1) and Trusted Types (§2) as
the highest-leverage items here: they are what turns an XSS bug into a blocked, reported violation.
Fetch Metadata, COOP/CORP and SRI (§3-§5) are isolation and supply-chain defence in depth. Roll
out in the order given under "Rollout order", not by pasting the whole block into production.

### 1. Strict CSP: nonce or hash plus `'strict-dynamic'`

**What to look for:** `script-src` built from host allowlists (`'self'`, `https://cdn.example.com`,
`https:`) with no nonce or hash; `'unsafe-inline'` in `script-src` with no nonce beside it; a nonce
that is a literal, is generated once at module load, or is baked into cached/static HTML; no
`object-src` or `base-uri`.

**Why it's exploitable:** an allowlist trusts every script the listed origin can ever serve. An open
redirect, a JSONP endpoint, an old library copy, or an upload/reflection endpoint on that origin
(`'self'` included) runs attacker-chosen script, so the policy passes a scanner and still lets XSS
through. Apps that need inline script then add `'unsafe-inline'`, which switches script protection
off. A nonce is a secret only while it is unguessable and per-response: a constant nonce, or one
frozen into cached HTML, is known to any attacker who reads the page. Without `object-src 'none'` a
plugin element can execute; without `base-uri` an injected `<base>` redirects every relative
`<script src>` to an attacker host.

**Fix:** generate 16 random bytes per request, base64 them, put the value in the header and on every
`<script nonce>`; add `'strict-dynamic'` so scripts the nonced loader creates are trusted without a
host list (modern browsers then ignore host entries and `'unsafe-inline'`, so keep those only as a
legacy fallback). Static HTML where a per-response nonce is impossible (a Vite SPA on a CDN) uses a
`sha256-` hash per script with `'strict-dynamic'` instead. Set `object-src 'none'` and
`base-uri 'none'`; `form-action 'self'` is a worthwhile option. Keep `'report-sample'` so violation
reports carry the first 40 characters of the offending code.

```
# BAD (bypassable): a host allowlist; any JSONP/redirect/upload on cdn.example.com defeats it
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com

# BAD: 'unsafe-inline' lets injected inline script run; the policy no longer prevents XSS
Content-Security-Policy: script-src 'self' 'unsafe-inline'

# GOOD
Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic' 'report-sample'; object-src 'none'; base-uri 'none'
```

```ts
// middleware — GOOD: a fresh nonce per request (Node and edge runtimes)
const bytes = crypto.getRandomValues(new Uint8Array(16));
const nonce = btoa(String.fromCharCode(...bytes));
headers.set('Content-Security-Policy',
  `script-src 'nonce-${nonce}' 'strict-dynamic' 'report-sample'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; report-to csp`);
// BAD: const NONCE = crypto.randomUUID();   // module scope: one value for every visitor
```

**Next.js:** the nonce is minted in `proxy.ts` (Next.js 16 renamed `middleware.ts` to `proxy.ts` and
the exported function from `middleware` to `proxy`; Next.js 15 and earlier still use `middleware.ts`).
The proxy sets the CSP on both the request and the response and passes the nonce in an `x-nonce`
request header; Next.js reads `'nonce-…'` from the request's CSP header and stamps it on its own
framework scripts, so only your own inline `<script>` / `<Script nonce>` needs it. The page must be
**dynamically rendered**: static pages are built with no request, so no nonce can be injected (call
`await connection()` to opt a page in), and CDN-cached HTML would freeze one nonce for everyone. The
Next.js docs derive the nonce as `Buffer.from(crypto.randomUUID()).toString('base64')`, which is
fine because it runs per request; for static output the docs describe an experimental SRI-hash
alternative. Copy the exact code from the current guide (Sources). **Hono / Cloudflare Workers:**
`secureHeaders({ contentSecurityPolicy: { scriptSrc: [NONCE] } })`, see
`secaudit:cloudflare-workers-security`.

A `<meta http-equiv>` CSP cannot carry `frame-ancestors` or Report-Only, so use a real header
wherever you can set one. The exception is a packaged page with no HTTP response, such as a FiveM
NUI `ui_page`, whose `'self'` + no-inline-script policy is covered in `secaudit:fivem-security` §8.
For pages that render user-authored documents, why a strict `script-src` matters and what else to
isolate is `secaudit:rich-text-security` §10.

### 2. Trusted Types

**What to look for:** an enforced CSP with no `require-trusted-types-for 'script'`; a policy whose
`createHTML` / `createScript` / `createScriptURL` returns its input unchanged.

**Why it's exploitable:** CSP stops injected `<script>`, but DOM XSS in your own code (`innerHTML`,
`document.write`, `script.src`, `eval`) is a string reaching a sink. Trusted Types makes those sinks
reject plain strings. A pass-through policy (`createHTML: (s) => s`) mints a trusted value from
anything, so the sink is open again while the audit looks green.

**Fix:** add `require-trusted-types-for 'script'` and restrict policy names with
`trusted-types <names>` (include `dompurify` if you delegate to DOMPurify, and `default` while
migrating). The policy sanitizes (`DOMPurify.sanitize(s, { RETURN_TRUSTED_TYPE: false })`) or
escapes; it never returns the string as-is. Prefer `el.setHTML()` where supported, which needs no
policy. Roll out through Report-Only first, and check that your framework and third-party libraries
already write trusted values. The sinks themselves are in `secaudit:web-vulns` §1.

### 3. Fetch Metadata resource isolation

**What to look for:** cookie-authenticated endpoints that never read `Sec-Fetch-Site`; a Fetch
Metadata check with no `Vary`; `same-site` trusted while a subdomain hosts user content.

**Why it's exploitable:** browsers send `Sec-Fetch-Site` / `Mode` / `Dest` on every request, and a
cross-site `<img>`, `<script>` or `fetch` to your API still carries the victim's cookies. Rejecting
cross-site non-navigation requests server-side closes CSRF-style and cross-site-leak (XS-Leaks)
probing for the whole app at once instead of per route. A CDN that caches the allowed answer and
replays it to the attacker's request needs `Vary` to tell them apart.

**Fix:** middleware, ahead of authentication, that allows `same-origin` / `same-site` / `none`,
allows cross-site only for top-level `navigate` GETs (not `object` / `embed`), and otherwise returns
403, with `Vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site`. Drop `same-site` if any subdomain
hosts untrusted content. Exempt only mapped cross-site integrations (webhooks, SSO callbacks) and
log before enforcing, since it blocks legitimate cross-site callers. A missing header (older
browsers) passes through; this is defence in depth, not a replacement for CSRF tokens or SameSite
cookies.

### 4. COOP and CORP

**What to look for:** no `Cross-Origin-Opener-Policy` on documents, or `unsafe-none`; no
`Cross-Origin-Resource-Policy` on authenticated JSON or file responses, or `cross-origin` set
globally.

**Why it matters:** with no COOP, a window your page opens (or that opened it) keeps a reference to
your page through `window.opener`, which enables cross-window XS-Leaks. A `same-origin` CORP stops
other sites reading your authenticated responses through `no-cors` embeds.

**Fix:** `Cross-Origin-Opener-Policy: same-origin` on documents, or `same-origin-allow-popups` when
the app itself opens OAuth or payment popups (Google's guide starts at `same-origin-allow-popups`
and moves to `same-origin` only after confirming nothing depends on `window.opener`).
`Cross-Origin-Resource-Policy: same-origin` on authenticated JSON and user files, `same-site`
across your own subdomains, `cross-origin` only on assets built for embedding. Full cross-origin
isolation (`COEP`, `Document-Isolation-Policy`) is only for `SharedArrayBuffer`; skip it otherwise.

### 5. Subresource Integrity

**What to look for:** a `<script src="https://…">` (or `<Script src>`) pointing at a third-party host
with no `integrity`; `integrity` without `crossorigin="anonymous"` (the browser cannot hash a
cross-origin response without CORS, so the script simply fails to load).

**Why it's exploitable:** a compromised CDN or tag host serves script to every visitor, running with
your origin's privileges; the SRI hash is what makes the tampered file fail to run.

**Fix:** `<script src="https://cdn.example.com/lib@1.2.3/lib.js" integrity="sha384-…"
crossorigin="anonymous">` for versioned, immutable files. Vendor the file, or rely on a nonce, for
assets that update in place (analytics and tag loaders): a changing file breaks every hash.

### Rollout order

1. Ship the low-risk headers now: HSTS (short `max-age` first, ramp to a year), `nosniff`,
   `Referrer-Policy`, `Permissions-Policy`, `frame-ancestors` / `X-Frame-Options`.
2. Add `Reporting-Endpoints: csp="https://…"` and the strict CSP, including
   `require-trusted-types-for 'script'`, as `Content-Security-Policy-Report-Only` with
   `report-to csp`. Run on real traffic for days to weeks and triage the reports, discarding noise
   from extensions and very old browsers.
3. Fix what the reports show (inline scripts get nonces, dangerous sinks get policies), then switch
   to `Content-Security-Policy` and **keep `report-to` on it** so regressions stay visible.
4. Add COOP/CORP and the Fetch Metadata check, logging before enforcing.

### Heuristics (grep / config)

First pass only: every line is a lead to read, not a verdict. Multi-line CSP arrays and policies set
in a CDN, Vercel or nginx config need a look at that config. Run against a scratch fixture with
vulnerable and clean files: the vulnerable set prints every check, the clean set prints nothing.

```bash
G() { grep -rnE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.jsx' \
  --include='*.html' --include='*.json' --include='*.toml' --include='*.yaml' --include='*.yml' --include='*.conf' "$@"; }

# 1a script-src with no nonce or hash (allowlist-only, or 'unsafe-inline' with nothing to disable it)
G "script-src|scriptSrc|script_src" . | grep -vE "nonce|NONCE|'sha(256|384|512)-"
# 1b CSP defined but missing object-src or base-uri
G -l "script-src|scriptSrc|script_src" . | while IFS= read -r f; do
  grep -qE "object-src|objectSrc|object_src" "$f" || echo "$f: no object-src"
  grep -qE "base-uri|baseUri|base_uri" "$f" || echo "$f: no base-uri"
done
# 1c constant nonce: a literal in a CSP string or attribute, or generated once at module load
G "'nonce-[A-Za-z0-9+/=_-]{8,}'|nonce[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=_-]{8,}[\"']|nonce=[\"'][A-Za-z0-9+/=_-]{8,}[\"']" .
G -i "^(export )?(const|let|var) +[A-Za-z_]*nonce[A-Za-z_]* *=.*(randomUUID|randomBytes|getRandomValues|Math\.random|Date\.now)" .
# 2 Trusted Types: pass-through (identity) policy, and enforcement absent everywhere
G "create(HTML|Script|ScriptURL) *: *(\(? *([A-Za-z_]+) *\)? *=> *\3 *[,}]|function *\( *([A-Za-z_]+) *\) *\{ *return +\4)|create(HTML|Script|ScriptURL) *\( *([A-Za-z_]+) *\) *\{ *return +\6 *;? *\}" .
G -q "require-trusted-types-for" . || echo "ADVISORY: require-trusted-types-for 'script' not set anywhere"
# 3 Fetch Metadata: header read without Vary, or never read
G -il "sec-fetch-site" . | while IFS= read -r f; do grep -qiE "vary.*sec-fetch" "$f" || echo "$f: Sec-Fetch-Site used, no Vary"; done
G -qi "sec-fetch-site" . || echo "ADVISORY: no Sec-Fetch-Site check anywhere"
# 4 COOP / CORP
G "Cross-Origin-Opener-Policy.{0,40}unsafe-none" .
G -qi "Cross-Origin-Opener-Policy|crossOriginOpenerPolicy" . || echo "ADVISORY: no COOP set"
G "Cross-Origin-Resource-Policy.{0,40}cross-origin" .
# 5 SRI: cross-origin script with no integrity; integrity with no crossorigin
G -i "<script[^>]*src=[\"']?(https?:)?//" . | grep -vi "integrity="
G -i "integrity=" . | grep -vi "crossorigin"
```

### Clickjacking

Without frame-busting headers, an attacker can embed your site in a transparent `<iframe>` over a
decoy page and trick a logged-in user into clicking real buttons (UI redress). Defend with both
`X-Frame-Options: DENY` (legacy) and the modern CSP directive `frame-ancestors 'none'` (or an
explicit allowlist if you intentionally embed your app). `frame-ancestors` supersedes
`X-Frame-Options` in browsers that support it; set both for coverage.

```
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
```

For Host-header trust in absolute-URL generation (password-reset poisoning, the
`ALLOWED_HOSTS`-style allowlist pattern, and failing closed with 421 on an unrecognized Host),
see `secaudit:proxy-trust`.

## Pre-Ship Checks

Before deploying:
- Run `gitleaks detect` on your repo to scan for leaked secrets in git history
- Verify `.env` files are in `.gitignore`
- Confirm debug mode / verbose logging is disabled
- Check that error pages don't leak stack traces
- Verify CORS is configured to allow only your domains, not `*`

## CORS Configuration

- Never use `Access-Control-Allow-Origin: *` on authenticated endpoints
- Whitelist only your own domains
- Be careful with `Access-Control-Allow-Credentials: true` — it must be paired with specific
  origins, not wildcards

## Sources

- https://owasp.org/projects/secure-headers-project -- CSP, HSTS, X-Frame-Options, frame-ancestors, etc.
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy -- CSP reference
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security -- HSTS reference
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS -- CORS (no wildcard with credentials)
- https://vercel.com/docs/deployment-protection -- preview deployments public by default
- https://github.com/GoogleChrome/modern-web-guidance-src/blob/main/guides/security/security/guide.md -- Google's security guide: strict CSP, Trusted Types, COOP/CORP, Fetch Metadata, SRI, report-only rollout, allowlists are bypassable
- https://github.com/GoogleChrome/modern-web-guidance-src/blob/main/guides/security/trusted-types/guide.md -- Trusted Types policies, `trusted-types` allowlist, no pass-through policy
- https://web.dev/articles/strict-csp -- nonce/hash plus `'strict-dynamic'`, why allowlist CSPs are bypassable
- https://web.dev/articles/trusted-types -- Trusted Types rollout
- https://web.dev/articles/fetch-metadata -- resource isolation policy on `Sec-Fetch-*`
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Reporting-Endpoints -- `Reporting-Endpoints` and `report-to`
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy -- COOP values
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy -- CORP values
- https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity -- SRI and `crossorigin`
- https://nextjs.org/docs/app/guides/content-security-policy -- Next.js nonce wiring (dynamic rendering, `proxy`, `x-nonce`)
- https://nextjs.org/docs/app/api-reference/file-conventions/proxy -- `middleware` renamed `proxy` in Next.js 16
