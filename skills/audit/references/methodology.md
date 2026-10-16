# Audit Methodology — recon, analysis strategies, variant analysis, fail-open sweep, coverage check

This reference backs the orchestrator's **Reconnaissance**, **Variant analysis**, **Fail-open /
insecure-defaults sweep** and **Coverage check** phases. It is the *how you look*, complementing the
domain skills' *what to look for*.

## 1. Reconnaissance — map the attack surface first

Before running the risk-ranked tiers, spend a short pass building a map of what you're auditing.
This makes domain selection and risk-ranking evidence-based (audit the surfaces that actually
exist) instead of guessed, and it feeds `Scope Control`.

Map, from the code and config (not assumptions):

- **Stack & frameworks** — language(s), framework + version (`package.json` etc.), meta-framework
  (Next.js, Expo), backend (Convex, Supabase, Firebase, custom), ORM/DB.
- **Entry points** (every place untrusted input or an unauthenticated caller can enter):
  HTTP routes / route handlers, Server Actions, RPC/tRPC, GraphQL resolvers, Convex public
  `query`/`mutation`/`action`/`httpAction`, webhooks, cron/scheduled jobs, file uploads, deep
  links / URL schemes, WebSocket handlers, CLI/queue consumers.
- **Trust boundaries** — client ↔ server, server ↔ third party, tenant ↔ tenant, user ↔ admin.
  Note where data crosses one; bugs cluster there.
- **AuthN / AuthZ mechanism** — how a request is authenticated (session, JWT, cookie) and where
  authorization is enforced (middleware? handler? DB/RLS?). Note the *authoritative* layer.
- **Data stores & secrets** — databases, object storage, env vars, key management.
- **Security config reads** — every `file:line` that reads a secret, allowed origin, auth toggle,
  rate-limit store, verification secret, TLS option, debug or security feature flag from env/config.
  This is the fail-open sweep's territory (§3).
- **Third-party integrations** — payments (Stripe), AI/LLM providers, email/SMS, OAuth providers.

Output of recon: a short attack-surface list that (a) tells `Scope Control` what's in play and
(b) orders the risk tiers toward the surfaces that carry the most exposure.

## 2. Two analysis strategies (apply within each domain)

The tiered domains are covered with two complementary lenses. Use both:

- **Sink-driven (taint tracing):** start at a dangerous **sink** (a SQL exec, a raw-HTML render
  sink, a shell/`child_process` call, `fetch(userUrl)`, `path.join(userInput)`, deserialization)
  and trace *backward* to see whether untrusted input reaches it without sanitization. Answers
  "can bad input get here?".
- **Control-driven (control enumeration):** start at each **entry point** from recon and check
  *forward* that the required control exists — is there an authZ check, an input validator, an
  ownership scope, a rate limit? Answers "is this protected?". This catches the *missing-guard*
  bugs (a new admin route with no role check) that sink-driven analysis alone misses.

Sink-driven finds injection-class bugs; control-driven finds access-control / missing-control bugs.
A vibe-coded app needs both because the common failure is an *omitted* control, not a *wrong* one.

## 3. Fail-open / insecure-defaults sweep — what happens when the config is wrong?

A cross-cutting pass alongside the tiers: for every security-relevant setting read from env/config,
**what does the code do when the value is missing, empty, or malformed?** Only *refuse to start*
(preferred) or *deny the request* are acceptable; a permissive fallback is the bug —
[CWE-636 Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html),
[CWE-1188 Initialization of a Resource with an Insecure Default](https://cwe.mitre.org/data/definitions/1188.html)
(variant [CWE-453](https://cwe.mitre.org/data/definitions/453.html)); OWASP's
["Fail Safe" and "Security by Default"](https://devguide.owasp.org/en/02-foundations/03-security-principles/).

### What to inventory

Recon lists every such read (`process.env.X`, `import.meta.env.X`, `c.env.X`, `config.get('x')`,
`os.getenv`, a YAML/JSON key) with its `file:line`:

| Class | Typical names | Permissive fallback to look for |
|---|---|---|
| Secrets and signing keys | `JWT_SECRET`, `SESSION_SECRET`, `AUTH_SECRET`, `SIGNING_KEY` | a literal fallback, or verification skipped when unset |
| Allowed origins / hosts | `ALLOWED_ORIGINS`, `CORS_ORIGIN`, `ALLOWED_HOSTS` | `'*'`, `origin: true` (reflect any origin), an empty list read as "allow all" |
| Auth toggles | `REQUIRE_AUTH`, `SKIP_AUTH`, `DISABLE_AUTH`, `NODE_ENV` gates | auth off unless a variable says otherwise |
| Rate-limit stores | `REDIS_URL`, `UPSTASH_REDIS_REST_URL`, KV bindings | every request allowed when the store is unset or down |
| Webhook verification | `*_WEBHOOK_SECRET`, `*_SIGNING_SECRET` | `if (secret) verify()` |
| TLS options | `sslmode`, `rejectUnauthorized`, `NODE_TLS_REJECT_UNAUTHORIZED` | encryption optional, or the certificate not verified |
| Debug flags | `DEBUG`, `VERBOSE_ERRORS`, `EXPOSE_STACK` | stack traces or debug routes on unless switched off |
| Security feature flags | `MFA_ENABLED`, `ENFORCE_SSO`, `CSRF_ENABLED` | the protection defaulting to off |

Evaluate three inputs per read: **missing** (unset in a preview or new target), **empty** (`FOO=`
sets `''`, which `??` does not catch, and `''.split(',')` is `['']`), **malformed** (`NODE_ENV=prod`,
`"false"` read as truthy, a silently coerced value).

### BAD / GOOD patterns

```typescript
// BAD — unset ALLOWED_ORIGINS means every origin
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? '*' }));
// GOOD — the list is validated at boot (schema below); there is no fallback to reach
app.use(cors({ origin: env.ALLOWED_ORIGINS, credentials: true }));
// Omitting `origin` is the same bug: Express `cors` and Hono `cors()` default it to '*' (secaudit:deployment)

// BAD — NODE_ENV unset, misspelled ('prod') or 'staging' => auth is skipped
if (process.env.NODE_ENV !== 'production') return next();
// GOOD — a bypass, if one must exist, needs an explicit opt-in the boot schema refuses in production
if (env.NODE_ENV === 'development' && env.DEV_AUTH_BYPASS) return next();

// BAD — "false" is truthy, so DISABLE_AUTH=false disables auth; and unset MFA_ENABLED means off
const authDisabled = !!process.env.DISABLE_AUTH;
const requireMfa = process.env.MFA_ENABLED === 'true';
// BAD — Zod's z.coerce.boolean() is Boolean(input): it parses "false" as true
const Flags = z.object({ ENFORCE_SSO: z.coerce.boolean() });
// GOOD — z.stringbool(), and security flags default to ON
const Flags = z.object({ ENFORCE_SSO: z.stringbool().default(true) });
```

```typescript
// BAD — the authorization error is swallowed and the action proceeds
try { await authorize(user, 'project:delete', project); } catch { /* continue */ }
await deleteProject(project.id);
// BAD — the error path returns the allow value (also: policy.check(...).catch(() => true))
try { return await policy.check(user, doc); } catch { return true; }
// GOOD — an error in the check is a denial
try { return await policy.check(user, doc); }
catch (err) { logger.error({ err }, 'authz check failed'); return false; }
```

The other shapes have a home in a domain skill; apply them from there, not from here:

- `if (process.env.WEBHOOK_SECRET) verify()` — `secaudit:webhook-security` ("Fail closed when the
  secret env var is unset").
- `jwt.verify(token, process.env.JWT_SECRET || 'dev-secret')` — a public signing key;
  `secaudit:secrets` (default literals) and `secaudit:cryptography` (algorithm pinning).
- A limiter that allows everything when its store is down — `secaudit:rate-limiting`. The one shape
  that can be a deliberate availability choice: only on low-risk routes, documented and alerted, never
  login / OTP / reset / AI spend. `@upstash/ratelimit` (TS) passes requests after its `timeout`
  (default 5 s); the `limit()` response's `reason` records it.
- Auth.js `!!auth` true on a config error — `secaudit:auth`. TLS that verifies nothing
  (`sslmode=require`, `rejectUnauthorized: false`) — `secaudit:prisma-security` §7.

### The fix that removes the whole class: validate config at boot

```typescript
// env.ts — imported first by the server entry point; every other module imports `env` from here
import { z } from 'zod';

const Env = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']),
  JWT_SECRET: z.string().min(32),
  WEBHOOK_SECRET: z.string().min(1),
  ALLOWED_ORIGINS: z.string().min(1)
    .transform((s) => s.split(',').map((o) => o.trim()))
    .pipe(z.array(z.url())),
  REDIS_URL: z.url(),
  ENFORCE_SSO: z.stringbool().default(true),
  DEV_AUTH_BYPASS: z.stringbool().default(false),
}).refine((e) => !(e.NODE_ENV === 'production' && e.DEV_AUTH_BYPASS), {
  message: 'DEV_AUTH_BYPASS must not be set in production',
});

export const env = Env.parse(process.env);   // throws a ZodError at startup -> the process exits
```

Every failure moves to boot, and once `env` exists a **direct `process.env.X` read of a security
setting elsewhere is itself a finding**. The parse runs at import, so tests need these variables set
too (a test `.env` or setup file) — not a reason to add fallbacks. Workers have no boot step: parse
in the first middleware and return 500 on failure (`secaudit:cloudflare-workers-security`).

### Grep heuristics

Every hit is a candidate; triage each with the three inputs above and the verification pass.

```bash
# Wildcard fallback: `|| '*'`, `?? '*'`
rg -n -t ts -t js "(\|\||\?\?)\s*['\"\`]\*['\"\`]" .
# Any literal fallback on an env read (triage by name: SECRET|KEY|TOKEN|ORIGIN|PASSWORD|URL)
rg -n -t ts -t js "[\w.]*env\.[A-Z0-9_]+\s*(\|\||\?\?)\s*['\"\`]" .
# Destructured defaults: const { JWT_SECRET = 'dev' } = process.env
rg -n -t ts -t js "\}\s*=\s*(process\.env|\benv)\b" .
# Verification/auth gated on a variable being set. Also matches the SAFE boot guard
# `if (!process.env.X_SECRET) throw ...` — keep hits whose branch skips or allows, drop the throws
rg -n -t ts -t js "if\s*\(\s*!?\s*[\w.]*env\.[A-Z0-9_]*(SECRET|KEY|TOKEN|VERIFY|AUTH)" .
rg -n -t ts -t js "[\w.]*env\.[A-Z0-9_]*(SECRET|KEY|TOKEN|VERIFY|AUTH)\w*\s*&&" .   # env.X && verify()
# Environment-name bypasses
rg -n -t ts -t js "NODE_ENV\s*!==?\s*['\"]production['\"]" .
# Boolean env parsing that reads "false" as true, or unset as off
rg -n -t ts -t js "!!\s*process\.env\.|process\.env\.[A-Z0-9_]+\s*===?\s*['\"](true|1)['\"]|z\.coerce\.boolean" .
# Swallowed errors and catch-to-allow: catch {}, catch { return true }, .catch(() => true)
rg -n -U -t ts -t js "catch\s*(\([^)]*\))?\s*\{\s*\}|catch\s*(\([^)]*\))?\s*\{\s*return\s+(true|next\(\))|\.catch\(\s*\(\)\s*=>\s*(true|null|undefined|\{\s*\})\s*\)" .
# Known bypass-flag names (extend the list with names recon found)
rg -n --hidden "\b(SKIP_AUTH|DISABLE_AUTH|AUTH_BYPASS|BYPASS_AUTH|DEV_AUTH_BYPASS|ALLOW_ALL_ORIGINS|INSECURE_[A-Z_]+)\b" -g '*.{ts,tsx,js,mjs,cjs,yml,yaml,toml,json}' -g '.env*' .
# TLS made optional or unverified
rg -n "rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|sslmode=(disable|allow|prefer)" .
# Python: os.environ.get / os.getenv with a literal default
rg -n -t py "(os\.environ\.get|os\.getenv)\([^,)]+,\s*['\"]" .
```

`-t ts` covers `.ts .tsx .mts .cts`, `-t js` `.js .jsx .mjs .cjs .vue`. Without ripgrep, `grep -rnE`
handles the single-line patterns; the multi-line `catch` case is then missed — say so in coverage.

### Evidence for a fail-open finding

The fallback code is evidence; whether production runs with the value missing usually is not in the
repo.

- **[Confirmed]** when the permissive state is what ships: the option is omitted entirely, the
  fallback is unconditional, or a deploy config in the repo (`.env.example`, compose file,
  `wrangler.toml`, a Kubernetes manifest, CI env) shows the variable unset or empty for a real target.
- **[Needs verification]** when the value's presence per deploy target is outside the repo; say what
  would confirm it (set in production *and* every preview — `secaudit:deployment`). Fix it anyway.
- **Not a finding** when only never-shipped code reaches it (confirmed from the imports).

Rate severity by what the permissive state exposes (skipped auth or a known signing secret is
Critical; a wildcard origin on credential-less public data is Low), not by the pattern. Each instance
of one shape is a variant (§4): one root cause, one fix at the env module. The fail-open worker
returns **the full config-read inventory with a verdict per read** (deny / crash / permissive) —
that is the explicit-pass record the coverage check needs.

## 4. Variant analysis — one confirmed bug is a search pattern

"Variant analysis is the process of using a known security vulnerability as a seed to find similar
problems in your code" ([CodeQL docs](https://codeql.github.com/docs/codeql-overview/about-codeql/)).
A vibe-coded app is assembled from repeated shapes, so a bug in one instance is rarely alone;
reporting it without its siblings is a coverage failure that looks like a complete finding.

### When it runs, and on what

After verification, before the report. Seeds are **CONFIRMED** findings (or PARTIAL with the root
cause confirmed), never unverified candidates; verified variants are not themselves seeds. Under the
fan-out model this is **Phase 4**: one worker per root cause, dispatched by the parent, searching the
**whole repository** rather than the domain's file list. Inline, run the steps yourself. In
**diff/PR scope** it is the one exception to "changed code only": label variants outside the diff
**pre-existing** and keep them out of the verdict on the change.

### Steps

The procedure follows Trail of Bits' [variant-analysis skill](https://github.com/trailofbits/skills/blob/main/plugins/variant-analysis/skills/variant-analysis/SKILL.md),
adapted to this audit's evidence rules.

1. **Name the root cause, not the symptom** — *why* the code is wrong. Most seeds are one of:
   a **missing guard** (an entry point lacks a check its siblings need), an **unsafe API** (`sql.raw`,
   `$queryRawUnsafe`, `dangerouslySetInnerHTML`, `child_process.exec`, `fetch(userUrl)`), a **shared
   helper** (the flaw is in one function every caller inherits), a **copy-pasted shape** (a handler
   template duplicated across files or services), or an **insecure default** (§3).
2. **Match the seed exactly first.** If the pattern does not match the seed, you have misunderstood
   the bug.
3. **Generalise one element at a time** — parameter name, HTTP method, router, file type, service —
   reading every match after each change. Stop widening when more than half the matches are noise.
4. **Sweep the whole codebase, including sibling services** — every workspace (`pnpm-workspace.yaml`,
   `package.json` `workspaces`, `turbo.json` / `nx.json`), and other-language services on the same data.
5. **Use the strongest tool present** and say which ran (no installs mid-audit): ripgrep (shape, not
   data flow); Semgrep (structural, `...` / `$X`); CodeQL (`codeql database create db
   --language=javascript-typescript`) for data flow. [Multi-repository variant analysis](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-vs-code/run-queries-at-scale)
   runs one CodeQL query on up to 1,000 repositories.
6. **Verify every candidate on its own** with the four verification questions (Phase 3, fresh
   context, under the fan-out model). A variant is reported only with its **own** `file:line` and
   mechanism — never "and probably the other routes too". Typical refutations: a guard applied
   upstream (router middleware, a wrapper), a constant argument, dead code.
7. **Report under the root cause** — verified instances, each tagged; refuted-match count and why;
   the pattern(s) run; one fix at the shared choke point where one exists; the pattern as a CI check.
   "Seed is the only instance across 23 handlers" is an explicit pass — record it.

### Worked examples

**A. One `sql.raw` with request data → every `sql.raw`.**

```typescript
// Seed (confirmed): src/db/posts.ts — the sort key from the query string is concatenated into SQL
const rows = await db.execute(sql`SELECT * FROM posts ORDER BY ${sql.raw(req.query.sort)}`);
```

Root cause: an unsafe API fed request data.

```bash
rg -n -t ts -t js "sql\.raw\(" .
# widen to the sibling escape hatches
rg -n -t ts -t js "sql\.identifier\(|\.\\\$queryRawUnsafe\(|\.\\\$executeRawUnsafe\(|\.as\(\s*[a-z]\w*\s*\)" .
semgrep -e 'sql.raw($X)' --lang ts .   # if installed: matches regardless of formatting
```

Constant arguments (`sql.raw('NOW()')`) are refuted and counted; the variants are calls whose
argument traces to a request. One fix: an allowlist helper (`orderByColumn(key)`) every caller uses
(`secaudit:data-access`).

**B. A Hono route missing a community-scope check → every route taking the same parameter.**

Seed: `app.get('/communities/:communityId/posts', requireUser, …)` returns any community's posts to
any signed-in user. Root cause: a missing guard — `:communityId` is used as a scope without a
membership check.

```bash
rg -n -t ts -t js "/:communityId\b" .
rg -n -t ts -t js "param\(\s*['\"]communityId['\"]\s*\)|communityId\s*[:=]\s*(body|input|args|data)\." .
```

Widen to other names for the scope (`:community`, `:slug`) and other entry types (WebSocket joins,
Server Actions, queue consumers). One middleware every matched route mounts:

```typescript
const requireMember = createMiddleware<{ Variables: { user: SessionUser } }>(async (c, next) => {
  const communityId = c.req.param('communityId');
  if (!communityId || !(await isMember(c.get('user').id, communityId))) return c.json({ error: 'Not found' }, 404);
  await next();
});
```

Other seeds follow the same shape: one Server Action without an auth check means auditing every
export of every `'use server'` module (`secaudit:auth`); one FiveM net-event handler trusting its
arguments instead of `source` means auditing every `onNet` / `RegisterNetEvent` handler
(`secaudit:fivem-security`).

## 5. Coverage check — what did I not cover?

After the sweep and the verification pass, run a short completeness-critic pass before writing the
report. Ask:

- **Every entry point traced?** Is there a route/action/handler from recon that no domain actually
  examined?
- **Every applicable domain run?** Was a tier-1/2/3 domain skipped? If skipped because the tech is
  absent, confirm that from the code — don't assume.
- **Every trust boundary checked?** Did each client↔server / tenant↔tenant / user↔admin crossing
  get an authorization look?
- **Data flows followed to the end?** Any untrusted input whose path you started but didn't finish?
- **Every security config read given a verdict?** Does the fail-open inventory (§3) cover every
  env/config read recon found, each marked deny / crash / permissive?
- **Every confirmed finding swept for variants?** For each root cause, which pattern ran, with which
  tool (rg / Semgrep / CodeQL), over which workspaces (§4)? A confirmed finding never swept is a gap.

Then either cover the gap, or state it explicitly. A report that names its own boundaries
("did not review the mobile deep-link handlers — out of scope this pass") is more trustworthy than
one that implies total coverage it didn't achieve. Surface these as a short **Coverage & known
gaps** note in the output.
