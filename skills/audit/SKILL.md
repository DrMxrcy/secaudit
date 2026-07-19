---
name: audit
description: Runs a full security audit of a codebase for the vulnerabilities AI coding assistants commonly introduce in "vibe-coded" apps. Orchestrates the focused secaudit domain skills (secrets, database, auth, payments, supply chain, AI/LLM, Expo, React Native, Convex, and more). Use whenever the user asks for a security review or audit, says "is this safe?", "check my code", "review for vulnerabilities", "can someone hack this?", mentions "vibe coding", or wants a whole-app security sweep before shipping.
license: MIT
---

# Security Audit (Orchestrator)

Audit a codebase for security vulnerabilities commonly introduced by AI code generation.
These issues are prevalent in "vibe-coded" apps: projects built rapidly with AI assistance where
security fundamentals get skipped. AI assistants consistently get these patterns wrong, leading
to real breaches, stolen API keys, and drained billing accounts.

This skill is the entry point for a full sweep. It owns the audit process, the severity model,
and the output format. The detection patterns and fixes for each area live in the focused domain
skills it dispatches to.

## When to Use

- The user asks for a security review, audit, or "check my code".
- The user asks "is this safe?", "can someone hack this?", or "is this production-ready?".
- The user mentions "vibe coding" or rapidly AI-generated code.
- Before shipping or deploying an app for the first time.
- For a single area only (e.g. "just check my Supabase RLS"), the matching domain skill below
  fires on its own. Use this orchestrator when the scope is the whole app.

## The Core Principle

Never trust the client. Every price, user ID, role, subscription status, feature flag, and rate
limit counter must be validated or enforced server-side. If it exists only in the browser, mobile
bundle, or request body, an attacker controls it.

## Scope Control

Match the effort to what was asked — don't blanket-dispatch every domain when the request is
narrow.

- **Whole app** (default): run the full risk-ranked sweep below, skipping only areas whose
  technology the project doesn't use.
- **A named surface** (e.g. "audit the admin panel", "just the checkout flow", "the auth"):
  scope to the files/routes for that surface and dispatch only the domains that apply to it. For
  an admin panel that's `privilege-escalation`, `auth`, `database`/`convex-security`, `web-vulns`
  (IDOR), and `logging-monitoring` — not payments, mobile, or supply chain.
- **A single domain** (e.g. "check my Supabase RLS"): dispatch only that domain skill.
- **A path/subset**: restrict reading to those files and run the relevant domains against them.

State the chosen scope in one line before you start, so the user can widen or narrow it.

## Reconnaissance (before the sweep)

First map the attack surface of what's in scope — stack and frameworks, **entry points** (routes,
Server Actions, webhooks, cron, public Convex functions, uploads, deep links), trust boundaries,
the authentication/authorization mechanism and its authoritative layer, data stores, and
third-party integrations. Read this from the code and config, not from assumptions.

Recon makes the rest evidence-based: it confirms which domains actually apply (so risk-ranking and
`Scope Control` target real surfaces, not guesses) and gives the coverage check something to check
against. Apply two lenses throughout the sweep — **sink-driven** (trace untrusted input toward
dangerous sinks) and **control-driven** (enumerate entry points, verify each has its authZ /
validation / ownership / rate-limit guard). Full checklist and strategies:
`./references/methodology.md`.

## Audit Process (risk-ranked)

Examine the codebase systematically. Work **highest-risk areas first** so criticals surface early,
but for a whole-app sweep still cover every applicable tier. For each area, apply the matching
domain skill **only if the codebase uses that technology or pattern** — skip areas that aren't
relevant. Each domain skill carries the concrete detection patterns and before/after fixes.

**Tier 1 — highest impact, always first.** These produce most critical findings in vibe-coded apps.

1. **Secrets & environment variables** — hardcoded keys, client-exposed env prefixes
   (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`), default credentials, `.gitignore` hygiene.
   → `secaudit:secrets`
2. **Framework versions** — known-vulnerable framework versions / CVEs in `package.json` and lock
   files (live advisory lookup). → `secaudit:framework-versions`
3. **Database access control** — Supabase RLS, Firebase Security Rules, SQL/ORM exposure. The #1
   source of critical vulnerabilities in vibe-coded apps. → `secaudit:database`
4. **Convex** — if the project uses Convex (`convex/` functions, schema). Convex has no row-level
   security; access control lives in function bodies. → `secaudit:convex-security`
5. **Authentication & authorization** — JWT handling, middleware (never the sole auth layer),
   Server Action protection, session management. → `secaudit:auth`
6. **Privilege escalation & admin surface** — unprotected admin routes/actions, roles trusted from
   the client, broken function-level authorization, role mass-assignment. → `secaudit:privilege-escalation`
7. **Payments** — client-side price manipulation, webhook signature verification, subscription
   status validation. → `secaudit:payments`

**Tier 2 — common, high-frequency web attack surface.**

8. **Rate limiting & abuse prevention** — auth endpoints, AI calls, expensive operations; tamper-
   proof counters. → `secaudit:rate-limiting`
9. **Web vulnerabilities** — XSS, SSRF, file upload / path traversal, IDOR (broken object-level
   authorization). → `secaudit:web-vulns`
10. **Data access & input validation** — SQL injection, ORM misuse, mass assignment, missing input
    validation. → `secaudit:data-access`
11. **AI / LLM integration** — exposed AI keys, missing usage caps, prompt injection, MCP security,
    unsafe output rendering. → `secaudit:ai-integration`
12. **Deployment configuration** — production settings, security headers, source maps, preview
    deployment isolation, environment separation. → `secaudit:deployment`

**Tier 3 — still covered on a full sweep; often lower or conditional impact.**

13. **Cryptography** — password hashing, secure randomness, weak algorithms/modes, hardcoded
    keys/IVs, JWT algorithm confusion. → `secaudit:cryptography`
14. **Logging, monitoring & integrity** — error info disclosure, secrets/PII in logs, missing
    audit logging, insecure deserialization, command injection. → `secaudit:logging-monitoring`
15. **Supply chain & dependencies** — hallucinated/phantom packages (slopsquatting), unpinned
    versions, lock file hygiene. → `secaudit:supply-chain`
16. **React Native** — if a bare/framework-agnostic RN app: secure storage, deep links, WebView,
    native bridge, network/ATS. → `secaudit:react-native-security`
17. **Expo / EAS** — if an Expo app: `EXPO_PUBLIC_` inlining, EAS secrets, expo-secure-store, OTA
    code signing, config plugins, deep links. → `secaudit:expo-security`

For a partial review or when generating code in a specific area, dispatch only the relevant
domain skill(s).

## Optional final phase — dynamic verification

Static tiers 1–17 read code and produce *candidate* findings. When a running instance of the app
is available **and the user authorizes active testing of their own app**, follow the static sweep
with `secaudit:dynamic-verification` to confirm or refute findings against the live app (security
headers, CORS, unauthenticated routes, IDOR, reflected XSS). It upgrades a suspected finding to
**Confirmed** with reproduction evidence, or **Refutes** it when a runtime control already handles
it. This phase is optional and off by default — it requires the authorization gate in that skill.
If no running app is available, leave unconfirmed findings tagged **Needs verification**.

## OWASP Coverage Map

A full sweep covers the OWASP Top 10 (2021), plus the OWASP LLM and Mobile Top 10s:

| OWASP 2021 | Domain skill(s) |
|---|---|
| A01 Broken Access Control | `database`, `auth`, `privilege-escalation`, `convex-security`, `web-vulns` (IDOR) |
| A02 Cryptographic Failures | `cryptography` |
| A03 Injection | `data-access`, `web-vulns` (XSS), `logging-monitoring` (command injection) |
| A04 Insecure Design | `rate-limiting`, `payments` (partial) |
| A05 Security Misconfiguration | `deployment`, `secrets` |
| A06 Vulnerable Components | `framework-versions`, `supply-chain` |
| A07 Auth Failures | `auth` |
| A08 Data Integrity Failures | `supply-chain`, `expo-security` (OTA), `logging-monitoring` (deserialization) |
| A09 Logging & Monitoring Failures | `logging-monitoring` |
| A10 SSRF | `web-vulns` |
| OWASP LLM Top 10 | `ai-integration` |
| OWASP Mobile Top 10 | `react-native-security`, `expo-security` |

## Core Instructions

- Report only genuine security issues. Do not nitpick style or non-security concerns.
- **No speculative findings.** Report a vulnerability only if you actually read the code that
  proves it. Every finding must cite a verified `file:line` you opened and name its mechanism (the
  source→sink data flow, or the specific missing control and the entry point it should protect). If
  you cannot point to real code, do not report it — a guess dressed as a finding is worse than
  silence.
- When multiple issues exist, prioritize by exploitability and real-world impact.
- If the codebase doesn't use a particular technology (e.g. no Supabase), skip that area entirely.
- When generating new code, consult the relevant domain skill proactively to avoid introducing
  vulnerabilities in the first place. Prevention is better than detection.
- If you find a critical issue (exposed secrets, disabled RLS, auth bypass, vulnerable framework
  version), flag it immediately at the top of your response — don't bury it in a long list.
- **Never reproduce a real secret in your output.** When a finding involves a hardcoded key,
  token, password, or other credential, identify it by **location** (file + line) and a **masked**
  form only — e.g. `sk_live_…REDACTED`, `AKIA…REDACTED`, or `***` — quoting at most the last 4
  characters for identification. Describe the vulnerable *pattern*; do not paste the sensitive
  literal into a "before" snippet, a quote, or a fix example. The audit report, its logs, and any
  PR comment are themselves places a leaked secret can spread. Treat a discovered secret as already
  compromised and tell the user to rotate it, without echoing its value.
- After the audit, recommend specific automated tools the developer should run (see Next Steps).

### Verification pass (before reporting)

Static reading produces *candidate* findings; some aren't real. Before a finding reaches the user,
challenge it adversarially and drop or downgrade the ones that don't survive:

1. **Reachable?** Is the vulnerable code reachable from an entry point (route, action, handler,
   event), or is it dead/unused code?
2. **Attacker-controlled?** Does untrusted input actually flow to the sink, or is the value fixed,
   server-derived, or already constrained upstream?
3. **Compensating control?** Is there an existing guard (RLS, a middleware+handler check, framework
   auto-escaping, a validator) that already neutralizes it?
4. **Evidenced?** Can you cite the verified `file:line` you actually read and name the mechanism
   (the source→sink path, or the missing control and the entry point it should guard)? If not,
   **drop it** — do not downgrade a finding you cannot tie to real code.

Label each reported finding **Confirmed** (a concrete exploit path holds, backed by cited code) or
**Needs verification** (real code evidence exists, but you could not confirm reachability or
attacker-control from the code alone — say what would confirm it). A finding that fails the
**Evidenced?** check is dropped, not labelled. Don't pad the report with issues you couldn't stand
behind. For findings that warrant runtime proof, hand off to `secaudit:dynamic-verification` when a
running app is available.

### Coverage check (after the sweep)

Before writing the report, run a short completeness-critic pass against the recon map: was every
entry point traced, every applicable domain actually run (skips confirmed from the code, not
assumed), every trust boundary given an authorization look, every started data-flow followed to its
end? Cover any gap you find, or state it explicitly. Report what you did **not** cover as a short
**Coverage & known gaps** line — a report that names its own boundaries is more trustworthy than
one that implies total coverage. See `./references/methodology.md`.

### Attack chains (link findings into exploit paths)

Individual findings undersell risk. After findings are gathered and verified, look for **attack
chains** — an ordered path where several issues combine into a worse outcome than any single one:
e.g. *public signup with no email verification → no rate limit on login → weak password-reset token
= account takeover*, or *IDOR on `/orders/:id` → an admin object is reachable → privilege
escalation*.

Rules:
- Build a chain only from findings that already passed the verification pass, and only when the
  steps are genuinely **connected and reachable in sequence** — no speculative chains.
- Reference each step by the finding's `file:line`; don't restate the whole finding.
- Rate the chain by its **outcome** severity — a chain can be more severe than any single link
  (three Mediums that combine into account takeover is a Critical chain).

## Output Format

Organize findings by severity: **Critical** → **High** → **Medium** → **Low**.

For each issue:
1. State the file and relevant line(s) — a verified `file:line` you actually read. If the line
   contains a secret, mask its value (see the redaction rule in Core Instructions) — cite the
   location, never the literal credential.
2. Name the vulnerability, and tag it **[Confirmed]** or **[Needs verification]** (see the
   Verification pass above).
3. Explain what an attacker could do (concrete impact, not abstract risk), and state the
   **mechanism** in one line: the source→sink path, or the missing control and the entry point it
   should guard. This is the evidence the finding rests on.
4. Show a before/after code fix. In the "before", use a masked placeholder where a real secret
   would appear (`***`, `sk_live_…REDACTED`) — do not reproduce the actual value.

Skip areas with no issues. After the severity-grouped findings, add an **Attack Chains** section
when two or more findings combine into an exploit path (see the Attack chains rules above); rate
each chain by its outcome severity and reference its steps by `file:line`. End with a prioritized
summary and a "Next Steps" section with specific automated tools to run.

### Example Output

#### Critical

**`lib/supabase.ts:3` — Supabase `service_role` key exposed in client bundle**

The `service_role` key bypasses all Row-Level Security. Anyone can extract it from the browser
bundle and read, modify, or delete every row in your database.

```typescript
// Before
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY!)

// After — use the publishable/anon key client-side; the secret/service_role key belongs only in server-side code
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

#### High

**`package.json` — next@15.1.0 vulnerable to CVE-2025-55182 (React2Shell, CVSS 10.0)**

This version is exposed to a critical pre-auth Remote Code Execution vulnerability in React Server
Components. Upgrade to the patched release for your branch (e.g. 15.1.9).

```json
// Before
"next": "15.1.0"

// After — upgrade to the patched version for your branch
"next": "15.1.9"
```

#### High

**`app/api/checkout/route.ts:15` — Price taken from client request body**

An attacker can set any price (including $0.01) by modifying the request. Prices must be looked up
server-side.

```typescript
// Before
const session = await stripe.checkout.sessions.create({
  line_items: [{ price_data: { unit_amount: req.body.price } }]
})

// After — look up the price server-side
const product = await db.products.findUnique({ where: { id: req.body.productId } })
const session = await stripe.checkout.sessions.create({
  line_items: [{ price: product.stripePriceId }],
})
```

### Attack Chains

**Chain 1 — Account takeover (Critical outcome; individual links are High/Medium)**
1. `app/api/auth/reset/route.ts:22` (High) — password-reset token is a 6-digit number (weak randomness).
2. `app/api/auth/login/route.ts:8` (Medium) — no rate limit on the reset/login endpoints.
3. Combined: an attacker requests a reset for a victim, then brute-forces the 6-digit token
   unthrottled (10^6 attempts) → full account takeover. Neither issue is critical alone; chained,
   they are. Fix either link to break the chain; fix both.

### Summary

1. **Service role key exposed (Critical):** Anyone can bypass all database security. Rotate the
   key immediately and move it to server-side only.
2. **Vulnerable Next.js version (High):** Upgrade to the patched version immediately — RCE is
   exploitable remotely.
3. **Client-controlled pricing (High):** Attackers can purchase at any price. Use server-side
   price lookup.

**Coverage & known gaps:** Reviewed the web/API surface, auth, database, and payments. Did not
review the mobile app (out of scope this pass) — run `secaudit:expo-security` on it separately.

### Next Steps

Run these automated checks:
- `npx gitleaks detect` — scan git history for leaked secrets
- `npm audit` — check dependencies for known vulnerabilities
- Supabase Dashboard → Security Advisor — scan for RLS misconfigurations
- Verify `.env` is in `.gitignore`: `git ls-files | grep -i env`

For the full, stack-specific tooling list, see `./references/tooling.md`.

## When Generating Code

These rules also apply proactively. Before writing code that touches auth, payments, database
access, API keys, or user data, consult the relevant domain skill to avoid introducing the
vulnerability in the first place. Prevention is better than detection.

## References

- `./references/methodology.md` -- The recon / attack-surface checklist, the sink-driven vs
  control-driven analysis strategies, and the coverage-gap self-check questions.
- `./references/tooling.md` -- Recommended automated security scanning tools, organized by stack,
  and when to run each.

## Sources

- https://owasp.org/Top10/ -- OWASP Top 10 (2021), the backbone this audit maps to
- https://genai.owasp.org/llm-top-10/ -- OWASP Top 10 for LLM Applications (2025)
- https://owasp.org/www-project-mobile-top-10/ -- OWASP Mobile Top 10
