---
name: audit
description: Runs a full security audit of a codebase for the vulnerabilities AI coding assistants commonly introduce in "vibe-coded" apps. Orchestrates the focused vibe-security domain skills (secrets, database, auth, payments, supply chain, AI/LLM, Expo, React Native, Convex, and more). Use whenever the user asks for a security review or audit, says "is this safe?", "check my code", "review for vulnerabilities", "can someone hack this?", mentions "vibe coding", or wants a whole-app security sweep before shipping.
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

## Audit Process

Examine the codebase systematically. For each area, apply the matching domain skill **only if the
codebase uses that technology or pattern** — skip areas that aren't relevant. Each domain skill
carries the concrete detection patterns and before/after fixes.

1. **Framework versions** — known-vulnerable framework versions / CVEs in `package.json` and lock
   files. → `vibe-security:framework-versions`
2. **Secrets & environment variables** — hardcoded keys, client-exposed env prefixes
   (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`), default credentials, `.gitignore` hygiene.
   → `vibe-security:secrets`
3. **Database access control** — Supabase RLS, Firebase Security Rules, SQL/ORM exposure. The #1
   source of critical vulnerabilities in vibe-coded apps. → `vibe-security:database`
4. **Convex** — if the project uses Convex (`convex/` functions, schema). Convex has no row-level
   security; access control lives in function bodies. → `vibe-security:convex-security`
5. **Authentication & authorization** — JWT handling, middleware (never the sole auth layer),
   Server Action protection, session management. → `vibe-security:auth`
6. **Rate limiting & abuse prevention** — auth endpoints, AI calls, expensive operations; tamper-
   proof counters. → `vibe-security:rate-limiting`
7. **Payments** — client-side price manipulation, webhook signature verification, subscription
   status validation. → `vibe-security:payments`
8. **Supply chain & dependencies** — hallucinated/phantom packages (slopsquatting), unpinned
   versions, lock file hygiene. → `vibe-security:supply-chain`
9. **React Native** — if a bare/framework-agnostic RN app: secure storage, deep links, WebView,
   native bridge, network/ATS. → `vibe-security:react-native-security`
10. **Expo / EAS** — if an Expo app: `EXPO_PUBLIC_` inlining, EAS secrets, expo-secure-store, OTA
    code signing, config plugins, deep links. → `vibe-security:expo-security`
11. **AI / LLM integration** — exposed AI keys, missing usage caps, prompt injection, MCP security,
    unsafe output rendering. → `vibe-security:ai-integration`
12. **Deployment configuration** — production settings, security headers, source maps, preview
    deployment isolation, environment separation. → `vibe-security:deployment`
13. **Data access & input validation** — SQL injection, ORM misuse, mass assignment, missing input
    validation. → `vibe-security:data-access`
14. **Web vulnerabilities** — XSS, SSRF, file upload / path traversal, IDOR (broken object-level
    authorization). → `vibe-security:web-vulns`
15. **Cryptography** — password hashing, secure randomness, weak algorithms/modes, hardcoded
    keys/IVs, JWT algorithm confusion. → `vibe-security:cryptography`
16. **Logging, monitoring & integrity** — error info disclosure, secrets/PII in logs, missing
    audit logging, insecure deserialization, command injection. → `vibe-security:logging-monitoring`

For a partial review or when generating code in a specific area, dispatch only the relevant
domain skill(s).

## OWASP Coverage Map

A full sweep covers the OWASP Top 10 (2021), plus the OWASP LLM and Mobile Top 10s:

| OWASP 2021 | Domain skill(s) |
|---|---|
| A01 Broken Access Control | `database`, `auth`, `convex-security`, `web-vulns` (IDOR) |
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
- When multiple issues exist, prioritize by exploitability and real-world impact.
- If the codebase doesn't use a particular technology (e.g. no Supabase), skip that area entirely.
- When generating new code, consult the relevant domain skill proactively to avoid introducing
  vulnerabilities in the first place. Prevention is better than detection.
- If you find a critical issue (exposed secrets, disabled RLS, auth bypass, vulnerable framework
  version), flag it immediately at the top of your response — don't bury it in a long list.
- After the audit, recommend specific automated tools the developer should run (see Next Steps).

## Output Format

Organize findings by severity: **Critical** → **High** → **Medium** → **Low**.

For each issue:
1. State the file and relevant line(s).
2. Name the vulnerability.
3. Explain what an attacker could do (concrete impact, not abstract risk).
4. Show a before/after code fix.

Skip areas with no issues. End with a prioritized summary and a "Next Steps" section with
specific automated tools to run.

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

### Summary

1. **Service role key exposed (Critical):** Anyone can bypass all database security. Rotate the
   key immediately and move it to server-side only.
2. **Vulnerable Next.js version (High):** Upgrade to the patched version immediately — RCE is
   exploitable remotely.
3. **Client-controlled pricing (High):** Attackers can purchase at any price. Use server-side
   price lookup.

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

- `./references/tooling.md` -- Recommended automated security scanning tools, organized by stack,
  and when to run each.

## Sources

- https://owasp.org/Top10/ -- OWASP Top 10 (2021), the backbone this audit maps to
- https://genai.owasp.org/llm-top-10/ -- OWASP Top 10 for LLM Applications (2025)
- https://owasp.org/www-project-mobile-top-10/ -- OWASP Mobile Top 10
