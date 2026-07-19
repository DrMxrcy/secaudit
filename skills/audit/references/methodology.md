# Audit Methodology — recon, analysis strategies, coverage check

This reference backs the orchestrator's **Reconnaissance** and **Coverage check** phases. It is
the *how you look*, complementing the domain skills' *what to look for*.

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

## 3. Coverage check — what did I not cover?

After the sweep and the verification pass, run a short completeness-critic pass before writing the
report. Ask:

- **Every entry point traced?** Is there a route/action/handler from recon that no domain actually
  examined?
- **Every applicable domain run?** Was a tier-1/2/3 domain skipped? If skipped because the tech is
  absent, confirm that from the code — don't assume.
- **Every trust boundary checked?** Did each client↔server / tenant↔tenant / user↔admin crossing
  get an authorization look?
- **Data flows followed to the end?** Any untrusted input whose path you started but didn't finish?

Then either cover the gap, or state it explicitly. A report that names its own boundaries
("did not review the mobile deep-link handlers — out of scope this pass") is more trustworthy than
one that implies total coverage it didn't achieve. Surface these as a short **Coverage & known
gaps** note in the output.
