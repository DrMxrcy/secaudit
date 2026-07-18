---
name: dynamic-verification
description: Optional runtime pass that confirms or refutes static security findings against a RUNNING instance of the app using the Playwright browser. Actively probes live security headers, CORS, routes reachable without authentication, IDOR (object-level authorization), and reflected XSS, then labels findings Confirmed (with reproduction evidence) or Refuted. Use only after a static audit when a running app URL is available AND the user has authorized active testing of their own app. Read-only by default.
license: MIT
---

# Dynamic Verification (Playwright)

Static reading finds *suspected* issues; it cannot tell you whether the running app is actually
exploitable. This skill closes that gap: it drives a real browser (the Playwright MCP) against a
running instance to **confirm or refute** a defined set of findings, turning "suspected" into
"Confirmed" with reproduction steps — or dropping it. This cuts false positives and the effort
spent arguing, from code alone, about whether a finding is real.

It is a complement to the static skills, not a replacement. Run it *after* `secaudit:audit` (or a
domain skill) has produced candidate findings.

## ⛔ Authorization gate — do this first, every time

Active testing sends real requests to a live system. Before any navigation or request, confirm
**all** of the following with the user, and stop if any is not met:

1. **Ownership / permission** — the target is the user's own app, or they have explicit written
   authorization to test it. Never probe a third party's site.
2. **Environment** — prefer a local, staging, or non-production instance. If production is the
   only option, the user must explicitly accept that and understand the probes below.
3. **Scope** — confirm the base URL(s) in scope and any that are off-limits.
4. **Test credentials** — for authenticated probes (IDOR), the user provides two low-value test
   accounts they own. Never test with real users' data.

State the confirmed scope in one line before starting. If the user cannot authorize, do **not**
run this skill — report the static findings as "Needs verification" instead.

## Guardrails (what this skill will not do)

- **Read-only by default.** No create/update/delete probes, no writes, no destructive actions
  unless the user explicitly asks and the target is non-production.
- **No load/DoS testing** and no automated exploit-chain generation or credential brute-forcing.
- **No data exfiltration.** Confirming IDOR means observing that *access is possible* to one test
  object you own — not dumping other users' data.
- One request at a time, low volume. You are demonstrating a vulnerability, not attacking.

## When to Use

- After a static audit, to verify findings against a running instance the user controls.
- When a finding's severity hinges on runtime behaviour (is the header actually missing? does the
  payload actually execute? is the route actually reachable unauthenticated?).
- The static verification pass in `secaudit:audit` tagged something **Needs verification** and a
  running app is available to settle it.

## The probe set

Each probe maps back to a static domain and to an OWASP WSTG test. Concrete Playwright MCP recipes
are in `./references/probes.md`. Summary:

| Probe | Confirms a finding from | What it checks |
|-------|------------------------|----------------|
| Security headers | `secaudit:deployment` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options present on live responses |
| CORS | `secaudit:deployment`, `secaudit:web-vulns` | Does the server reflect an arbitrary `Origin` / allow credentials cross-origin |
| Unauthenticated routes | `secaudit:auth`, `secaudit:privilege-escalation` | Do protected pages/APIs respond with data when no session is present |
| IDOR / object-level auth | `secaudit:web-vulns`, `secaudit:privilege-escalation` | Can test account A read account B's object by changing an id |
| Reflected XSS | `secaudit:web-vulns` | Is an injected marker reflected unescaped and executed in the DOM |

## Output — Confirmed vs Refuted

For each finding you probe, report a verdict:

- **Confirmed** — the probe reproduced the issue. Give the exact request/URL, the observed
  response (status, relevant header, or DOM evidence), and the reproduction steps. Keep the
  static skill's severity and before/after fix.
- **Refuted** — the running app already handles it (a compensating control fired: header present,
  CORS not reflected, route returned 401/redirect, ownership enforced, payload escaped). Drop the
  finding or downgrade it, and say what you observed that cleared it.
- **Inconclusive** — could not set up the preconditions (e.g. no second test account). Keep it as
  "Needs verification" and say what would settle it.

Fold these verdicts back into the audit report so the user sees which suspected issues are real.

## References

- `./references/probes.md` -- Concrete Playwright MCP recipes for each probe (headers, CORS,
  unauthenticated routes, IDOR, reflected XSS), each mapped to its OWASP WSTG test id.

## Sources

- https://owasp.org/www-project-web-security-testing-guide/latest/ -- OWASP Web Security Testing Guide (WSTG)
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security -- WSTG HSTS test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing -- WSTG CORS test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References -- WSTG IDOR test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting -- WSTG reflected XSS test
