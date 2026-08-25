---
name: dynamic-verification
description: Optional runtime pass that confirms or refutes static security findings against a RUNNING app or container. Two probe families - browser probes via Playwright (live security headers, CORS, routes reachable without authentication, IDOR, reflected XSS) and container probes via the local Docker CLI (secrets in image layers, root containers, docker.sock mounts, ports published on 0.0.0.0, missing runtime hardening). Labels each finding Confirmed with reproduction evidence, or Refuted. Use after a static audit when a running instance or container is available AND the user has authorized testing of their own system. Read-only.
license: MIT
---

# Dynamic Verification

Static reading finds *suspected* issues; it cannot tell you whether the running system actually
behaves that way. This skill closes that gap and **confirms or refutes** findings against a live
instance, turning "suspected" into "Confirmed" with reproduction steps — or dropping it. That
cuts false positives and the effort spent arguing, from code alone, about whether a finding is
real.

Two probe families, with **different risk profiles and different authorization gates**:

- **Browser probes** (Playwright MCP) — active requests against a running web app. Governed by
  the full gate below.
- **Container probes** (local Docker CLI) — read-only inspection of the user's own Docker daemon.
  No requests reach the application. Governed by the reduced gate.

It is a complement to the static skills, not a replacement. Run it *after* `secaudit:audit` (or a
domain skill) has produced candidate findings.

## When to Use

- After a static audit, to verify findings against a running instance the user controls.
- The project is containerised and the container is running, so `secaudit:docker-security`
  findings can be confirmed or refuted against the live daemon.
- When a finding's severity hinges on runtime behaviour (is the header actually missing? does the
  payload actually execute? is the route actually reachable unauthenticated?).
- The static verification pass in `secaudit:audit` tagged something **Needs verification** and a
  running app is available to settle it.

## ⛔ Authorization gate (browser probes) — do this first, every time

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

## Authorization gate (container probes) — reduced, and here is why

Container probes are **local, read-only inspection of the user's own Docker daemon**. Nothing is
sent to the application, nothing is injected, nothing is written. Applying the full network-probe
gate above to them would be theatre — and a gate people learn to click past is worse than no
gate, because it erodes the one that matters.

Confirm three things, then proceed:

1. **The daemon and containers are the user's own**, on this machine. Never probe a remote or
   shared Docker host.
2. **Never `docker run` an image the user did not build.** One probe starts a container; it must
   use `--rm`, an overridden entrypoint, and `--network none`.
3. **Redact.** `docker inspect` output contains live credentials — `.Config.Env` is exactly where
   the secrets from `secaudit:docker-security` live. Report *that* a credential is exposed and
   name the variable; **never reproduce its value** in the report, the transcript, or a log.

## Guardrails (what this skill will not do)

- **Read-only by default.** No create/update/delete probes, no writes, no destructive actions
  unless the user explicitly asks and the target is non-production.
- **No load/DoS testing** and no automated exploit-chain generation or credential brute-forcing.
- **No data exfiltration.** Confirming IDOR means observing that *access is possible* to one test
  object you own — not dumping other users' data.
- One request at a time, low volume. You are demonstrating a vulnerability, not attacking.
- **Container probes never mutate.** No `docker start/stop/rm`, no writes into a container, no
  `docker exec` beyond `id`. One probe starts a throwaway container from an image the user built;
  it uses `--rm --network none` and an overridden entrypoint.
- **Never print a secret value.** Several `docker inspect` fields carry live credentials; report
  the variable name and the fact of exposure, never the value.


## Browser probes

Each probe maps back to a static domain and to an OWASP WSTG test. Concrete Playwright MCP recipes
are in `./references/probes.md`. Summary:

| Probe | Confirms a finding from | What it checks |
|-------|------------------------|----------------|
| Security headers | `secaudit:deployment` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options present on live responses |
| CORS | `secaudit:deployment`, `secaudit:web-vulns` | Does the server reflect an arbitrary `Origin` / allow credentials cross-origin |
| Unauthenticated routes | `secaudit:auth`, `secaudit:privilege-escalation` | Do protected pages/APIs respond with data when no session is present |
| IDOR / object-level auth | `secaudit:web-vulns`, `secaudit:privilege-escalation` | Can test account A read account B's object by changing an id |
| Reflected XSS | `secaudit:web-vulns` | Is an injected marker reflected unescaped and executed in the DOM |

## Container probes

Each confirms a specific `secaudit:docker-security` finding. All are read-only.

| Probe | Confirms | Command |
|-------|----------|---------|
| Secrets in image layers | §1 | `docker image history --no-trunc <img>` |
| `.env` / `.git` in the image | §2 | `docker run --rm --network none --entrypoint sh <img> -c 'ls -a /'` |
| Runs as root | §3 | `docker exec <c> id` |
| Base image not digest-pinned | §4 | `docker image inspect -f '{{.RepoDigests}}' <img>` |
| Docker socket mounted in | §5 | `docker inspect -f '{{json .Mounts}}' <c>` |
| Published on 0.0.0.0 | §6 | `docker inspect -f '{{json .NetworkSettings.Ports}}' <c>` · `ss -lntp` |
| Credentials in env | §7 | `docker inspect -f '{{json .Config.Env}}' <c>` |
| No runtime hardening | §8 | `docker inspect -f '{{.HostConfig.Privileged}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}' <c>` |

Runtime evidence cuts **both** ways here, which is the reason to run these at all:

- **Confirms what static cannot see.** A `USER` directive can be overridden by
  `docker run --user`, and a compose file with no `ports:` says nothing about a container someone
  started by hand with `-p`. `docker exec <c> id` returning `uid=0`, or a `0.0.0.0` binding in
  `NetworkSettings.Ports`, settles it.
- **Refutes false positives.** An `ARG NPM_TOKEN` in the Dockerfile looks damning, but if CI
  passed the value as a BuildKit secret, `docker image history` shows no value and the finding is
  **Refuted**. Likewise a digest in `RepoDigests` refutes an "unpinned base image" finding even
  when the `FROM` line carries only a tag.

A probe that cannot run (daemon not running, container not started, image not built locally) is
**Inconclusive**, not Refuted — say which, and what would settle it.

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
