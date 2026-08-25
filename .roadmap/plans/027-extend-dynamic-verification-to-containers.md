---
id: 27
title: Extend dynamic-verification to containers
type: feature
version: 3.6.0
status: done
created: 2026-08-24
---

# ✨ Plan 27: Extend dynamic-verification to containers

> Type: feature · Target: v3.6.0

## 🎯 Target Scope & Boundaries

`docker-security` (v3.5.0) produces eight classes of finding entirely from reading `Dockerfile`
and compose files. Several of them are **cheaply and decisively confirmable at runtime**, and in
two cases the static read is genuinely ambiguous:

- A `USER` directive can be present and still be overridden by `docker run --user`, or the image
  can `USER root` in a later stage. Static says "probably fine"; `docker exec <c> id` says `uid=0`
  or it doesn't.
- A compose file may declare no `ports:` while the container was started manually with `-p`.
  Static reads clean; the host is listening on `0.0.0.0`.

The other direction matters too: an image built from a Dockerfile with `ARG NPM_TOKEN` may have
had the value passed as a build secret in CI, so the static finding is a false positive that
`docker image history` immediately refutes.

### Probes to add

| Probe | Confirms a finding from | Command |
|---|---|---|
| Secrets in image layers | `docker-security` §1 | `docker image history --no-trunc <img>` |
| `.env` / `.git` in the image | §2 | `docker run --rm --entrypoint sh <img> -c 'ls -a /'` |
| Container runs as root | §3 | `docker exec <c> id` |
| Base image not digest-pinned | §4 | `docker image inspect -f '{{.RepoDigests}}' <img>` |
| Docker socket mounted in | §5 | `docker inspect -f '{{json .Mounts}}' <c>` |
| DB/cache published on 0.0.0.0 | §6 | `docker inspect -f '{{json .NetworkSettings.Ports}}' <c>`, `ss -lntp` |
| Credentials visible in env | §7 | `docker inspect -f '{{json .Config.Env}}' <c>` |
| No runtime hardening | §8 | `docker inspect -f '{{.HostConfig.Privileged}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}' <c>` |

## ⚠️ Risk class differs from the existing probes — say so explicitly

The skill's current authorization gate is written for **active network testing against a live web
app**: it asks about production, scope URLs, and test credentials, because those probes send
attacker-shaped requests to a running service.

Container probes are a different class: **local, read-only inspection of the user's own Docker
daemon**. No requests are sent to the application, nothing is injected, and nothing is written.
Applying the full network-probe gate to them would be security theatre that trains people to
click past the gate — the same false-positive-fatigue failure mode the freshness checker is
designed around.

But they are not free either, and two carry real risk that must be stated:

1. **`docker inspect` output contains live secrets.** `.Config.Env` is exactly where the
   credentials from `docker-security` §7 live. The existing redaction rule (item #6, "Redact
   secrets in audit output") applies with full force — the probe must report *that* a credential
   is exposed, never its value.
2. **`docker run` on an unknown image executes that image.** The `.env`/`.git` probe starts a
   container. Override the entrypoint, use `--rm`, no network, and never run an image the user
   did not build.

So: a **reduced gate** for container probes (confirm the daemon and containers belong to the
user; do not run untrusted images; redact), while the existing full gate continues to govern the
network probes.

**Out of scope:** starting, stopping, or modifying containers; `docker exec` of anything beyond
`id`; scanning images with third-party tools; any probe against a remote Docker daemon.

## 🏗️ Architectural Blueprint

- **Modified:** `skills/dynamic-verification/SKILL.md` — the skill is currently framed as
  Playwright-only ("drives a real browser"). Reframe as runtime verification with **two probe
  families** (browser probes, container probes), add the container probe table, and add the
  reduced gate.
- **Modified:** its `description` frontmatter, so it fires for a containerised project even when
  no browser is involved.
- **Modified:** `skills/docker-security/SKILL.md` — a pointer that these findings can be
  confirmed at runtime.
- **Modified:** `skills/audit/SKILL.md` — the optional final phase currently says "a running
  instance of the app"; widen to include a running container.

## ✅ Acceptance

- Every probe command is read-only and runs against the local daemon only.
- The redaction requirement is stated on the two probes that surface secrets.
- The reduced gate is clearly separated from the existing network-probe gate, with the reason.
- Each probe names the `docker-security` section it confirms, and states what a **Refuted**
  result looks like — not just a confirmation.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Reframe the skill around two probe families and widen the description
  -> target: `skills/dynamic-verification/SKILL.md`
- [x] Step 2: Add the container probe table with Confirmed/Refuted criteria per probe
  -> target: `skills/dynamic-verification/SKILL.md`
- [x] Step 3: Add the reduced authorization gate, with the redaction and untrusted-image rules
  -> target: `skills/dynamic-verification/SKILL.md`
- [x] Step 4: Cross-reference from `docker-security` and widen the audit final phase
  -> target: `skills/docker-security/SKILL.md`, `skills/audit/SKILL.md`
- [x] Step 5: Verify — every command is read-only, docker-security section numbers referenced
  actually exist, and the freshness check still exits 0 -> target: manual verification
