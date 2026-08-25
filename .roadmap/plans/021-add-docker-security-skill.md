---
id: 21
title: Add docker-security skill
type: feature
version: 3.5.0
status: done
created: 2026-08-24
---

# Plan 21: Add docker-security skill
> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

New `skills/docker-security/` — `grep -riE "docker|container|compose" skills/` returned
**nothing**. `deployment` was entirely Vercel/serverless.

Eight sections. The one most worth having: **a `:ro` docker.sock mount is not read-only in any
meaningful sense** — read-only applies at the filesystem layer while the Docker API is spoken over
the socket, so `:ro` grants full API write access while reading as safe.

**Out of scope:** merging into `deployment`; the trigger (file presence vs Vercel config) and the
threat model are orthogonal, and it would have tripled that skill.

## 🏗️ Architectural Blueprint

- **New:** `skills/docker-security/SKILL.md` (568 lines, 8 sections + checklist).
- **Modified:** `audit` Tier 2 entry, OWASP A02:2025 map, plugin keywords, `SOURCES.md`.
- Framing decisions: unpinned base images presented as the container twin of the npm
  unpinned-dependency problem `supply-chain` owns; compose-literal credentials as the container
  shape of the default-credentials pattern `secrets` greps for.
- Also documents that Docker's iptables rules bypass UFW, so a "closed" port may not be.

## ✅ Acceptance

- **Passes when:** the skill fires on a `Dockerfile` or compose file and covers layer secrets,
  `.dockerignore`, root containers, pinning, socket mounts, `0.0.0.0` binds, compose creds, and
  runtime hardening.
- **Fails if:** any example contains a real-looking base-image digest someone could copy.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write the skill -> target: `skills/docker-security/SKILL.md`
- [x] Step 2: Register in the audit tiers and the OWASP A02:2025 row
- [x] Step 3: Add sources and plugin keywords
- [x] Step 4: Verify — placeholder digest is obviously fake, freshness check green
