---
id: 29
title: Parallel subagent fan-out for whole-app audits
type: feature
version: 3.7.0
status: done
created: 2026-08-25
---

# ✨ Plan 29: Parallel subagent fan-out for whole-app audits

> Type: feature · Target: v3.7.0

## 🎯 Target Scope & Boundaries

### The observed failure

A real whole-app sweep (Expo + Convex + Clerk + RevenueCat + R2) ran the entire audit inline in
one context and reported: *"Did not line-by-line read all 104 Convex modules, the watch Swift
targets, widgets/, ml/, or scripts/ … sampled by pattern, not exhaustively."*

That caveat is honest, and it is the symptom. The audit found no confirmed vulnerabilities — but
on a codebase where the majority of the Convex modules were never read, "no findings" and "not
looked at" are indistinguishable to the reader.

### Root cause — a missing feature, not a regression

`git log -S "subagent"` and `-S "parallel"` over `skills/audit/SKILL.md` both return **nothing
across its entire history**. Fan-out was never instructed. The word "dispatch" appears six times
and has always meant *"apply that domain skill"*, which a model correctly reads as "load it and
continue in this context".

The arithmetic now makes that untenable. The skill set is **6,201 lines across 24 skills**, and a
whole-app sweep on a modern stack pulls in ~16 of them — roughly 3,000 lines of skill text before
a single line of the target codebase is read. One context cannot hold that plus 104 Convex
modules, so it samples. The skill grew past the delivery mechanism.

### Use the project's own agents

The environment already defines specialised agents with deliberate model assignments, and they
map onto the audit's existing phases almost exactly:

| Agent | Model | Phase |
|---|---|---|
| `scout` | haiku | Recon — enumerate entry points, routes, modules. Cheap, high volume. |
| `security-executor` | opus | One per domain. Loads only its own skill, reads exhaustively. |
| `verifier` | opus | Fresh-context adversarial check of each candidate finding. |

The skill must **discover** these rather than hardcode them: probe `.claude/agents/` in the
project, then `~/.claude/agents/`, and fall back to a general-purpose agent when none match. A
project with its own security agent should get that agent.

`verifier` matters as much as the fan-out. The observed run refuted a false positive well (`ws`
flagged at the range spec, resolved 8.21.0 in the lockfile), but did so in the same context that
raised it. Fresh-context verification is what makes a refutation trustworthy, and it is what the
existing "evidence-backed findings (anti-hallucination)" work (item #10) was reaching for.

### Scope

- Whole-app sweeps fan out **by default**; the user can say "inline" to opt out.
- Narrow scopes (single domain, named surface, diff/PR) stay inline — fan-out costs more than the
  work for those, and the existing `Scope Control` section already handles them correctly.
- Each worker reports **what it read and what it skipped**, so coverage is mechanical and
  per-domain rather than one hedge at the end.
- After the static sweep, **offer** dynamic verification rather than waiting to be asked. It is
  opt-in by design and correctly did not run in the observed sweep, but in practice that means it
  never runs.

**Out of scope:** changing any domain skill's content; making dynamic verification automatic (the
authorization gate stays); parallel *writes* of any kind.

## 🏗️ Architectural Blueprint

- **Modified:** `skills/audit/SKILL.md` — new `## Execution model` section between
  `Scope Control` and `Reconnaissance`, covering agent discovery, the three phases, the per-worker
  report contract, and the inline fallback.
- **Contract for each domain worker** — must return: findings (file:line, severity, evidence,
  suggested fix), **files read**, **files deliberately skipped and why**, and explicit "no finding"
  statements for checks that passed. A silent absence is not a pass.
- **Parent responsibilities:** de-duplicate across domains (one root cause surfacing in three
  domains is one finding), build attack chains (existing item #8), apply the severity model, and
  own the final report. Workers never write to the report directly.
- **Why the parent must not also audit:** if the parent reads code too, it reintroduces the
  context pressure the fan-out exists to remove.
- **Failure handling:** a worker that dies leaves its domain **unaudited, and the report must say
  so**. Silently dropping a domain is the same defect as sampling — it looks like a clean result.

## ✅ Acceptance

- A whole-app sweep spawns one worker per applicable domain, concurrently.
- Agent types are discovered, not hardcoded; a project defining its own security agent gets it.
- Falls back cleanly to inline execution when no subagent capability exists.
- Every domain in the final report carries an explicit coverage line.
- A dead or skipped worker is reported as unaudited, never as clean.
- Narrow and diff scopes still run inline.
- Dynamic verification is offered at the end of a static sweep.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Add the `## Execution model` section — agent discovery order, the three phases, and
  the inline fallback -> target: `skills/audit/SKILL.md`
- [x] Step 2: Define the per-worker report contract, including files-read / files-skipped and
  explicit pass statements -> target: `skills/audit/SKILL.md`
- [x] Step 3: Define parent-side synthesis — de-duplication, attack chains, severity, and the
  rule that a dead worker means the domain is unaudited -> target: `skills/audit/SKILL.md`
- [x] Step 4: Add fresh-context verification of candidate findings via a verifier agent, and wire
  it to the existing evidence/anti-hallucination rules -> target: `skills/audit/SKILL.md`
- [x] Step 5: Make the static sweep offer dynamic verification at the end -> target:
  `skills/audit/SKILL.md`
- [x] Step 6: Verify — the coverage-gap phase still holds, `Scope Control` still routes narrow
  scopes inline, cross-references resolve, and the freshness check exits 0 -> target: manual
  verification
