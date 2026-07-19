---
id: 6
title: Redact secrets in audit output (Snyk W007)
type: bug
version: 3.2.0
status: done
created: 2026-07-19
---

# Plan 6: Redact secrets in audit output (Snyk W007)
> Type: bug · Target: v3.2.0

## 🎯 Target Scope & Boundaries
- **The bug:** The skills instruct the model to report the file, relevant lines, and a "before"
  snippet for each finding. For the secrets / cryptography / supply-chain skills, that "before"
  snippet can be a *real hardcoded credential* from the user's code — so the audit output itself
  repeats the secret verbatim into the transcript, logs, or a PR comment. The skill.sh Snyk audit
  flags this as **HIGH / W007 — Insecure credential handling in the skill instructions**
  (analyzed Mar 15, 2026). There is currently no redaction rule anywhere in the skills.
- **The fix:** Add a mandatory redaction rule to the reporting instructions: never reproduce a
  discovered secret, token, key, or full credential string. Identify the finding by location
  (file + line) and a masked form (e.g. `sk_live_…REDACTED`, `***`, or at most the last 4 chars),
  and describe the vulnerable *pattern* rather than pasting the sensitive literal. The rule must be
  present both in the orchestrator (full sweeps) and in the domain skills that fire independently
  and are most likely to encounter literal secrets.
- **Out of scope:** Changing the finding/severity model or the before/after format for
  *non-secret* code fixes (those examples use the skill's own placeholder values and are fine).
  This is about never echoing the *user's* real secret values.

## 🏗️ Architectural Blueprint
- **Files to modify:**
  - `skills/audit/SKILL.md` — add a Redaction rule to **Core Instructions** and reinforce it in
    the **Output Format** step that says "state the file and relevant line(s)".
  - `skills/secrets/SKILL.md` — add the redaction rule (this skill fires independently and is the
    one that hunts hardcoded keys/tokens).
  - `skills/cryptography/SKILL.md` — short redaction note (hardcoded keys/IVs).
  - `skills/supply-chain/SKILL.md` — short redaction note (JWT secrets, default credentials).
- **Schema/interface changes:** None. Wording-only change to instructions.
- **Downstream impact:** Audit reports mask secret values; alignment with Snyk W007 so a re-run
  clears cleanly.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Add the mandatory Redaction rule to the orchestrator Core Instructions and the
  Output Format reporting step -> target: `skills/audit/SKILL.md`
- [x] Step 2: Add the redaction rule to the secrets skill's reporting guidance -> target: `skills/secrets/SKILL.md`
- [x] Step 3: Add a short redaction note to cryptography and supply-chain -> target: `skills/cryptography/SKILL.md`, `skills/supply-chain/SKILL.md`
- [x] Step 4: Verify no instruction anywhere tells the model to paste a real secret value, and the
  rule reads consistently across the four files -> target: manual verification
