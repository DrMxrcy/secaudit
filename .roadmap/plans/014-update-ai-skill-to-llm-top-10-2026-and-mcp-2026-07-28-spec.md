---
id: 14
title: Update AI skill to LLM Top 10 2026 and MCP 2026-07-28 spec
type: bug
version: 3.4.0
status: done
created: 2026-08-21
---

# 🐛 Plan 14: Update AI skill to LLM Top 10 2026 and MCP 2026-07-28 spec

> Type: bug · Target: v3.4.0

## 🔍 Symptom & Reproduction

- **Observed:** `skills/ai-integration/SKILL.md` cites the OWASP LLM Top 10 **2025** edition and
  pins the MCP specification to revision **2025-11-25**. It also gives MCP advice about
  protocol-level sessions, which the current MCP revision no longer has.
- **Expected:** Citations track the current LLM Top 10 edition and MCP revision, and no advice
  references a protocol feature that has been removed.
- **Repro steps:** `grep -n "LLM10\|llm-top-10\|2025-11-25\|Session hijacking" skills/ai-integration/SKILL.md`,
  then compare against the upstream pages.

Verified upstream on 2026-08-21:

- **LLM Top 10 2026 exists and is published** — dated 2026-08-03, described by OWASP as
  introducing "updated rankings, expanded threat coverage". Confirmed via the WordPress REST
  record for the resource page (HTTP 200).
- **MCP revision 2026-07-28 exists** — `…/specification/2026-07-28/basic/authorization` returns
  200, and the security-best-practices page has moved to
  `…/docs/2026-07-28/tutorials/security/security_best_practices`. The old
  `…/specification/2025-11-25/basic/security_best_practices` URL now 301s to a `docs/2025-11-25/`
  path, marking it as an archived revision.

## 🩺 Root Cause

- **Culprit:** `skills/ai-integration/SKILL.md` (:3 description, :30 heading, :119 MCP session
  bullet, :144-147 sources) and `SOURCES.md` (:102-105).
- **Why:** Both upstreams are living documents on an annual/quarterly cadence. The skill cited
  them by edition-specific number and revision-pinned URL, so both went stale on publication of
  the next revision.

## ⚠️ Deliberate scope decision — cite by name, not by number

The OWASP 2026 PDF is behind an access gate ("No Access" on the download endpoint), and the
canonical `genai.owasp.org/llm-top-10/` landing page still renders the **2025** entries. The
specific 2026 renumbering could therefore **not** be verified against a primary source.

Rather than assert numbers that could not be checked, this plan references LLM categories by
**name** ("Unbounded Consumption") instead of by number ("LLM10"), and notes that the numbering
changed in the 2026 edition. Category names are stable across editions; numbers are not. This is
the same lesson plan 13 applied to the web Top 10, and it makes the file resistant to the next
renumbering rather than merely correct for one edition.

Anyone who later obtains the 2026 PDF can add exact numbers — but the skill must not depend on
them.

## ✅ Acceptance

- **Passes when:** no citation names the 2025 LLM edition as current, and no bare `LLMnn` number
  is presented as authoritative.
- **Passes when:** MCP links point at the 2026-07-28 revision and every rewritten URL returns 200.
- **Passes when:** the MCP session-hijacking bullet no longer instructs the reader to secure a
  protocol feature that current MCP does not have.
- **Fails if:** any specific 2026 category number is asserted without a verified primary source.

## 🛠️ Checklist

- [x] Step 1: Replace the `OWASP LLM10` heading reference with the category name plus an
  edition-independent note -> target: `skills/ai-integration/SKILL.md`
- [x] Step 2: Rewrite the MCP session-hijacking bullet for the current stateless model (server-
  minted state handles bound server-side to the authenticated user) -> target:
  `skills/ai-integration/SKILL.md`
- [x] Step 3: Update the LLM Top 10 and MCP source URLs in the skill and in `SOURCES.md` to the
  2026 edition / 2026-07-28 revision -> target: `skills/ai-integration/SKILL.md`, `SOURCES.md`
- [x] Step 4: Verify — every rewritten URL returns HTTP 200 and no `2025-11-25` or
  `owasp-top-10-for-llm-applications-2025` reference remains -> target: manual verification
