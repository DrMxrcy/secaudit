---
id: 28
title: Add mcp-agent-security skill
type: feature
version: 3.6.0
status: done
created: 2026-08-24
---

# ✨ Plan 28: Add mcp-agent-security skill

> Type: feature · Target: v3.6.0

## 🎯 Target Scope & Boundaries

`ai-integration` carries a `## MCP (Model Context Protocol) Security` section covering tool
poisoning, omnibus scopes, MCP + `service_role` bypassing RLS, token passthrough, confused deputy,
SSRF via OAuth metadata URLs, state-handle hijacking, and prompt injection via MCP inputs. That is
the right depth for "you have an LLM app and you connected a couple of MCP servers".

It is **not** enough for a project that *builds an agent* or *hosts an MCP server*, and that gap
has grown: v3.5.0 added the chat/RAG application layer, and the MCP spec went stateless in the
2026-07-28 revision, which invalidated a whole class of session-based advice.

The new skill is the depth `ai-integration`'s MCP section points at. Where the two overlap it
goes a level deeper and cross-references rather than restating.

### Spine

1. **Authorization is per-tool-call, not per-session.** An agent loop that authenticates once and
   then makes N tool calls has one authorization decision for N privileged actions.
2. **Confused deputy in agent architectures.** The agent holds credentials the user does not, so
   anything that steers the agent is an instruction to spend them. Per-tool least privilege and
   downstream tokens scoped to the end user, rather than one omnibus service token.
3. **Human-in-the-loop that actually gates.** Approving a model-written summary, or a whole plan
   rather than each irreversible call, is theatre. Show the literal arguments.
4. **Tool result provenance and injection laundering.** Chained tools launder injected
   instructions: retrieved doc → summarise → the summary is now "the assistant's own words".
5. **MCP server implementation** — the side `ai-integration` does not cover at all: server-side
   input validation rather than trusting the client's schema, not trusting the calling model's
   claimed identity, per-tool authorization inside the handler, resource/URI traversal in resource
   handlers, per-caller rate limits.
6. **Agent memory and state poisoning.** An injection written into persisted memory once executes
   on every subsequent run, and contaminates other users if memory is shared.
7. **Autonomy and blast radius.** Unbounded steps, self-invoking loops, agents that spawn agents,
   agents with write access to their own tool list. Denial-of-wallet at agent scale.
8. **Auditability.** Caller identity, literal arguments, and the decision — what makes an agent
   incident investigable at all.

**Out of scope:** rewriting `ai-integration`'s MCP section (it stays as the entry point), and
prompt-injection fundamentals (already owned there).

## ⚠️ Accuracy constraints carried into this item

Everything learned the hard way in v3.4.0–v3.6.0 applies, and the freshness check now enforces
most of it:

- MCP spec revision is **2026-07-28**; the 2025-11-25 revision is archived. **MCP is stateless
  with no protocol-level sessions**, so any advice about securing MCP session IDs describes a
  feature that no longer exists.
- OWASP **LLM** categories by **name, not number** — the 2026 renumbering could not be verified
  from a primary source (the PDF is access-gated), so numbers must not be asserted.
- OWASP **web** categories use 2025 numbering with the year.
- No invented CVE IDs; no `pkg@x.y.z` presented as an upgrade target.
- Every cited URL must return 200 **without a redirect** — `scripts/check-freshness.py` fails the
  build otherwise, which is how the four `www.better-auth.com` 307s and one 404 were caught in
  v3.5.0.

## 🏗️ Architectural Blueprint

- **New:** `skills/mcp-agent-security/SKILL.md`.
- **Modified:** `skills/ai-integration/SKILL.md` — its MCP section gains a pointer to the deeper
  skill, so the two do not drift into duplicates.
- **Modified:** `skills/audit/SKILL.md` — conditional tier-2 dispatch when the project defines
  MCP servers or an agent loop, plus the OWASP map.
- **Modified:** `SOURCES.md` and `.claude-plugin/plugin.json` keywords.

## ✅ Acceptance

- No duplication of `ai-integration`'s MCP section; overlap is deeper plus a cross-reference.
- No MCP session-ID advice anywhere in the file.
- LLM categories cited by name only.
- `python3 scripts/check-freshness.py` exits 0.
- The skill fires on a project that hosts an MCP server, not only one that consumes them.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Write `skills/mcp-agent-security/SKILL.md` -> target: new file
- [x] Step 2: Add the pointer from `ai-integration`'s MCP section -> target:
  `skills/ai-integration/SKILL.md`
- [x] Step 3: Register in the audit dispatch tiers and OWASP map -> target: `skills/audit/SKILL.md`
- [x] Step 4: Add sources and plugin keywords -> target: `SOURCES.md`,
  `.claude-plugin/plugin.json`
- [x] Step 5: Verify — frontmatter valid, cross-references resolve, no session-ID advice, no bare
  LLM numbers, freshness check exits 0 -> target: manual verification
