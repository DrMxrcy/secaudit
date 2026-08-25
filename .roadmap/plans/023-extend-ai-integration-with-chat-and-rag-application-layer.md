---
id: 23
title: Extend ai-integration with chat and RAG application layer
type: feature
version: 3.5.0
status: done
created: 2026-08-24
---

# Plan 23: Extend ai-integration with chat and RAG application layer
> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

Extend `ai-integration` with the chat/RAG application layer. Verified absent:
`grep -riE "retriev|thread|conversation|streamtext|usechat"` across `skills/` returned nothing but
the word "RAG" in one bullet.

Nine gaps. The one that required a **rewrite** rather than an addition: the existing
Tool/Function Calling section said "validate parameters against a schema" — correct but
insufficient, because **the schema is the wrong place for identity**. A `userId` in `inputSchema`
means the model supplies it, which means the user's prompt supplies it.

**Out of scope:** splitting chat into its own skill — indirect injection and RAG retrieval are the
same threat and must be read together.

## 🏗️ Architectural Blueprint

- **Modified:** `skills/ai-integration/SKILL.md` only (+~190 lines), reordered so the flow reads
  Prompt Injection → Chat Application Layer → RAG Retrieval → Tool Calling → Output → Telemetry.
- New: client-supplied conversation history (forged *tool results* bypass earlier turns' checks),
  chat-thread IDOR, client-supplied model/system prompt, RAG retrieval without an ACL filter,
  AI telemetry recording full prompts to third parties.
- Extended: the concrete XSS vector (markdown renderers with raw HTML enabled, reached via
  poisoned RAG documents) and the `onError` un-masking regression, where a secure-by-default
  error mask is disabled by a documented troubleshooting snippet.
- Notes AI SDK v4 vs v5+ field renames so detection greps cover both spellings.

## ✅ Acceptance

- **Passes when:** the tool-calling section states identity must close over the session, not
  appear in the schema.
- **Fails if:** MCP content is duplicated — that section stays the entry point.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Add the chat, RAG, output and telemetry material and rewrite tool calling
  -> target: `skills/ai-integration/SKILL.md`
- [x] Step 2: Reorder sections, widen the description, add sources and the SDK-version note
