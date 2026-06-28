---
name: ai-integration
description: Audits AI/LLM integration security — keeping AI API keys server-side, hard spending caps and per-user usage limits (denial-of-wallet), prompt injection (direct, indirect, and tool/agent-based), treating LLM output as untrusted, and MCP (Model Context Protocol) risks like tool poisoning, over-permissioned scopes, and token passthrough. Use whenever the app calls an LLM API, builds an agent or chatbot, uses function/tool calling, or connects MCP servers. Maps to the OWASP LLM Top 10.
license: MIT
---

# AI / LLM Integration Security

## When to Use

- The app calls an LLM API (OpenAI, Anthropic, Google, etc.).
- Building a chatbot, agent, RAG pipeline, or function/tool-calling flow.
- Connecting or configuring MCP servers/connectors.
- Auditing for leaked AI keys, runaway spend, prompt injection, or unsafe output.

Maps to the OWASP Top 10 for LLM Applications (2025).

## API Keys Are Server-Side Only

AI API keys (OpenAI, Anthropic, Google, etc.) must never appear in client-side code. They allow
unlimited API usage at your expense. A leaked key can drain thousands of dollars in minutes.

- No `NEXT_PUBLIC_OPENAI_API_KEY`
- No API keys in React Native / Expo bundles
- No API keys in client-side JavaScript

All AI API calls go through your backend. The client sends the user's message to your server; your
server calls the AI API. (See `secaudit:secrets`.)

## Unbounded Consumption / Spending Caps (OWASP LLM10)

Set hard spending caps on every AI API provider:
- OpenAI: Usage limits in dashboard
- Anthropic: Spending limits in console
- Google: Budget alerts in Cloud Console

Also implement **per-user usage limits** in your application — provider caps alone leave you open
to denial-of-wallet:
- Track token usage per user in your database
- Set daily/monthly caps per user or per tier
- Return a clear error when limits are exceeded
- Pair with rate limiting (see `secaudit:rate-limiting`)

## Prompt Injection (OWASP LLM01 — the #1 risk)

User input must be treated as untrusted before it reaches a prompt. Never concatenate raw user
input into system prompts:

```typescript
// BAD: user can override system instructions
const prompt = `You are a helpful assistant. User says: ${userInput}`;

// BETTER: separate system and user messages
const messages = [
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user', content: userInput },
];
```

Three forms to defend against:
- **Direct** — user input says "ignore previous instructions."
- **Indirect** — malicious instructions hidden in fetched web pages, files, emails, or repos the
  model later processes. Segregate and clearly mark untrusted external content.
- **Agentic / tool-based** — injection drives the model to call tools (query private data, send
  email, run commands). Use least-privilege tool access and require human approval for high-risk
  operations.

For high-stakes applications: validate output with deterministic code before acting on it, limit
the LLM's capabilities (no tool access for user-facing chat), and adversarially test.

## LLM Output Is Untrusted

LLM responses should be treated as untrusted user input:

- **Sanitize before rendering as HTML** — LLM output can contain script tags or event handlers
- **Never execute LLM output as code** without sandboxing
- **Validate tool/function call parameters** — if using function calling, validate all returned
  parameters against an allowlist and schema before executing

## Tool / Function Calling

If your application gives an LLM access to tools (database queries, API calls, file operations):
- Restrict operations to a safe allowlist
- Validate all parameters from the LLM against a schema
- Use least-privilege access (read-only where possible)
- Log all tool invocations for audit
- Never let the LLM construct raw SQL or shell commands from user input

## MCP (Model Context Protocol) Security

MCP connectors give AI agents access to external services (Supabase, GitHub, Slack, etc.). This is
powerful but creates new attack surfaces.

### Tool poisoning / shadowing

A malicious tool's *description or metadata* can manipulate the model — a semantic attack that
bypasses signature checks. Vet the tools an MCP server exposes, not just the server binary.

### Over-permissioned / omnibus scopes

One token granting `files:*`, `db:*`, `admin:*` creates a huge blast radius and makes the MCP
server a single point of failure across every connected service. Use least-privilege, progressive
scopes — never omnibus scopes.

### MCP + service_role = Bypassed RLS

If your MCP connector uses the Supabase `service_role`/secret key, the agent bypasses ALL
Row-Level Security. A prompt injection hidden in a code comment, README, or package description the
agent reads can instruct it to exfiltrate data. Use read-only credentials, never give production
write access, and review every operation before approving it. (See `secaudit:database`.)

### Protocol-level footguns

- **Token passthrough is forbidden** — an MCP server must reject tokens that were not issued to it.
- **Confused deputy** — enforce per-client consent, exact `redirect_uri` matching, and single-use
  `state` on OAuth proxy flows.
- **SSRF via OAuth metadata URLs** — block private/link-local ranges (e.g. `169.254.169.254`);
  HTTPS-only; reject `javascript:`/`file:` schemes.
- **Session hijacking** — use non-deterministic session IDs bound to the user; never use sessions
  for auth.
- **Local server compromise** — sandbox local MCP servers and show the exact startup command
  before execution.

### Prompt injection via MCP inputs

Content returned by MCP tools (file contents from GitHub, messages from Slack) can contain
adversarial instructions. The agent may follow them because it treats tool results as trusted
context. Don't auto-execute code or commands suggested by retrieved content; use separate MCP
configurations for development and production.

## AI Billing Protection

Beyond per-provider spending caps, implement application-level controls:

- **Per-user token budgets** stored server-side (not in client-accessible tables)
- **Request-level cost estimation** before making expensive API calls
- **Circuit breakers** — if total API spend exceeds a threshold in a short window, halt all AI
  calls and alert
- **Separate API keys** for development and production — a dev key leak shouldn't drain your
  production budget

## Sources

- https://genai.owasp.org/llm-top-10/ -- OWASP Top 10 for LLM Applications (2025)
- https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ -- official 2025 list/PDF
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices -- MCP security best practices
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization -- MCP token-audience binding (no passthrough)
