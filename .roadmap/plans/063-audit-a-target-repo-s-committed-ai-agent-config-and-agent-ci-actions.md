---
id: 63
title: Audit a target repo's committed AI-agent config and agent CI actions
type: feature
version: 3.12.0
status: done
created: 2026-10-17
---

# Plan 63: Audit a target repo's committed AI-agent config and agent CI actions
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** the pack audits the AI-agent configuration a *target* repo commits (today: zero coverage — no hits for `.claude/settings`, `.mcp.json`, `AGENTS.md`, `bypassPermissions`, hidden Unicode). Primary source: OWASP Agentic Skills Top 10 v1.0-2026 (https://github.com/OWASP/www-project-agentic-skills-top-10 — AST01 malicious skills, AST02 supply chain, AST03 over-privileged, AST04 insecure metadata, AST05 untrusted external instructions, AST08 poor scanning); Check Point "Caught in the Hook" CVE-2025-59536 and CVE-2026-21852 (verify both on OSV/NVD and the Check Point URL before citing); ByteHide secure-env concept.
- **New section in mcp-agent-security** "Agent configuration committed to the repo", checks:
  1. Repo config runs as code on open: `.claude/settings.json` / `settings.local.json` `hooks` commands that fetch/exec; `env` overriding `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` (traffic + key redirection); `enableAllProjectMcpServers`, `enabledMcpjsonServers`. Commands: `jq '.hooks,.env,.enableAllProjectMcpServers,.enabledMcpjsonServers' .claude/settings*.json`.
  2. Over-broad permissions: `jq '.permissions'` — `Bash(*)`, `Bash(curl:*)`, unscoped `WebFetch`, `defaultMode: "bypassPermissions"`.
  3. MCP server inventory: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` — HTTP servers on non-HTTPS / unknown hosts, auth tokens hard-coded in `headers`, stdio `npx -y pkg` unpinned or `@latest`, scope mismatch vs upstream (fork republishing), `mcp-remote` version.
  4. Hidden instructions in agent files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/**`, `.github/copilot-instructions.md`, `.claude/**`): `grep -rnP '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{E0000}-\x{E007F}]'`, long base64 blobs, exfil hosts (`discord.com/api/webhooks`, `hooks.slack.com`, `api.telegram.org`), instructions to fetch-and-follow remote content.
  5. Skills/agents/commands bundled in the repo: `.claude/skills/**/scripts/*` with `curl … | sh`, `/dev/tcp/`, `base64 -d … | sh`, reads of `~/.ssh`, `~/.aws`, `.env`; frontmatter `allowed-tools` with bare `Bash`; agents with `tools: *`.
  6. Persistence: hooks/skills that write to `CLAUDE.md`/`AGENTS.md`/`MEMORY.md`.
- **ci-cd-security:** AI agent actions (`anthropics/claude-code-action`, `openai/codex-action`, `google-github-actions/run-gemini-cli`) triggered on `issues`/`issue_comment`/`pull_request_target` with secrets or write permissions — prompt injection from untrusted issue/PR text to repo write; require author-association gates, read-only tokens, no secrets on untrusted triggers. Verify action names exist before citing.
- **Out of scope:** registry signing schemes from AST10 that can't be checked in a web repo; how our own audit picks agents (plan 64).

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/mcp-agent-security/SKILL.md (new section + checklist lines + sources), skills/ci-cd-security/SKILL.md (AI agent action subsection), skills/audit/SKILL.md (dispatch mcp-agent-security when any of those files exist, not only when MCP servers/agent loops are in app code; OWASP map row), skills/supply-chain/SKILL.md (one pointer: MCP stdio packages are dependencies), SOURCES.md.

## ✅ Acceptance
- **Passes when:** all 6 checks have runnable commands; CVE IDs and URLs verified; audit dispatch triggers on `.claude/`, `.mcp.json`, `AGENTS.md`, `.cursor/`; ci-cd covers AI agent actions on untrusted triggers; freshness clean.
- **Fails if:** a cited CVE/URL does not resolve, or the hidden-Unicode grep is not valid for GNU/BSD grep (state `grep -P` needs GNU grep / `ggrep`, give a `perl -ne` fallback).

## 🚶 Step-by-Step Checklist
- [x] Step 1: Add "Agent configuration committed to the repo" section with checks 1-6 -> target: skills/mcp-agent-security/SKILL.md
  > evidence: check-freshness.py: All current; CVE-2025-59536/2026-21852/2026-33068, GHSA-ph6w, CVE-2025-6514 and all Claude Code keys verified; §9 blocks extracted and run on bad/good/edge fixtures (macOS + GNU container): all planted cases flagged, good fixture silent; spec MET; quality PARTIAL x2 -> fixed; implementer hit usage limit mid round 3, parent verified the final 4 regex fixes on the edge fixture (2026-10-18)
- [x] Step 2: Add AI agent GitHub Actions subsection -> target: skills/ci-cd-security/SKILL.md
  > evidence: check-freshness.py: All current; action inputs verified vs each action.yml/docs, pinned SHAs dereferenced; check block run on 14 fixtures; combined spec+quality review PARTIAL -> parent fixed workflow_run trigger, github_token in GOOD example, id-token prose, multi-line claude_args caveat; allowlisted research.checkpoint.com 202 bot challenge (2026-10-19)
- [x] Step 3: Audit dispatch + OWASP row, supply-chain pointer, SOURCES; freshness green -> target: skills/audit/SKILL.md, skills/supply-chain/SKILL.md, SOURCES.md
  > evidence: check-freshness.py: All current (github.com/advisories rate-limited = unreachable, not drift); audit dispatch fires on committed agent config and names §9; OWASP A02/A08 rows; supply-chain pointer; 34 sources mirrored; parent self-review of mechanical diff (2026-10-19)
