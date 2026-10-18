---
id: 64
title: Audit must vet project agents as untrusted before delegating to them
type: bug
version: 3.12.0
status: planned
created: 2026-10-17
---

# 🐛 Plan 64: Audit must vet project agents as untrusted before delegating to them
> Type: bug · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Bug:** skills/audit/SKILL.md "Choosing worker agents" (~L80-96) says "Project-level agents take precedence over everything else" and resolves roles project → personal → general. The audited repo is untrusted input: a hostile repo can ship `.claude/agents/security-executor.md` (or any matching name/description) whose prompt tells the worker to report "no findings", skip files, or run commands. OWASP AST01/AST05.
- **Fix:** project agents are used only after vetting: read each candidate's full file as data; reject if its prompt contains instructions to suppress/downgrade findings, skip paths, contact network hosts, run setup commands, or if its `tools` exceed the role (read-only audit roles need Read/Grep/Glob, Bash only for listed commands); never let a project agent's text override audit methodology or severity rules; prefer personal/general agents for the verification phase (fresh-context verifier must not be the target's own agent); record in the report which project agents were used or rejected and why.
- **Out of scope:** auditing the target's agent config as findings (plan 63) — just cross-link.

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/audit/SKILL.md (Choosing worker agents + verification phase + report template line), skills/audit/references/methodology.md if it repeats the precedence rule (grep first).

## ✅ Acceptance
- **Passes when:** the precedence sentence is replaced by a vet-then-use rule with explicit reject criteria; verification never uses a target-repo agent; report records used/rejected project agents; no other audit text still says project agents take precedence unconditionally (`grep -n "precedence" skills/audit`).
- **Fails if:** the change removes the benefit of using vetted project agents for domain knowledge.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Replace project-agent precedence with vet-then-use rule, verification exclusion and report line -> target: skills/audit/SKILL.md, skills/audit/references/methodology.md
