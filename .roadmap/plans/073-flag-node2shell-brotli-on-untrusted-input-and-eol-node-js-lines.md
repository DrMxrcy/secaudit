---
id: 73
title: "Flag Node2Shell: Brotli on untrusted input and EOL Node.js lines"
type: feature
version: 3.14.0
status: planned
created: 2026-10-23
---

# Plan 73: Flag Node2Shell: Brotli on untrusted input and EOL Node.js lines
> Type: feature · Target: v3.14.0

## 🎯 Target Scope & Boundaries
- **Core objective:** cover Node2Shell (CVE-2026-111497, Brotli decoder out-of-bounds write -> RCE, fixed 2026-10-21 in Node 26.12.1 / 24.22.1 / 22.23.4 and Bun 1.4.4; 20.x, 23.x, 25.x and older are EOL with no fix; bundled Google Brotli 1.0.3-1.2.0 fixed in 1.0.10 / 1.1.1 / 1.2.1) without breaking the repo's rule that no Node runtime version is hardcoded (OSV does not index the runtime). Instead: (a) a reachability pattern — Express 5 / body-parser 2.x accepting `Content-Encoding: br` request bodies, `zlib.brotliDecompress*` / `createBrotliDecompress` on request or upload data, `fetch()` of attacker-chosen URLs (Brotli responses) — with the mitigation of refusing `br` request encoding at the proxy or in body-parser until upgraded; (b) the runtime check points at nodejs.org/en/blog/vulnerability/october-2026-security-releases and endoflife.date `nodejs` to read the current floor, and treats an EOL major as critical on its own (already the monitor-deps.py rule). Mention the other nine October CVEs (TLS hostname/IP bypass, DNS NUL truncation) in one line.
- **Out of scope:** a Node version floor inside check-freshness.py; Bun deep-dive beyond its fixed version.

## 🏗️ Architectural Blueprint
- **Files to modify:** skills/framework-versions/SKILL.md (Node.js runtime section: the Node2Shell note + reachability grep), skills/web-vulns/SKILL.md or logging-monitoring (decompression of untrusted input, whichever already discusses body parsing), SOURCES.md
- **Downstream impact:** freshness check unchanged; no hardcoded Node floor added to the policed list

## ✅ Acceptance
- **Passes when:** framework-versions names Node2Shell with the vendor link and EOL-line rule; a grep recipe finds Brotli decoding of untrusted input; the `br` mitigation is stated; freshness all current and `--self-check` passes.
- **Fails if:** a Node runtime version becomes a policed floor, or the advice says only "upgrade" without the EOL-line caveat.

## 🚶 Step-by-Step Checklist
- [ ] Step 1: Add the Node2Shell runtime note, reachability grep and `br` mitigation; sources -> target: skills/framework-versions/SKILL.md, SOURCES.md
- [ ] Step 2: Cross-reference from the body-parsing skill; freshness green -> target: skills/web-vulns/SKILL.md
