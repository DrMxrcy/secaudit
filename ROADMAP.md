# 🗺️ Roadmap: Secaudit

## 💡 Idea Incubator
- deployment: CSP reporting hygiene, Local Network Access and Connection-Allowlist (emerging Chrome)
- auth: passkey rpId on IP/public suffix, client-generated challenge, AAGUID in authz
- python-web-security: torch.load without weights_only and trust_remote_code=True
- Normalized finding JSON with SARIF 2.1.0 export for CI and tracker handoff
- CI injection scan of our own skill pack (hidden Unicode, exfil hosts, curl|sh) and release checksums (OWASP AST01/AST02)
- Least-privilege allowed-tools frontmatter on read-only audit skills plus a frontmatter schema check
- Per-check vulnerable/benign fixtures as regression tests for grep heuristics (UnitOne tests/fixtures, Google expectations.md pattern)
<!-- Free-form. Drop loose ideas here; scripts never touch this region. -->
<!-- roadmap:auto:start -->
**Current version: v3.14.0**

## 📊 Versions

### [x] v3.0.0 — 100% · 1 item · shipped 2026-06-27 ([history](CHANGELOG.internal.md))

### [x] v3.1.0 — 100% · 1 item · shipped 2026-06-28 ([history](CHANGELOG.internal.md))

### [x] v3.2.0 — 100% · 4 items · shipped 2026-07-17 ([history](CHANGELOG.internal.md))

### [x] v3.3.0 — 100% · 4 items · shipped 2026-07-19 ([history](CHANGELOG.internal.md))

### [x] v3.3.1 — 100% · 1 item · shipped 2026-07-20 ([history](CHANGELOG.internal.md))

### [x] v3.4.0 — 100% · 6 items · shipped 2026-08-21 ([history](CHANGELOG.internal.md))

### [x] v3.5.0 — 100% · 7 items · shipped 2026-08-24 ([history](CHANGELOG.internal.md))

### [x] v3.6.0 — 100% · 4 items · shipped 2026-08-24 ([history](CHANGELOG.internal.md))

### [x] v3.7.0 — 100% · 5 items · shipped 2026-08-25 ([history](CHANGELOG.internal.md))

### [x] v3.8.0 — 100% · 2 items · shipped 2026-08-25 ([history](CHANGELOG.internal.md))

### [x] v3.9.0 — 100% · 10 items · shipped 2026-09-16 ([history](CHANGELOG.internal.md))

### [x] v3.10.0 — 100% · 10 items · shipped 2026-10-16 ([history](CHANGELOG.internal.md))

### [x] v3.11.0 — 100% · 3 items · shipped 2026-10-16 ([history](CHANGELOG.internal.md))

### [x] v3.12.0 — 100% · 11 items · shipped 2026-10-19 ([history](CHANGELOG.internal.md))

### [x] v3.12.1 — 100% · 1 item · shipped 2026-10-20 ([history](CHANGELOG.internal.md))

### [x] v3.13.0 — 100% · 1 item · shipped 2026-10-20 ([history](CHANGELOG.internal.md))

### [ ] v3.14.0 — 50%
- [x] **#76 Watch pwn.watch for new advisories and hand capped fixes to Copilot** `feature` — 100% ([plan](.roadmap/plans/076-watch-pwn-watch-for-new-advisories-and-hand-capped-fixes-to-copilot.md))
- [x] **#72 Add a php-security skill covering PHP2Shell and PHP runtime floors** `feature` — 100% ([plan](.roadmap/plans/072-add-a-php-security-skill-covering-php2shell-and-php-runtime-floors.md))
- [ ] **#73 Flag Node2Shell: Brotli on untrusted input and EOL Node.js lines** `feature` — 0% ([plan](.roadmap/plans/073-flag-node2shell-brotli-on-untrusted-input-and-eol-node-js-lines.md))
- [ ] **#74 Cover the Storybook dev-server code-injection advisory (CVE-2026-114125)** `feature` — 0% ([plan](.roadmap/plans/074-cover-the-storybook-dev-server-code-injection-advisory-cve-2026-114125.md))
- [ ] **#75 Add pwn.watch as an optional live-incident source in monitor-deps.py** `feature` — 0% ([plan](.roadmap/plans/075-add-pwn-watch-as-an-optional-live-incident-source-in-monitor-deps-py.md))
<!-- roadmap:auto:end -->
