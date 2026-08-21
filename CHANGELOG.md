# Changelog

## v3.4.0 — 2026-08-21

### ✨ New
- Dependency checks no longer rely on advisory scanners alone, so a compromised package that was never formally reported can still be caught.
- The version check now recognises a recent group of framework authentication flaws, including two that are known to be under active attack.

### 🐛 Fixed
- Version-check advice now points at genuinely patched releases; several entries previously named a version that was still vulnerable.
- All OWASP category references now match the current 2025 Top 10 numbering.
- AI and MCP guidance now tracks the 2026 LLM Top 10 and the current Model Context Protocol revision.
- Repairs one dead documentation link and four that had moved.

## v3.3.1 — 2026-07-20

_Plus behind-the-scenes performance and reliability work._

## v3.3.0 — 2026-07-19

### ✨ New
- Audit reports now connect related weaknesses into a single step-by-step attack path, so you can see how separate issues combine into a real-world risk.
- Every reported issue is now backed by a verified spot in your code and a concrete attack path, so you get fewer false alarms.

## v3.2.0 — 2026-07-17

### ✨ New
- Version and dependency checks now look up the latest published security advisories as they run, so you're alerted to newly disclosed issues instead of relying only on a built-in list.
- Audits now start with your highest-risk areas, can zero in on a single part of your app such as the admin area, and double-check each finding before reporting it.

## v3.1.0 — 2026-06-28

### ✨ New
- Every security check is now backed by cited sources, and the audit covers the full OWASP Top 10 with new checks for cryptography, web vulnerabilities (XSS, SSRF, file uploads), and security logging.

## v3.0.0 — 2026-06-27

### ✨ New
- Secaudit is now a one-step installable plugin with sharper, more focused security checks and new coverage for Expo, React Native, and Convex apps.
