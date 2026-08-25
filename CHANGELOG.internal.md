# Changelog (internal)

_Full work log — every item, including internal/dev work. The curated public changelog is CHANGELOG.md._

## v3.7.0 — 2026-08-25

### ✨ New
- Whole-app audits now run each area in its own worker, so large projects get read thoroughly instead of sampled.
- Findings are now ranked by how likely an issue is to actually be exploited, and the audit flags runtimes that no longer receive security updates.
- New checks for apps selling subscriptions through mobile in-app purchase.
- New checks for apps using Clerk for sign-in.
- New checks for file and image storage, covering who can read uploaded files and for how long.

## v3.6.0 — 2026-08-24

### ✨ New
- Version checks now cover several more widely used frameworks and the Node.js runtime itself.
- When a container is running, the audit can now confirm container findings against it instead of reporting them as suspected.
- New checks for apps that connect AI agents to external tools, covering the permissions those connections are granted.

### 🐛 Fixed
- The automated freshness check now also verifies versions named as a fix for a specific issue, catching outdated upgrade advice it previously skipped.

## v3.5.0 — 2026-08-24

### ✨ New
- Adds a script that re-checks every version and link the skills cite, so outdated advice is caught automatically instead of drifting unnoticed.
- New checks for projects using Prisma with Postgres, including tenant isolation and vector search used by AI features.
- New checks for apps built with Better Auth, covering session handling, organization roles, and account linking.
- New checks for containerised projects, covering image contents, published ports, and runtime permissions.
- New checks for Python backends built with FastAPI or Django.
- AI checks now cover chat apps end to end, including conversation history, retrieval, and how tools are given access to data.
- Existing checks now recognise Python equivalents alongside the JavaScript ones.

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

### ✨ New
- When auditing Convex or Expo apps, the audit now points you to the official build guides for those platforms and checks their recommended security settings.

## v3.3.0 — 2026-07-19

### ✨ New
- You can now point the audit at just your current branch or a pull request's changes, getting a fast, focused review of what you changed instead of the whole app.
- Audit reports now connect related weaknesses into a single step-by-step attack path, so you can see how separate issues combine into a real-world risk.
- Audits now begin by mapping your app's attack surface and end with a check for anything the sweep missed, making the review more thorough.
- Every reported issue is now backed by a verified spot in your code and a concrete attack path, so you get fewer false alarms.

## v3.2.0 — 2026-07-17

### ✨ New
- Version and dependency checks now look up the latest published security advisories as they run, so you're alerted to newly disclosed issues instead of relying only on a built-in list.
- The audit can now optionally run your app and actively test it to confirm real vulnerabilities and filter out false alarms.
- Audits now start with your highest-risk areas, can zero in on a single part of your app such as the admin area, and double-check each finding before reporting it.

### 🐛 Fixed
- Security audits now mask any secrets they find in their reports instead of repeating the real values, so running an audit can't itself leak a credential into logs or transcripts.

## v3.1.0 — 2026-06-28

### ✨ New
- Every security check is now backed by cited sources, and the audit covers the full OWASP Top 10 with new checks for cryptography, web vulnerabilities (XSS, SSRF, file uploads), and security logging.

## v3.0.0 — 2026-06-27

### ✨ New
- Secaudit is now a one-step installable plugin with sharper, more focused security checks and new coverage for Expo, React Native, and Convex apps.
