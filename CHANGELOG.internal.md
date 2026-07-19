# Changelog (internal)

_Full work log — every item, including internal/dev work. The curated public changelog is CHANGELOG.md._

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
