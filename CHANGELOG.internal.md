# Changelog (internal)

_Full work log — every item, including internal/dev work. The curated public changelog is CHANGELOG.md._

## v3.3.0 — (in progress)

### ✨ New
- (pending) You can now point the audit at just your current branch or a pull request's changes, getting a fast, focused review of what you changed instead of the whole app.
- (pending) Audit reports now connect related weaknesses into concrete step-by-step attack paths, so you can see how separate issues combine into a real exploit.
- (pending) Audits now begin by mapping your app's attack surface and end with a check for anything the sweep missed, making the review more thorough.
- Every reported issue is now backed by a verified spot in your code and a concrete exploit path, cutting speculative or false findings.

## v3.2.0 — 2026-07-17

### ✨ New
- Version and dependency checks now pull the latest published vulnerability advisories at audit time, so you're warned about newly disclosed issues instead of only a fixed built-in list.
- The audit can now optionally run your app and actively test it to confirm real vulnerabilities and filter out false alarms.
- Audits now start with your highest-risk areas, can focus on a specific surface such as the admin panel, double-check each finding before reporting it, and add a dedicated check for privilege-escalation gaps.

### 🐛 Fixed
- Security audits now mask any secrets they find in their reports instead of repeating the real values, so running an audit can't itself leak a credential into logs or transcripts.

## v3.1.0 — 2026-06-28

### ✨ New
- Every security check is now backed by cited sources, and the audit covers the full OWASP Top 10 with new checks for cryptography, web vulnerabilities (XSS, SSRF, file uploads), and security logging.

## v3.0.0 — 2026-06-27

### ✨ New
- Secaudit is now a one-step installable plugin with sharper, more focused security checks and new coverage for Expo, React Native, and Convex apps.
