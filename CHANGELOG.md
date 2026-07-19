# Changelog

## v3.3.0 — 2026-07-19

### ✨ New
- You can now point the audit at just your current branch or a pull request's changes, getting a fast, focused review of what you changed instead of the whole app.
- Audits now begin by mapping your app's attack surface and end with a check for anything the sweep missed, making the review more thorough.

## v3.2.0 — 2026-07-17

### ✨ New
- The audit can now optionally run your app and actively test it to confirm real vulnerabilities and filter out false alarms.

### 🐛 Fixed
- Security audits now mask any secrets they find in their reports instead of repeating the real values, so running an audit can't itself leak a credential into logs or transcripts.

## v3.1.0 — 2026-06-28

### ✨ New
- Every security check is now backed by cited sources, and the audit covers the full OWASP Top 10 with new checks for cryptography, web vulnerabilities (XSS, SSRF, file uploads), and security logging.

## v3.0.0 — 2026-06-27

### ✨ New
- Secaudit is now a one-step installable plugin with sharper, more focused security checks and new coverage for Expo, React Native, and Convex apps.
