# Changelog (internal)

_Full work log — every item, including internal/dev work. The curated public changelog is CHANGELOG.md._

## v3.2.0 — 2026-07-17

### ✨ New
- Version and dependency checks now pull the latest published vulnerability advisories at audit time, so you're warned about newly disclosed issues instead of only a fixed built-in list.
- The audit can now optionally run your app and actively test it to confirm real vulnerabilities and filter out false alarms.
- Audits now start with your highest-risk areas, can focus on a specific surface such as the admin panel, double-check each finding before reporting it, and add a dedicated check for privilege-escalation gaps.

## v3.1.0 — 2026-06-28

### ✨ New
- Every security check is now backed by cited sources, and the audit covers the full OWASP Top 10 with new checks for cryptography, web vulnerabilities (XSS, SSRF, file uploads), and security logging.

## v3.0.0 — 2026-06-27

### ✨ New
- Secaudit is now a one-step installable plugin with sharper, more focused security checks and new coverage for Expo, React Native, and Convex apps.
