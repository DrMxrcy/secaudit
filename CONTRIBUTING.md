# Contributing to Vibe Security

Contributions, corrections, and improvements are welcome! This skill is meant to be a community resource for making AI-generated code safer.

## How to Contribute

1. **Fork** this repository
2. **Create a branch** for your changes
3. **Make your changes** following the guidelines below
4. **Submit a pull request** with a clear description of what you changed and why

## What to Contribute

- **New vulnerability patterns** — Found a security anti-pattern that AI assistants commonly introduce? Add it to the relevant reference file or create a new one.
- **Better examples** — Clearer before/after code samples help the AI understand what to flag and how to fix it.
- **Corrections** — If something is wrong or outdated, please fix it.
- **New platform coverage** — The skill currently covers Supabase, Firebase, Convex, Stripe, Next.js, and React Native. If you have security patterns for other platforms commonly used in vibe-coded apps, add them.
- **Real-world cases** — If you've seen a specific vulnerability in the wild that AI assistants keep introducing, that's exactly what this skill is for.

## Guidelines

- **Keep it concise.** Markdown should be scannable. Use short sentences and code examples over long explanations.
- **Explain the "why."** Don't just say "don't do X" — explain what an attacker can do if you do X. This helps the AI understand the severity and make better judgments.
- **Focus on AI-generated patterns.** This isn't a general security checklist. Focus on mistakes that AI coding assistants specifically and repeatedly make.
- **Test your changes.** If possible, verify that an AI assistant actually catches the issue with your updated instructions.
- **One topic per reference file.** If you're adding a new category, create a new file in `references/` and add a step to the audit process in `SKILL.md`.

## Keeping cited facts current

Security guidance rots. A CVE's "fixed in" version is correct until a later advisory lands on
that same release line; a vendor doc URL is correct until the vendor reorganises. In v3.4.0 four
entries in `framework-versions` were sending readers to versions that were still vulnerable, and
one Stripe link had 404'd — every one of them had been accurate when written.

Run the checker before opening a PR that touches `skills/` or `SOURCES.md`:

```bash
python3 scripts/check-freshness.py            # ~15s, stdlib only, no install
python3 scripts/check-freshness.py --only links
python3 scripts/check-freshness.py --json     # machine-readable
```

It re-derives four things from live sources and exits non-zero on drift:

| Check | What it asserts |
|---|---|
| `versions` | every `pkg@x.y.z` offered as an upgrade target has **zero** open advisories on OSV |
| `cves` | every cited `GHSA-…` resolves |
| `links` | every URL returns 200 **without** a redirect |
| `kev` | no cited CVE has quietly joined the CISA KEV catalog without the skill saying so |

**Why monthly?** Measured on 2026-08-21: `next` has 64 advisories, 31 of them published in 2026
alone, and the **median gap between advisory days is 31 days** (longest quiet stretch 96 days,
shortest 1). A hardcoded floor for a fast-moving framework has a useful life of weeks, so
`.github/workflows/freshness.yml` runs on the 1st of each month and opens an issue on drift. Other
ecosystems are far slower — `express` had zero advisories in the preceding 12 months — so a single
cadence necessarily over-checks some packages and under-checks others. The check is cheap enough
that this does not matter.

Two rules when it reports something:

- **Re-verify against the live source before editing.** The script tells you a fact moved, not
  what the new fact is.
- **Never auto-apply.** The script deliberately does not edit the skills. Silently rewriting
  security guidance from an API response is a worse failure mode than staleness.

If a check reports something that is actually fine, add it to `URL_ALLOWLIST` or
`PLACEHOLDER_PATTERNS` in the script **with a comment explaining why**. False positives are the
real threat to a checker like this: once people learn to ignore it, it stops working.

## Code of Conduct

Be kind, be constructive, be helpful. We're all here to make vibe-coded apps safer.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
