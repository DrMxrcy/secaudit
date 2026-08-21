---
name: supply-chain
description: Audits dependencies for supply-chain risk — hallucinated/phantom packages ("slopsquatting") that AI assistants invent and attackers pre-register, unpinned versions, missing lock files, and weak/default JWT secrets. Use whenever adding dependencies (especially AI-suggested ones), reviewing package.json / requirements.txt, or auditing the dependency tree before deploying.
license: MIT
---

# Supply Chain & Dependency Security

AI coding assistants introduce a unique supply chain risk: they hallucinate package names that
don't exist, and attackers register those names with malicious code. This is called
**slopsquatting**.

## When to Use

- Adding any dependency, especially one an AI assistant just suggested.
- Reviewing `package.json` / `requirements.txt` or the lock file.
- Auditing the dependency tree before a deploy.

## Slopsquatting (Hallucinated Packages)

Research is consistent and alarming. The 2025 USENIX Security study *"We Have a Package for You"*
(576,000 code samples, 16 models) found **~19.7% of AI-generated code referenced packages that
don't exist** — commercial models averaged ~5.2%, open-source models ~21.7%. Critically, **43% of
hallucinated names recurred across repeated runs of the same prompt**, making them predictable and
easy to pre-register.

This is not theoretical: a hallucinated package (`huggingface-cli`), registered as a proof of
concept by researcher Bar Lanyado at Lasso Security, drew **30,000+ real downloads in three
months**. Unlike typosquatting (betting on human typos), slopsquatting bets on the AI being
predictably wrong.

### What to Check

For every dependency in `package.json` or `requirements.txt`:

1. **Verify the package exists** on the official registry (npmjs.com, pypi.org) and is the
   legitimate project — before installing it. Never trust an AI's import blindly.
2. **Check download stats** — a legitimate utility package has thousands of weekly downloads, not 12.
3. **Check the publisher** — legitimate packages have identifiable authors with multiple published packages.
4. **Check creation date** — a package created last week that your AI just recommended is suspicious.
5. **Check for name confusion** — does the name suspiciously combine two real package names?

### Red Flags

- Package has fewer than 100 weekly downloads
- Package was published within the last 30 days
- Package name looks like two well-known packages smashed together
- Package has no GitHub repo linked, or the repo has no stars
- Package has a `preinstall` or `postinstall` script (check the dependency's `package.json`)

The signals above catch a package that was *always* malicious. A package that *became* malicious
looks different — the name, download count, and repo all stay reputable, so these red flags all
pass. Watch instead for:

- A transitive dependency you never touched gains a new version in the lockfile diff
- A lifecycle hook appears where the previous version had none (`hasInstallScript` flips to true)
- A long-stable package publishes an unexpected patch release, especially across a whole family
  of related packages at once
- A maintainer account change, or a release that breaks the package's usual cadence

## Lock File Hygiene

Always commit lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`). Lock files pin
exact versions and integrity hashes, preventing supply chain substitution. Install with
`npm ci` / `pnpm install --frozen-lockfile` in CI so a new or unexpected package name can't be
resolved silently.

```bash
# Verify lock file exists and is committed
git ls-files | grep -E "(package-lock|yarn\.lock|pnpm-lock)"
```

If no lock file is committed, any `npm install` can pull in different (potentially compromised)
versions than what was tested.

## Dependency Auditing

Run these after every vibe-coding session before deploying:

```bash
# npm — built-in audit
npm audit

# More thorough — check for known vulnerabilities
npx audit-ci --critical

# Validate lock file integrity / allowed hosts
npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm
```

For deeper behavioral analysis (install scripts, suspicious package behavior), consider
[Socket](https://socket.dev) or Snyk. For Python projects:
```bash
pip-audit
```

### A clean `npm audit` is not evidence of a clean dependency tree

Every tool above is a **lagging indicator**: it matches your tree against *published advisories*.
When a legitimate, correctly-spelled, popular package is compromised at the source, there is no
advisory to match until someone files one — and often no CVE is ever assigned. The scan returns
clean while the compromise is live.

**Worked example — CHAINDROP / Shai-Hulud, 2026-08-04.** A maintainer account in the
`keyv` / `cacheable` ecosystem was taken over. Over 400 unique npm packages were compromised. The
payload ran from a **`preinstall`** hook — arbitrary commands executed *before* the package is
installed, needing no action from the victim beyond `npm install`. It harvested credentials
against 300+ patterns (AWS/GCP/Azure, GitHub tokens, SSH keys, Kubernetes tokens, npm tokens, and
AI tooling credentials), attempted IDE persistence via editor config files, and wormed: on
finding an npm token with publish rights it enumerated every package the victim could publish to
and injected itself, bumping the patch version.

**No CVE was assigned.** `npm audit`, `audit-ci`, and OSV.dev had nothing to report.

So do not treat a clean scan as a result. Use the controls that hold when no advisory exists:

```bash
# Install scripts are the delivery mechanism — turn them off by default.
npm config set ignore-scripts true
npm ci --ignore-scripts        # re-enable per-package, deliberately, only where needed

# Install exactly what the lockfile says. `npm ci` fails on drift; `npm install` silently resolves.
npm ci

# Pin exact versions — no ^ or ~ — so a patch bump can never arrive unreviewed.
npm install --save-exact <pkg>
```

Then review the lockfile diff like code. In a compromise of this shape the tell is in the
lockfile, not in `package.json`: a transitive dependency you did not touch gains a new `version`,
`resolved`, and `integrity`, and sometimes a `hasInstallScript: true` where there was none.

```bash
# Scan the tree for packages that execute code at install time
npm query ":attr(hasInstallScript)" 2>/dev/null || grep -n "hasInstallScript" package-lock.json

# Review dependency churn in a PR
git diff package-lock.json | grep -E '^\+.*(version|resolved|integrity|hasInstallScript)'
```

For behavioral analysis of what a package actually does at install time — as opposed to whether
it has a CVE — [Socket](https://socket.dev) is the right class of tool.

### Look up live advisories, not a frozen list

`npm audit` / `pip-audit` already query live data — good. When you flag a specific package
(unpinned, freshly added, or AI-suggested) and want to know whether *that exact version* has a
known vulnerability, query OSV.dev directly rather than relying on any static list. OSV.dev needs
no API key and covers npm, PyPI, crates.io, and Go. The full procedure and a worked example live
in the `secaudit:framework-versions` skill's `live-advisory-lookup.md` reference (tool order:
`osv-scanner` → OSV.dev API → `npm audit` → GitHub Advisories → firecrawl/WebSearch fallback).

## Unpinned Dependencies

AI assistants often generate `package.json` with loose version ranges:

```json
// BAD: accepts any minor/patch version — a compromised update auto-installs
"dependencies": {
  "some-lib": "^2.0.0"
}

// BETTER: pin exact versions for production
"dependencies": {
  "some-lib": "2.0.3"
}
```

At minimum, use a lock file. For critical production apps, pin exact versions.

> **Redaction:** The greps below can surface real credentials and secrets. When reporting a match,
> cite its **location** and a **masked** form (`***`, last 4 chars) — never echo the literal
> password, token, or JWT secret into your output. Treat any real value found as compromised and
> tell the user to rotate it.

## Common AI-Generated Default Credentials

AI-generated apps frequently ship with hardcoded test credentials that work in production:

| Username | Password | Where it appears |
|----------|----------|-----------------|
| `user@example.com` | `password123` | Login/register endpoints |
| `admin@admin.com` | `admin` or `admin123` | Admin panels |
| `test@test.com` | `test` or `test123` | Seeded user data |
| `demo@demo.com` | `demo` | Demo accounts |

Search for these patterns:
```bash
grep -rn "password123\|admin123\|@example\.com\|@test\.com\|@admin\.com" --include="*.ts" --include="*.js" --include="*.tsx" --include="*.sql"
```

If found in seed data that runs in production, or in auth logic, flag as **High** severity.
(See also `secaudit:secrets`.)

## JWT Signing Secrets

AI-generated apps commonly use weak, predictable JWT secrets:

- `"secret"`, `"jwt-secret"`, `"your-secret-key"`
- `"supersecret"`, `"changeme"`, `"keyboard-cat"`

These are trivially guessable, allowing token forgery. Search for:
```bash
grep -rn "secret\|changeme\|keyboard.cat\|supersecret" --include="*.ts" --include="*.js" --include="*.env*"
```

## Sources

- https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen -- USENIX 2025 package-hallucination study (19.7% / 43% stats)
- https://arxiv.org/abs/2406.10279 -- preprint of the same study
- https://www.lasso.security/blog/ai-package-hallucinations -- Lasso Security: the huggingface-cli proof of concept
- https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks -- Socket research on slopsquatting
- https://snyk.io/articles/slopsquatting-mitigation-strategies/ -- mitigation guidance
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/ -- lockfiles pin versions + integrity hashes
- https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain -- CHAINDROP npm worm, preinstall delivery, no CVE assigned
- https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack -- independent analysis of the same incident
