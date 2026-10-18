---
name: supply-chain
description: Audits dependencies for supply-chain risk — hallucinated/phantom packages ("slopsquatting") that AI assistants invent and attackers pre-register, unpinned versions, missing lock files, and weak/default JWT secrets. Also covers a compromised-but-legitimate package producing no advisory at all, vendor-only and late advisories that OSV / npm audit miss (with npm/yarn/pnpm overrides to force a patched transitive version), and PyPI specifics (setup.py as the install hook, lock files and hash pinning, --extra-index-url dependency confusion). Use whenever adding dependencies (especially AI-suggested ones), reviewing package.json / requirements.txt / pyproject.toml, or auditing the dependency tree before deploying.
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

### PyPI differs from npm in ways that change the check

The red flags above are npm-shaped. Three registry differences matter when auditing Python:

- **The install hook is `setup.py`, not `postinstall`.** A package's `setup.py` runs on
  `pip install`, *before any import* — verified: installing a package whose `setup.py` calls
  `os.system` executed it at install time. Crucially, installing a **wheel** (`.whl`) runs no
  build code, while an **sdist** (`.tar.gz`) does. So `pip install --only-binary :all:` is a real
  mitigation with no npm equivalent.
- **Name normalization collapses typosquats.** PEP 503 folds `-`, `_`, and `.` and lowercases, so
  `foo-bar`, `foo_bar`, and `Foo.Bar` are the *same* PyPI project. That kills a whole class of
  npm-style typosquats and makes digit swaps and extra words the dominant shape instead.
- **Provenance is stronger where it exists.** PyPI has Trusted Publishing (OIDC, no long-lived
  tokens) and publish attestations. A package with no attestation *and* a fresh account is a
  stronger negative signal than the equivalent on npm.

```bash
# Vet an AI-suggested package before installing it
curl -s https://pypi.org/pypi/<name>/json | python3 -c "import json,sys; d=json.load(sys.stdin)['info']; print(d['name'], d['author'], d['home_page'])"

# Prefer wheels so no build code executes; inspect an sdist before trusting it
uv pip install --only-binary :all: somepkg
pip download --no-deps --no-binary :all: somepkg && tar tzf somepkg-*.tar.gz   # then read setup.py
```

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

### Python lock files and hash pinning

The grep above only knows about npm, so **a Python project with a bare `requirements.txt` passes
this check while being entirely unpinned.**

```bash
# BAD — no lock, no hashes, floating versions
$ cat requirements.txt
fastapi
sqlalchemy>=2.0

# GOOD — a committed lock, restored with hash verification
$ uv lock && uv sync --frozen                 # uv.lock / poetry.lock / Pipfile.lock / pylock.toml
$ uv export --format requirements.txt -o requirements.txt   # includes hashes by default
$ pip install --require-hashes -r requirements.txt
```

Hash pinning is the part that actually stops substitution: verified, `--require-hashes` with a
deliberately wrong sha256 refuses the install outright (*"Hash mismatch"*). Note `pylock.toml`
(PEP 751) is the new standardised lock format, so accept it alongside the tool-specific ones.

```bash
# Verify a Python lock file exists and is committed
git ls-files | grep -E "uv\.lock|poetry\.lock|Pipfile\.lock|pdm\.lock|pylock\.toml"
```

### `--extra-index-url` is dependency confusion

pip's own documentation is unusually blunt, and quoting it is the whole finding:

> "Using the `--extra-index-url` option to search for packages which are not in the main
> repository (for example, private packages) is unsafe. This is a class of security issue known as
> dependency confusion: an attacker can publish a package with the same name to a public index,
> which may then be chosen instead of your private package."

The private index is *added to* PyPI, and the highest version anywhere wins — so an attacker who
publishes your internal package name publicly, at a higher version, gets installed.

```ini
# BAD — pip.conf / Dockerfile / CI
extra-index-url = https://pypi.company.com/simple
```
```bash
# GOOD — scope each package to one index (uv defaults to first-index for exactly this reason)
uv add --index company=https://pypi.company.com/simple internal-lib
# pip equivalent: --index-url (replace, not extend) plus --require-hashes
```

uv's opt-outs are named `unsafe-first-match` and `unsafe-best-match`, which makes them an
unusually clean grep target.

Detection: `grep -rn "extra-index-url\|extra_index_url\|index-strategy\|unsafe-best-match" --include="*.txt" --include="*.toml" --include="*.cfg" --include="Dockerfile*" --include="*.yml"`

## Dependency Auditing

Run these after every vibe-coding session before deploying:

```bash
# npm — built-in audit
npm audit

# More thorough — check for known vulnerabilities
npx audit-ci --critical

# Validate lock file integrity / allowed hosts.
# --validate-https matters as much as --allowed-hosts: without it a lockfile entry whose
# resolved URL is http:// or git:// passes, which is the exact substitution the lockfile
# is supposed to prevent.
npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm --validate-https
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

The same shape reaches you from the workflow side: a GitHub Action pinned to a mutable tag is an
unreviewed dependency that runs with your CI secrets, and a compromised pipeline is how several of
these npm compromises were published in the first place (tj-actions/changed-files, AsyncAPI,
TanStack). For the pipeline itself — action pinning, privileged triggers, token scope, cache and
artifact poisoning — see `secaudit:ci-cd-security`.

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

### An empty OSV / `npm audit` result is not a clean bill

The compromise above had no advisory anywhere. This is a different failure: the advisory
exists, but in a database your tools don't read, or it hasn't reached them yet.

**Vendor-only advisories.** Commercial scanners publish under their own IDs (Aikido
`AIKIDO-YYYY-NNNNN`, Snyk `SNYK-JS-…`, Socket alerts). Many never get a GHSA or CVE, so they
never reach OSV, and `npm audit` never shows them. Verified 2026-10-17: these are three of the
advisories Aikido lists against the vulnerable `undici@6.29.1` (not the full set, since its undici
page lists more):

| Advisory | Severity | Fixed in (per Aikido) |
|---|---|---|
| AIKIDO-2026-54683 | Medium | 8.10.2 |
| AIKIDO-2026-10369 | Low | 7.23.0 |
| AIKIDO-2026-10385 | Low | 7.24.1 |

On the same day, OSV `POST /v1/query` returned no vulnerabilities for undici 6.29.1, 7.30.1, or
8.12.2, and `npm audit` on a lockfile pinning undici 6.29.1 reported zero. Every OSV-backed tool
called that tree clean.

**Disclosure lag.** Advisories that do go through GHSA still arrive late. Vendor post → GHSA →
OSV can take days: the Next.js advisories Vercel published on 2026-10-14 were still missing from
OSV on 2026-10-17. Floors that come from a vendor post live in `secaudit:framework-versions`.

What the auditor does:

1. For each framework and major runtime dependency in use, read the vendor's own security
   page, blog, or GitHub Security tab. Don't stop at OSV.
2. Name the sources you consulted in the report. "No known vulnerabilities" overstates an
   OSV-only lookup:
   ```text
   Advisory sources: OSV (osv-scanner, OSV API), npm audit (GitHub Advisory DB). OSV-only:
   vendor-only feeds (Aikido, Snyk, Socket) not consulted; vendor posts checked for: next, react.
   ```
3. Recommend a second scanner with its own advisory feed in CI (Socket, Snyk, Aikido) next to
   `npm audit`. Their IDs are the ones OSV never sees.
4. Aikido's public feed is at `https://intel.aikido.dev` (returned 200 on 2026-10-17). Re-check
   with `curl -sI https://intel.aikido.dev` before you cite it, and leave it out if it doesn't
   return 200.

### Forcing a patched version of a transitive dependency

If the vulnerable copy belongs to a parent package, bumping your own `package.json` changes
nothing, because the parent's declared range keeps the old copy. In one audited tree `discord.js`
declared `undici: ^6.27.0` directly and again through `@discordjs/rest`, so both copies resolved
to 6.29.1, alongside separate 7.x and 8.x copies pulled in by other packages. Map every copy
first:

```bash
npm ls undici        # every installed copy and the chain that pulls each one in
npm explain undici   # the same, with the range each parent declares
```

Then override from the **root** `package.json`. npm ignores overrides set anywhere else. Pick
one npm form.

npm, every undici under `discord.js` at any depth (this also covers the copy under
`@discordjs/rest`):

```json
{ "overrides": { "discord.js": { "undici": "^8.10.2" } } }
```

npm, one parent only. This rewrites the copy under `@discordjs/rest`, and the copy `discord.js`
declares itself stays on 6.29.1:

```json
{ "overrides": { "@discordjs/rest": { "undici": "^8.10.2" } } }
```

yarn `resolutions` accept one level of `parent/child`:

```json
{ "resolutions": { "discord.js/undici": "^8.10.2", "@discordjs/rest/undici": "^8.10.2" } }
```

pnpm reads overrides from `pnpm-workspace.yaml`. pnpm 10 and earlier read `pnpm.overrides` from
`package.json`; since v11 pnpm no longer reads the `pnpm` field. `parent>child` matches only that
parent's direct dependency, so list each parent:

```yaml
overrides:
  "discord.js>undici": "^8.10.2"
  "@discordjs/rest>undici": "^8.10.2"
```

A bare `"undici": "^8.10.2"` rewrites every copy in the tree. If you also depend on undici
directly, npm throws `EOVERRIDE` unless the spec matches your dependency (or you use `"$undici"`).

```bash
npm install && npm ls undici   # confirm every copy moved, not only the one you aimed at
```

Forcing `^8` into a parent that declared `^6` installs a major version it was never tested
against. Re-run the parent's code paths (its tests, or a smoke test of the feature that uses it)
before you ship.

It can also raise your Node floor. undici 8 declares `engines: node >=22.19.0`, while
`discord.js` 14.27.0 declares `node >=18`. Check `node -v` locally and the deploy runtime's Node
version before you force it:

```bash
npm view undici@8.10.2 engines   # { node: '>=22.19.0' }
node -v
```

Here the major jump is the only route. Aikido lists the AIKIDO-2026-54683 fix only in 8.10.2
(affected through 8.10.1), and the newest 6.x and 7.x releases (dist-tags `six` = 6.29.1, `seven` =
7.30.1) don't carry it. Use the override until `discord.js` widens its range, then delete it.

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

- https://pip.pypa.io/en/stable/cli/pip_install/ -- --extra-index-url dependency-confusion warning (verbatim)
- https://pip.pypa.io/en/stable/topics/secure-installs/ -- hash-checking mode
- https://docs.astral.sh/uv/concepts/indexes/ -- first-index default, unsafe-best-match opt-out
- https://peps.python.org/pep-0751/ -- pylock.toml standardised lock format
- https://docs.pypi.org/trusted-publishers/ -- PyPI Trusted Publishing (OIDC)
- https://docs.pypi.org/attestations/ -- PyPI publish attestations
- https://packaging.python.org/en/latest/specifications/name-normalization/ -- PEP 503 name folding
- https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen -- USENIX 2025 package-hallucination study (19.7% / 43% stats)
- https://arxiv.org/abs/2406.10279 -- preprint of the same study
- https://www.lasso.security/blog/ai-package-hallucinations -- Lasso Security: the huggingface-cli proof of concept
- https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks -- Socket research on slopsquatting
- https://snyk.io/articles/slopsquatting-mitigation-strategies/ -- mitigation guidance
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/ -- lockfiles pin versions + integrity hashes
- https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain -- CHAINDROP npm worm, preinstall delivery, no CVE assigned
- https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack -- independent analysis of the same incident
- https://intel.aikido.dev -- Aikido Intel vulnerability feed (AIKIDO-* IDs not in OSV); resolved 200 on 2026-10-17
- https://docs.npmjs.com/cli/v10/configuring-npm/package-json/#overrides -- npm overrides: root-only, scoped `parent: { child }` form, EOVERRIDE and `$` references
- https://yarnpkg.com/configuration/manifest -- yarn `resolutions`, one level of `parent/child`
- https://pnpm.io/settings/dependency-resolution -- pnpm `overrides` in pnpm-workspace.yaml, `parent>child` selector
- https://pnpm.io/package_json -- since v11 pnpm no longer reads settings from the `pnpm` field of package.json
- https://intel.aikido.dev/cve/AIKIDO-2026-54683 -- undici Medium advisory: affected through 8.10.1, fixed in 8.10.2
