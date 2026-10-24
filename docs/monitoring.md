# Continuous dependency monitoring

`secaudit` audits an app when you ask it to. This watches an app **between** audits.

## What it is, and what it is not

It does **not** replace Dependabot or `osv-scanner`. Those tell you which dependencies have
advisories. This tells you **which of them to do first**, which is the part that is usually
missing:

- Dependabot opens a PR per advisory. Forty open PRs is not a priority order, and the usual
  outcome is that they get batch-merged unreviewed or ignored entirely.
- `osv-scanner` reports advisories but carries no EPSS, so a CVSS-Critical open redirect at
  0.8% exploitation probability looks identical to a pre-auth RCE at 99.8%.
- Neither knows your **runtime** is end-of-life, because no advisory database indexes runtimes.
  An EOL runtime will never be patched, which outranks any individual CVE.

Ordering is CISA KEV first, then EPSS descending, with an EOL runtime surfaced above everything.
That is the same rule `secaudit:audit` applies to severity, run continuously instead of only when
someone remembers to ask.

## Add it to an app repo

Create `.github/workflows/dependency-monitor.yml`:

```yaml
name: Dependency Monitor
on:
  schedule:
    - cron: "0 7 * * 1"     # weekly
  workflow_dispatch:

jobs:
  monitor:
    uses: DrMxrcy/secaudit/.github/workflows/dependency-monitor.yml@bd3a6dcdeeee5aec48d16babb3a065e457201d06
    permissions:
      contents: read
      issues: write
```

### Pin by commit SHA, not by tag or branch

The reference above is pinned to a full commit SHA on purpose. A tag can be moved and a branch
changes under you, so `@main` means you run whatever that repo contains at the moment your job
starts — you have handed a third party write access to your CI. `secaudit:supply-chain` says
exactly this about npm dependencies, and it would be incoherent to ship a security workflow that
asks you to ignore it.

Renovate and Dependabot both understand SHA-pinned action references and will offer bumps.

## Options

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan |
| `min-epss` | `0` | Only report at or above this exploitation probability |
| `fail-on` | `any` | `any`, `kev`, or `epss` — what makes the job fail |
| `open-issue` | `true` | Open (or update) a tracking issue when something is found |

Starting point for a noisy repo: `fail-on: kev` fails only on confirmed in-the-wild exploitation,
while the report still lists everything so nothing is hidden.

## Run it locally

```bash
python3 scripts/monitor-deps.py --path ../myapp
python3 scripts/monitor-deps.py --path ../myapp --min-epss 0.1
python3 scripts/monitor-deps.py --json
```

Stdlib only — no install step, and therefore no new supply-chain surface in the tool that checks
your supply chain.

## Supported dependency files

Parsed: `package-lock.json` (v1, v2/v3), `uv.lock`, and `requirements.txt` (`==` pins only — a
floating range has no single version to query).

**Detected but deliberately not parsed:** `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`,
`composer.lock`, `go.sum`. These use bespoke formats, and a partial parse that reported
"no findings" would be worse than no scan at all. They are reported as **UNCHECKED**, the job
fails, and you are pointed at `osv-scanner scan source`, which handles them properly.

## Failure behaviour

The monitor is built to fail **loud**, never clean:

- Cannot reach OSV, EPSS, or the KEV feed → exit 2, the job errors, and the log says the result
  is UNCHECKED rather than clear. A monitor that fails open is worse than none, because it
  reports "all clear" from a network blip and nobody looks again for a week.
- A lockfile it cannot parse → reported as UNCHECKED and the job fails.
- 429 and 5xx responses are retried before anything is believed. A transient error is never
  reported as a finding, and never as a pass.

## Optional: live incidents from pwn.watch (`--pwnwatch`)

OSV indexes packages. It does not index language runtimes, and a vendor-only advisory can take
days to reach it. In October 2026 both of those mattered: PHP2Shell and Node2Shell were runtime
bugs that no OSV query for a package can return. pwn.watch tracks incidents like these, with affected and fixed versions and links to the vendor
sources. `--pwnwatch` adds it as a second source:

```bash
python3 scripts/monitor-deps.py --path ../myapp --pwnwatch
python3 scripts/monitor-deps.py --path ../myapp --pwnwatch --json      # adds a "pwnwatch" array
python3 scripts/monitor-deps.py --pwnwatch --pwnwatch-state ./pwnwatch-state.json
```

The flag is opt-in. Without it, the script makes no pwn.watch request and its output is
unchanged. The pwn.watch client and sanitiser are loaded from `scripts/watch-advisories.py`, so
keep the two files together. If that file is missing, the script stops with exit 2 and says so.

**Which feeds it reads.** It reads `https://pwn.watch/t/<tag>.json` for each stack it finds under
`--path` (`node_modules`, `vendor`, `.git` and virtualenvs are skipped):

| Found | Tags |
|---|---|
| `package-lock.json`, `package.json`, `yarn.lock`, `pnpm-lock.yaml`, `.nvmrc`, `.node-version` | `node`, `npm` (the version files map to `node` only) |
| `uv.lock`, `requirements.txt`, `pyproject.toml`, `.python-version` | `python`, `pypi` (`.python-version` maps to `python` only) |
| `composer.json`, `composer.lock`, `.php-version` | `php` |
| `Dockerfile`, `Containerfile`, `Dockerfile.*`, `*.Dockerfile`, `docker-compose*.yml`, `compose.yml` | `docker`, plus `php`, `node` or `python` when a `FROM` line or `image:` uses that image (`oven/bun` maps to `node`) |
| `.tool-versions`, `package.json` `volta` / `packageManager: bun@...` | the runtime they name |
| `.github/workflows/*.yml` | `github-actions` |
| `Gemfile.lock`, `go.sum` | `ruby`, `go` |

Lockfiles the monitor cannot parse, such as `composer.lock`, still choose a tag. That matters for
PHP in particular, because a PHP runtime incident needs no lockfile to apply.

It keeps only incidents with status `live` in the `patch` or `supply-chain` category.

**How it matches.** `affectedVersions` is free text, so matching is best effort. It is
conservative where it cannot be sure:

- **Packages.** An incident matches when a package from a parsed lockfile is named in its product
  or affected text. The match is whole-word and case-insensitive. Scoped names (`@x402/fetch`,
  or `nestjs/core` for `@nestjs/core`), slash lists (`next/react`), brand forms (`Next.js`,
  `Express.js`) and PyPI names with `_`, `-` or `.` all match. Package names that are also everyday
  words (`is`, `next`, `node`...) count only when a version follows them. Once they do, an
  unreadable range is reported as **check manually**, not dropped.
- **Strict grammar.** The text after a package name runs to the next installed or scoped package
  name, never to a `;` or `,` on its own, so `express 4.x before 4.19.2; 5.x before 5.0.1` is read
  as two ranges. A following line that has no package name and is only versions belongs to the
  package before it. Each clause must be consumed completely by a known form: `< X`, `<= X`, `> X`,
  `>= X, < Y`, `before X`, `prior to X`, `less than X`, `under X`, `until X`, `pre-X`, `up to X`,
  `through X`, `X and earlier`, `X or later`, `X and above`, `X+`, `X onwards`, `from X`,
  `since X`, `after X`, `X to Y`, `X - Y`, `X..Y`, `X -> Y`, `from X to Y`, `between X and Y`,
  `X.x before Y` (or `8.3 before 8.3.36`), `== X`, or a bare version list (`1.2.3, 1.2.4 and 1.2.5`). Clauses join with `,`,
  `;`, `/`, `&`, `and`, `or` or `plus`. `^X`, `~X` and `~> X` prove "affected" from inside but
  only "check manually" from outside. `fixed in X` / `(fixed X)` phrases are removed first,
  because a fixed version is not an affected one. One leftover word, number or operator in any
  clause makes the whole incident **check manually** for that package, never "not affected".
- **"Not affected" needs every line read.** It is issued in one place, and only when all of
  these hold: the sanitiser did not have to alter or truncate any of the incident's text (more
  than 12 entries, an over-long entry or a dropped character all count, so a PyPI name written with
  `_` is check); every affected line was either read for that package or runtime, or is attributed
  to something else the script recognises (an installed package, a scoped or `vendor/name` form,
  `name@<range>`, a runtime name, or an item of the incident's product field); and no clause was
  left unread. A line such as `Canary <= 14.3.0`, `Self-hosted: 14.x before 14.2.25` or
  `Windows builds: 8.4 before 8.4.10` names nothing it recognises, so the verdict is **check
  manually**. A parenthetical is dropped only when it is a bare ecosystem label (`(npm)`,
  `(PHP)`), a `(fixed X)` note, or a vulnerability label carrying a CVE/GHSA id. Anything else,
  `(including canary releases)`, `(Windows only)`, is unread text. Pre-releases are ordered
  numerically (`rc9 < rc10`, `3.0.0-rc.1` = `3.0.0rc1`), and a pre- or post-release of a version
  the incident names as a boundary (`8.3.0rc1` against `8.3.x`) is check.
- **Runtimes.** It reads the versions of PHP, Node.js, Bun and Python from Dockerfile `FROM`
  tags, compose `image:` lines, `.nvmrc`, `.node-version`, `.php-version`, `.python-version`,
  `.tool-versions`, `package.json` `volta` and `packageManager: bun@...`. Each is compared with
  the fixed version on the same release line: major.minor for PHP, Python and Bun, and the major
  for Node.js. Fixed versions are read with the same strict rules: `8.2.29 is not fixed` or
  `8.3.36 (Windows only)` is unread text, never a fix. An exact version below its line's fix
  (`php:8.3.35-cli`) is affected. At or above the fix it is "not affected" only under the rules
  above and only if no parsed affected range still contains it; otherwise it is check. A
  `FROM` tag suffix must be a known variant (`-cli`, `-fpm`, `-alpine3.20`...) or a pre-release
  (`-RC1`); any other suffix leaves the version unread. A clause like `Node.js 22 before 22.12.0,
  Bun before 1.1.38` is split at the second runtime name. A release line with no fix
  that the affected text covers (an EOL branch, for example) is a hit. A floating tag like
  `php:8.3-apache` does not pin a patch release: if its line has a fix the result is **check the
  tag/digest**, and if its line has no fix it is a hit.
- **Constraints are not deployed versions.** `composer.json` `require.php` and
  `config.platform.php`, and `package.json` `engines.node` / `engines.bun`, admit a range of patch
  levels. They are always reported as **check manually**, never as a hit and never as urgent, with
  a line saying a constraint does not identify the deployed patch level. When the constraint
  admits a line that has no fixed release for the incident (`^8.1` and an unpatched 8.1 branch),
  that is added as a one-line note.
- **Unreadable declarations are loud.** `.nvmrc` values such as `lts/*`, `lts/iron` or `node`, a
  `FROM node:lts` or build-argument tag, a non-official or mirrored image (`mirror.example.com/php`,
  `bitnami/node`), a non-string `engines` entry, or a `package.json` / `composer.json` that does not
  parse each become a runtime with no version. That runtime matches every incident for it as
  **check manually**, and the report prints a `runtime version not read` line for it. A `FROM` whose
  image cannot be resolved at all (`FROM ${BASE}`) is listed as **UNCHECKED**.
- A live **critical** or **high** incident for a detected stack that matched nothing is listed as
  **check manually**, one line each, critical first, up to 10.

Each hit shows the severity, patch status, the matched package or runtime, the affected and fixed
text, the vendor sources and the tracker link. Sources on a known vendor host (NVD, GitHub
advisories, nodejs.org, php.net and similar) are shown as `vendor:`. Any other host is shown as
`source (unverified host):`. pwn.watch is a tracker, not the vendor. Read and cite the vendor
source before acting, never the tracker page. Feed text goes through the same sanitiser as the
advisory watcher. Only printable ASCII is kept, backticks are stripped, and prose fields are
dropped.

**Ranking and exit code.** A hit is **urgent** when its patch status is `partial` or `unpatched`,
or when it matched a runtime line that has no fixed release. `partial` means the incident is not
fully patched across every affected product or line, so the hit is urgent even when a fix exists
for your own line (`php:8.3.35` with 8.3.36 released, during PHP2Shell). Urgent hits are listed
first. pwn.watch has no KEV or EPSS data, so it is combined with `--fail-on` like this:

| `--fail-on` | Fails on a pwn.watch hit when |
|---|---|
| `any` | any hit (affected) |
| `kev` / `epss` | an urgent hit: affected while the incident is not fully patched, or on a runtime line with no fixed release |

"Check manually" items never change the exit code.

**State file.** The script stores each tag's ETag together with the last incident list it kept.
It sends the ETag back as `If-None-Match`, so an unchanged feed costs a 304. A 304 has no body,
so the script matches the stored list again, and a lockfile that changed since the last run is
still checked. The ETag is sent only when that list is stored too. Vendor sources are cached per
incident until its `updatedAt` changes. The default location is a user cache directory, so a
scan never writes into the repository it scans: `$XDG_CACHE_HOME/secaudit/pwnwatch-state.json`,
or `~/.cache/secaudit/pwnwatch-state.json`. Pass `--pwnwatch-state PATH` to choose another
location, for example one a CI cache step restores. A missing or corrupt state file, a state file
written by a different version of the script, or an ETag that is not a quoted printable-ASCII
token only means a full fetch. The file is written atomically with mode `0600`. If a feed lists
more than 300 live incidents, only the first 300 are matched and the report says so. After two
vendor-source lookups fail in a row, the rest are skipped and those incidents say their vendor
sources could not be fetched.

**Run it hourly at most.** The feeds are edge-cached for 60 seconds and the publisher asks for
no more than that. The script never polls in a loop. Each run is one pass, so put the schedule in
cron or CI. Requests send a descriptive `User-Agent`.

**When pwn.watch is down.** That stack is reported as **UNCHECKED** for pwn.watch, with a
warning, and never as clean. The exit code does not change: a pwn.watch outage alone never
causes exit 2. If a cached list exists, it is still matched, and the UNCHECKED line says how old
it is. After two feeds fail in a row, the remaining feeds are skipped rather than retried one by
one. OSV, EPSS and KEV failures still exit 2, as before.

The reusable `dependency-monitor.yml` workflow does not pass `--pwnwatch`. To use it in CI, run
the script in your own workflow step.

## Keeping secaudit itself current (maintainers)

This section is about **this** repo, not an app repo. Three workflows turn a new advisory into
a reviewed PR:

1. **`advisory-watch.yml`** (every 6 hours) runs `scripts/watch-advisories.py` against the
   pwn.watch tag feeds for the stacks the skills cover. It sends each feed's ETag back as
   `If-None-Match`, so an unchanged feed costs a 304. It opens one `advisory` issue per new
   live `patch` or `supply-chain` incident, with affected and fixed versions and the vendor
   sources. A later material change (patch status, versions, CVEs) updates the same issue. It
   never opens a second one. An issue gets the `copilot-ok` label only when all three of
   these hold: it is a critical or high `patch` incident, sanitising did not have to alter
   any field, and at least one source is on a known vendor host (NVD, GitHub advisories,
   nodejs.org, php.net and similar). Sources on other hosts are listed as unverified. Every
   issue is locked as soon as it is opened.
2. **`copilot-dispatch.yml`** runs daily, and also when a person adds `copilot-ok`. Labels
   that a workflow adds do not trigger it, so those issues wait for the daily run. It
   assigns the oldest eligible issue to the Copilot coding agent. An issue is eligible
   when it has the `copilot-ok` label and an `advisory` or `freshness` label, was opened
   by `github-actions[bot]`, is locked, has nobody assigned, and has no comment from
   anyone other than an owner, member or collaborator. Copilot reads issue comments, and
   this repo is public. Copilot opens a PR. A maintainer reviews and merges it. Nothing is
   ever auto-merged.
3. **`copilot-setup-steps.yml`** gives the agent Python 3.12 on the standard
   `ubuntu-latest` runner, with a 30-minute limit.
4. **`copilot-pr-scope.yml`** fails any Copilot PR that touches anything outside
   `skills/**`, `SOURCES.md` and `scripts/check-freshness.py`. The written instructions
   ask for the same thing. This check is what actually enforces it.

pwn.watch is a tracker, not the vendor. Issues list the vendor sources, and both the
issue text and `.github/copilot-instructions.md` require every version to be verified there
before it is written into a skill.

### Spend

- **Actions minutes: zero.** The agent runs on GitHub Actions. Actions is free for public
  repos on standard GitHub-hosted runners. The dispatcher checks that the repo is public
  before every assignment and does nothing if it is private. Do not move
  `copilot-setup-steps.yml` to a larger runner, because larger runners are billed even on
  public repos.
- **Copilot premium requests: one per session.** These are capped at `COPILOT_WEEKLY_CAP`
  assignments (a repo variable, default 2, at most 10) in any rolling 7 days. The dispatcher
  also waits while any Copilot PR is open, or while an issue it handed over in the last
  24 hours has no PR yet, so only one session runs at a time. Sessions you start yourself
  (a manual assignment, or `@copilot` on a PR) also cost premium requests. Only issue
  assignments count towards the cap.

### Setup

1. Enable the Copilot coding agent for this repository in your Copilot settings.
2. Create a fine-grained personal access token scoped to this repository only, with these
   permissions: Metadata read; Actions, Contents, Issues and Pull requests read/write. The
   assignment API accepts only user tokens. `GITHUB_TOKEN` and app installation tokens are
   rejected.
3. Save it as the repository secret `COPILOT_ASSIGN_TOKEN`. Without it, the dispatcher logs
   a notice and does nothing. Advisory issues are still opened.
4. Add a branch ruleset for `main` with these settings: require a pull request; require
   review from Code Owners (`.github/CODEOWNERS` covers `.github/`, `scripts/`,
   `.roadmap/` and the plugin manifests); and require the `Copilot PR Scope / scope`
   status check. Also keep the repo setting that requires approval before workflows run on
   Copilot's PRs.
5. Give the PAT an expiry date, and rotate it when it expires.
6. Optional: set the repository variable `COPILOT_WEEKLY_CAP`.
7. To hand over a `freshness` drift issue, add `copilot-ok` to it yourself. The dispatcher
   applies the same lock and comment-author checks to it.

Copilot cannot run the roadmap CLI. After merging one of its PRs, run `/roadmap:catchup`.

Run the watcher locally:

```bash
python3 scripts/watch-advisories.py                        # last 7 days
python3 scripts/watch-advisories.py --tags php,node --since 2026-10-01
```
