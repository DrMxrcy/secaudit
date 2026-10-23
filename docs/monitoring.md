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
