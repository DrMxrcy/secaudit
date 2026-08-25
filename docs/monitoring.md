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
