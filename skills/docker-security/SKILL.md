---
name: docker-security
description: Audits Dockerfiles, Compose files, and container runtime config — secrets baked into image layers via ARG/ENV, a missing .dockerignore shipping .env and .git inside the image, containers running as root, unpinned or `latest` base images, the Docker socket mounted into a container, databases published on 0.0.0.0, hardcoded credentials in compose files, and missing runtime hardening. Use whenever the project has a Dockerfile, docker-compose.yml, or a container deploy, or when reviewing how an image is built, what it contains, and what it can reach.
license: MIT
---

# Docker & Container Security

A container is a shipping format for a filesystem plus a process, and both halves leak. The image
carries whatever the build could read — including layers you thought you deleted. The runtime
grants whatever the host handed it — including, by default, root, ~14 Linux capabilities, and a
network binding on every interface. Most container findings in vibe-coded projects are the same
mistake twice: the build copied more than it needed, and the runtime kept more than it needed.

This skill covers the container layer. For what happens after the image is running behind a URL —
security headers, source maps, CORS, preview-environment isolation — see `secaudit:deployment`.
Container misconfiguration maps to OWASP **A02:2025** (Security Misconfiguration).

## When to Use

- The project has a `Dockerfile`, `docker-compose.yml` / `compose.yaml`, or a container deploy.
- Reviewing how an image is built, what ends up inside it, or what the running container can reach.
- Adding a database, cache, or queue as a compose service.
- Auditing a self-hosted or VM deploy (Docker on a cloud VM, Coolify, Dokploy, Portainer, etc.).

## 1. Secrets Baked Into Image Layers (`ARG` / `ENV`)

The single most common container mistake. **Image layers are immutable.** Every `ARG` value used
during a build and every `ENV` value set in the Dockerfile is recoverable from the shipped image
with `docker image history` — and under BuildKit's `max` provenance mode the build args land in the
attestation attached to the pushed image too. Deleting the file in a later `RUN` does not remove
it: the earlier layer still exists, and anyone who can pull the image can read it. Assume every
image you push to a registry is readable by whoever can pull it, and every base layer is readable
by whoever can read the manifest.

```dockerfile
# BAD — NPM_TOKEN is in the build history forever; the `rm` only affects the final layer
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc \
 && npm ci \
 && rm .npmrc

# BAD — every runtime secret is now `docker inspect`-able and in the image manifest
ENV DATABASE_URL="postgres://appuser:hunter2@db.example.com:5432/prod"
ENV STRIPE_SECRET_KEY="sk_live_REDACTED"
```

```dockerfile
# GOOD — BuildKit secret mount: available only to that RUN, never written to a layer
# syntax=docker/dockerfile:1
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN="$(cat /run/secrets/npmtoken)" \
    npm ci --omit=dev
COPY . .
```

```bash
# Build with the secret passed from the environment, never as a build arg
docker build --secret id=npmtoken,env=NPM_TOKEN .
```

Compose has the same mechanism for build-time secrets:

```yaml
services:
  app:
    build:
      context: .
      secrets:
        - npmtoken
secrets:
  npmtoken:
    environment: NPM_TOKEN   # or: file: ./npmtoken.txt (gitignored)
```

**Runtime secrets are a separate problem with a separate answer:** inject them at container start
from the platform's secret store (compose `env_file`, Kubernetes secrets, your PaaS's env UI), so
they live in the container's environment but never in the image. Never `ENV` a live credential in
a Dockerfile.

**Detection:**

```bash
# ARG/ENV lines naming a credential, or a URL with inline credentials
grep -rniE '^[[:space:]]*(ARG|ENV)[[:space:]].*(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL)' \
  --include='Dockerfile*' --include='*.dockerfile' .
grep -rniE '^[[:space:]]*(ARG|ENV)[[:space:]].*://[^[:space:]/]+:[^[:space:]@]+@' \
  --include='Dockerfile*' --include='*.dockerfile' .

# Confirm against a built image — this is what an attacker with pull access runs
docker image history --no-trunc <image> | grep -iE 'token|secret|key|password|://.*:.*@'
docker image inspect <image> --format '{{json .Config.Env}}'
```

Any hit is a **Critical**: the credential is in a distributed artifact, so treat it as compromised
and rotate it — rebuilding without it does not un-publish the layers already pushed. Report it by
location and masked form only, per the redaction rule in `secaudit:secrets`.

## 2. No `.dockerignore` — `.env` and `.git` Ride Into the Image

`COPY . .` copies the build context as it exists on disk. With no `.dockerignore`, that includes
`.env` with live production credentials, the entire `.git` directory (every secret ever committed,
even ones deleted in a later commit), `node_modules` from someone's laptop, CI configs, SSH keys,
and cloud credential files.

Two things make this worse than it looks:

- **It silently defeats section 1.** You can do the BuildKit secret mount perfectly and still ship
  the credential, because `.env` walked in through `COPY . .` two lines later.
- **It is the exposed-`.git` problem by a path `secaudit:deployment` doesn't cover.** That skill
  flags `.git` served from a web root; here the same history is baked into a registry artifact,
  where no web-server rule can block it and no redeploy can remove it from an already-pushed tag.

```dockerfile
# BAD — no .dockerignore in the repo
COPY . .
```

```gitignore
# GOOD — .dockerignore at the build-context root
.git
.gitignore
.env
.env.*
!.env.example
**/node_modules
**/.venv
**/__pycache__
*.pem
*.key
.ssh
.aws
.npmrc
Dockerfile*
docker-compose*.yml
.github
coverage
*.log
```

Prefer copying what you need (`COPY package.json package-lock.json ./`, then `COPY src/ ./src/`)
over `COPY . .` plus a denylist — an allowlist cannot forget a file that gets added next month.

**Detection:**

```bash
# 1. Does it exist at all, next to each Dockerfile?
find . -name 'Dockerfile*' -not -path '*/node_modules/*' \
  -exec sh -c 'd=$(dirname "$1"); [ -f "$d/.dockerignore" ] || echo "MISSING: $d/.dockerignore"' _ {} \;

# 2. If it exists, does it actually cover the two that matter?
grep -qE '^\.env' .dockerignore && grep -qE '^\.git$|^\.git/' .dockerignore \
  || echo "FINDING: .dockerignore does not cover .env* and .git"

# 3. Verify against the built image — the only answer that isn't a guess
docker run --rm --entrypoint sh <image> -c 'ls -la /app/.env /app/.git 2>&1'
```

## 3. Container Runs as Root

A Dockerfile with no `USER` directive runs PID 1 as uid 0. Official language base images
(`node`, `python`, `golang`) do **not** switch users for you — several ship a non-root user but
leave it unselected. So any RCE in your app — a deserialization bug, a template injection, a
compromised dependency's postinstall — starts life as root *inside* the container. That means
writing to any bind-mounted host directory as root, installing tooling to pivot with, and a much
shorter path to container escape if a kernel or runtime CVE is available.

```dockerfile
# BAD — no USER; the app runs as root
FROM node:22-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
CMD ["node", "server.js"]
```

```dockerfile
# GOOD — dedicated non-root user, correct ownership, dropped before CMD
FROM node:22-alpine
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --chown=app:app package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=app:app . .
USER app
EXPOSE 3000
CMD ["node", "server.js"]
```

Install packages *before* the `USER` switch (you need root for that), then drop. If the app must
bind a port below 1024, change the port instead of staying root — inside a container the port
number is arbitrary and the host mapping can still be 80.

**Detection:**

```bash
# Dockerfiles with no USER at all
grep -rLiE '^[[:space:]]*USER[[:space:]]' --include='Dockerfile*' .

# Dockerfiles where the LAST USER directive is root (a later switch-back undoes an earlier drop)
for f in $(find . -name 'Dockerfile*' -not -path '*/node_modules/*'); do
  last=$(grep -iE '^[[:space:]]*USER[[:space:]]' "$f" | tail -1)
  case "$last" in *[Rr][Oo][Oo][Tt]*|*' 0'*) echo "FINDING: $f -> $last";; esac
done

# Runtime truth
docker exec <container> id      # uid=0(root) is the finding
```

Note that a compose `user:` key overrides the image's `USER`, in both directions — check both.

## 4. Unpinned and `latest` Base Images

`FROM node:22-alpine` resolves to whatever that tag points at *at build time*. Tags are mutable:
the image you tested locally is not necessarily the image your CI builds tomorrow, and
`FROM node:latest` is a promise to run code you have never seen. This is the container-layer twin
of the unpinned-dependency problem `secaudit:supply-chain` covers for npm — the same "a name is
not a version" failure, one layer down, where a compromised or simply changed base image brings a
new libc, a new OpenSSL, and possibly a new attacker.

Pin by **digest**, which is content-addressed and immutable, while keeping the human-readable tag
so reviewers can see what it is:

```dockerfile
# BAD
FROM node:latest
FROM python                       # bare name = implicit :latest
FROM node:22-alpine               # mutable tag; better, still not pinned

# GOOD — tag for readability, digest for integrity
# (digest below is illustrative and truncated — copy the real one from your registry)
FROM node:22-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000
```

Get the real digest with `docker buildx imagetools inspect node:22-alpine` (or from the registry
UI), and let Dependabot/Renovate bump digests on a schedule — pinning without an update path just
converts a mutability risk into a staleness risk. Keep base images minimal (`-slim`, `-alpine`,
distroless): fewer packages means fewer CVEs to triage and no shell for an attacker to land in.

**Detection:**

```bash
# FROM lines that are not digest-pinned
grep -rhniE '^[[:space:]]*FROM[[:space:]]' --include='Dockerfile*' . | grep -v '@sha256:'

# The worst offenders specifically
grep -rniE '^[[:space:]]*FROM[[:space:]]+[^[:space:]]+(:latest)?[[:space:]]*($|AS)' \
  --include='Dockerfile*' . | grep -vE '@sha256:|:[0-9]'

# Compose services pulling a floating tag
grep -rnE '^[[:space:]]*image:[[:space:]]*[^[:space:]]+(:latest)?[[:space:]]*$' \
  --include='*compose*.y*ml' . | grep -v '@sha256:'
```

## 5. The Docker Socket Mounted Into a Container

`/var/run/docker.sock` is the Docker Engine API. Anything that can talk to it can start a new
container that is `--privileged` with the host's `/` bind-mounted — which is root on the host, full
stop. There is no lesser interpretation: **socket access is host root access.** Assistants add this
mount reflexively for anything that lists, restarts, or inspects containers (dashboards, log
viewers, "auto-deploy" watchers, CI runners).

**`:ro` does not help.** This is the part that gets missed, because the flag reads like a
mitigation. Read-only applies at the *filesystem mount* level: it stops writes to the socket
*file* (its inode, permissions, contents). The Docker API is not spoken by writing to that file —
it is spoken over the Unix socket with `connect(2)` / `sendmsg(2)` / `recvmsg(2)`, which a
read-only mount does not restrict. So `docker.sock:ro` grants a container full read **and write**
access to the Docker API while looking safe in review. Treat `:ro` on a socket mount as a false
label, not a control.

```yaml
# BAD — both of these are host root
services:
  dashboard:
    image: some/dashboard
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  watcher:
    image: some/watcher
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro   # NOT read-only for API purposes
```

```yaml
# GOOD — broker through a filtering socket proxy with an explicit read-only allowlist
services:
  dockerproxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1        # allow GET /containers
      IMAGES: 1
      POST: 0              # deny every mutating call
      EXEC: 0
      VOLUMES: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro   # only the proxy touches the socket
    networks: [dockerproxy]

  dashboard:
    image: some/dashboard
    environment:
      DOCKER_HOST: tcp://dockerproxy:2375             # no socket in this container at all
    networks: [dockerproxy, web]

networks:
  dockerproxy:
    internal: true
```

The proxy still holds host root, so keep it on an `internal: true` network, publish no port for it,
and keep `POST: 0` unless a specific mutating endpoint is genuinely required. If the workload needs
to *build* images, use a rootless builder (BuildKit in rootless mode) rather than the host socket.

**Detection:**

```bash
# Every hit is a finding, :ro or not
grep -rn 'docker\.sock' --include='*.y*ml' --include='Dockerfile*' --include='*.sh' \
  --include='*.tf' --include='*.json' .

# Running containers that hold it
docker ps -q | xargs -r docker inspect \
  --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' | grep docker.sock
```

## 6. Databases and Caches Published on `0.0.0.0`

In compose, `ports: ["5432:5432"]` is short form for `0.0.0.0:5432:5432` — **all** host interfaces,
including the public one. On any cloud VM without a separate firewall, that is Postgres on the
internet, found by internet-wide scanners within hours. Combine with section 7's default password
and it is a complete database takeover with no exploit required.

**Docker's iptables rules bypass UFW.** Docker inserts its forwarding rules into the `DOCKER`
chain in `nat`/`filter`, which is evaluated before the `INPUT` chain that UFW manages. An admin who
ran `ufw deny 5432` and saw it accepted may still have Postgres reachable from the internet. Never
accept "the firewall covers it" without checking from outside the host.

The key question is whether the port needs to leave the compose network at all. Services that only
talk to each other reach each other by service name on the compose network — **no host port
needed**, and publishing one adds exposure and buys nothing.

```yaml
# BAD — Postgres and Redis on every host interface
services:
  db:
    image: postgres:17
    ports: ["5432:5432"]
  cache:
    image: redis:7
    ports: ["6379:6379"]
```

```yaml
# GOOD — internal-only; the app reaches them at postgres://db:5432 and redis://cache:6379
services:
  app:
    build: .
    ports: ["127.0.0.1:3000:3000"]   # only the reverse proxy on this host reaches the app
    networks: [frontend, backend]
    environment:
      DATABASE_URL: postgres://app@db:5432/app   # service name, no host port involved
  db:
    image: postgres:17
    networks: [backend]              # no `ports:` at all
  cache:
    image: redis:7
    networks: [backend]

networks:
  frontend:
  backend:
    internal: true                   # no external connectivity for this network
```

If a human genuinely needs host access (a migration tool, a GUI client), bind loopback only —
`"127.0.0.1:5432:5432"` — and reach it over an SSH tunnel. Loopback binding is the difference
between "reachable by anyone" and "reachable by someone already on the box."

**Detection:**

```bash
# Short-form port mappings with no IP prefix — prioritise datastore ports
grep -rnE '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+"?[[:space:]]*$' --include='*compose*.y*ml' .
grep -rnE '(^|[^0-9.])(5432|3306|6379|27017|9200|11211|5672|9092):[0-9]+' \
  --include='*compose*.y*ml' .

# What is actually published right now
docker compose ps --format '{{.Name}}\t{{.Publishers}}'
ss -lntp | grep -vE '127\.0\.0\.1|::1'     # anything on 0.0.0.0 is internet-facing on a VM
```

Confirm from **off** the host (`nmap -Pn -p 5432,6379,27017 <public-ip>` from elsewhere) — a local
check cannot tell you what the internet sees.

## 7. Hardcoded Credentials in Compose Files

`docker-compose.yml` is committed to the repo, so `POSTGRES_PASSWORD: postgres` is not a local
convenience — it is a repository-wide credential, shared with every fork, every CI log, and every
contributor who ever cloned. And `environment:` values are readable at runtime by anyone who can
run `docker inspect` on the host or read `/proc/<pid>/environ` for the process. Chained with
section 6's published port, this is direct, unauthenticated database takeover.

This is the container-shaped instance of the default-credentials pattern `secaudit:secrets` greps
for in application source — same failure, different file, and one that source-code greps for
`password123` will miss because the literal lives in YAML.

```yaml
# BAD — a committed credential, and `docker inspect`-readable at runtime
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_USER: postgres
  app:
    environment:
      JWT_SECRET: supersecret
      STRIPE_SECRET_KEY: sk_live_REDACTED
```

```yaml
# GOOD — file-based compose secrets, mounted at /run/secrets/<name>, never in the repo
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_USER: app
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password   # Postgres reads the file, not an env value
    secrets: [db_password]
  app:
    build: .
    environment:
      DATABASE_URL_FILE: /run/secrets/db_url
    secrets: [db_url]

secrets:
  db_password:
    file: ./secrets/db_password.txt    # gitignored, mode 0600
  db_url:
    file: ./secrets/db_url.txt
```

The `*_FILE` convention is supported by the official Postgres, MySQL/MariaDB, and Redis images and
by many others; for your own app, read the file at startup rather than accepting the value as an
env var. Keep an `.env` (gitignored, referenced via `${VAR}` interpolation or `env_file:`) as the
lighter-weight option, and commit a placeholder-only `.env.example`.

**Detection:**

```bash
# A literal value (not ${VAR}) after a credential-shaped key
grep -rniE '^[[:space:]]*-?[[:space:]]*[A-Z_]*(PASSWORD|SECRET|TOKEN|_KEY|APIKEY)[A-Z_]*[:=][[:space:]]*["'"'"']?[^$[:space:]{]' \
  --include='*compose*.y*ml' --include='*.env' .

# Confirm the secret material is not tracked
git ls-files | grep -E '^\.env$|^secrets/|\.env\.(local|production)$'

# Runtime exposure of anything set via `environment:`
docker inspect <container> --format '{{json .Config.Env}}'
```

Any credential found in a committed compose file is already in git history — rotate it, do not just
edit the file. See `secaudit:secrets` for the redaction rule when reporting.

## 8. No Runtime Hardening

Docker's defaults are permissive because they optimize for "it runs," not "it contains." A default
container gets roughly 14 Linux capabilities (including `CHOWN`, `SETUID`, `NET_RAW`, `MKNOD`), a
writable root filesystem, permission to gain privileges through setuid binaries, and unbounded
memory and PIDs. Individually none of these is an exploit; together they turn a contained,
app-level RCE into persistence (write a binary into the image's filesystem, escalate via a setuid
helper, spawn a reverse shell) and let one compromised or merely buggy service exhaust the host's
memory or process table and take every other service down with it.

Treat this as **blast-radius reduction** — a hardening checklist item, not a Critical on its own.
It is what decides whether an incident is "one container was compromised" or "the host was."

```yaml
# GOOD — a hardened production service
services:
  app:
    image: myapp@sha256:0000000000000000000000000000000000000000000000000000000000000000
    user: "10001:10001"              # non-root even if the image forgot (see section 3)
    read_only: true                  # immutable root filesystem
    tmpfs:
      - /tmp:size=64m,mode=1777      # writable scratch that vanishes on restart
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]      # add back only what is provably needed, or nothing
    security_opt:
      - no-new-privileges:true       # setuid binaries cannot escalate
    pids_limit: 256                  # fork bombs stay contained
    mem_limit: 512m
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
```

Start with `cap_drop: [ALL]` and add back only what breaks — most web apps need nothing. If
`read_only: true` breaks the app, find what it writes and give it a `tmpfs` or a named volume
rather than reverting. Prefer named volumes over host bind mounts, and mount read-only (`:ro`) any
host path the container only needs to read (unlike a socket, a *filesystem* bind mount genuinely is
read-only with `:ro`).

**Detection:**

```bash
# Production services with none of the hardening keys present
grep -rLE 'cap_drop|read_only|no-new-privileges|pids_limit|mem_limit' --include='*compose*.y*ml' .

# Higher-severity findings — each of these is a separate, worse problem
grep -rnE 'privileged:[[:space:]]*true' --include='*.y*ml' .           # ~= root on the host
grep -rn '\-\-privileged' --include='*.sh' --include='*.y*ml' .
grep -rnE 'network_mode:[[:space:]]*["'"'"']?host' --include='*.y*ml' .  # no network namespace;
                                                                        # ignores port bindings
grep -rnE 'pid:[[:space:]]*["'"'"']?host|ipc:[[:space:]]*["'"'"']?host' --include='*.y*ml' .

# Runtime check
docker inspect <container> \
  --format '{{.HostConfig.Privileged}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.ReadonlyRootfs}}'
```

`privileged: true` and `network_mode: host` are not hardening gaps — they are removals of the
container boundary itself, and each deserves its own finding well above checklist severity.

## Container Footgun Checklist

- `ARG`/`ENV` holding a credential — it is in `docker image history` forever; rotate, don't rebuild.
- No `.dockerignore` next to a Dockerfile that does `COPY . .` — `.env` and `.git` are in the image.
- No `USER` directive, or a `USER root` that comes after the drop.
- `FROM` with no `@sha256:` digest, and especially `:latest` or a bare image name.
- `docker.sock` mounted anywhere — `:ro` is not a mitigation, it is a mislabel.
- `ports:` on a database, cache, or search service; short form means `0.0.0.0`, and UFW may not
  cover it.
- A literal password/secret in a compose file — it is in git history and in `docker inspect`.
- No `cap_drop` / `read_only` / `no-new-privileges` / `pids_limit` on production services.
- `privileged: true`, `network_mode: host`, `pid: host` — the boundary is gone, not just weakened.

## Sources

- https://docs.docker.com/build/building/best-practices/ -- Dockerfile best practices, non-root USER
- https://docs.docker.com/build/building/secrets/ -- build secrets; why ARG/ENV leak into layers
- https://docs.docker.com/reference/dockerfile/ -- ARG/ENV/USER/FROM directive reference
- https://docs.docker.com/build/concepts/context/ -- build context and `.dockerignore`
- https://docs.docker.com/reference/compose-file/services/ -- ports, cap_drop, security_opt, user
- https://docs.docker.com/reference/compose-file/secrets/ -- file/environment compose secrets
- https://docs.docker.com/engine/security/ -- daemon attack surface; socket access is root access
- https://docs.docker.com/engine/network/packet-filtering-firewalls/ -- Docker's iptables rules vs UFW
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html -- OWASP Docker cheat sheet
- https://www.cisecurity.org/benchmark/docker -- CIS Docker Benchmark
