---
name: proxy-trust
description: Audits how an app behind a reverse proxy, tunnel, or forward-auth gateway decides who and where a request came from. Covers what `X-Forwarded-For`/`X-Forwarded-Proto`/`X-Forwarded-Host`/`X-Forwarded-Prefix` and `Forwarded` mean and when a framework's trust setting believes them — Express `trust proxy` (why `true` is a footgun), Koa `app.proxy`/`maxIpsCount`, Fastify `trustProxy` (numeric hop-count trust disabled after CVE-2026-16732), Next.js Server Actions Origin-vs-`x-forwarded-host`; rate limits, IP allowlists and audit logs keyed on a spoofable header; Host-header trust in absolute-URL generation, password-reset poisoning, and Koa CVE-2026-27959; forward-auth deployments (Traefik `forwardAuth`, Caddy `forward_auth`, nginx `auth_request`) and identity-header injection (`Remote-User`, `X-Forwarded-User`, `X-Auth-Request-*`), including Traefik CVE-2026-35051/39858/54764; Cloudflare Tunnel/Access `Cf-Access-Jwt-Assertion` JWT verification against the team JWKS; and Tailscale Serve identity headers. Use whenever the project sets a framework's `trust proxy`/`trustProxy`/`app.proxy`/`trustHost` option, reads `X-Forwarded-For`, defines a `forwardAuth`/`forward_auth`/`auth_request` block, runs a Traefik/Caddy/nginx/nginx-proxy-manager compose service, or sits behind Cloudflare Tunnel/Access or Tailscale Serve.
license: MIT
---

# Reverse Proxies and Edge Auth (Proxy Trust)

Every header your app reads about the request — who sent it, what host they asked for, what
scheme they used — is, by default, whatever the *last hop before your process* put there. If
that hop is a reverse proxy you control, those headers are metadata. If it isn't — if your
process is also reachable directly, or the proxy forwards a header without overwriting it — those
same headers are attacker input with a trustworthy-sounding name.

The recurring AI-codegen failure mode is a deployment that *works in the demo*. `app.set('trust
proxy', true)` makes rate limiting, `req.ip`, and `req.secure` all report sane-looking values
behind the load balancer the developer tested against, so it ships. A `forwardAuth` block gets
wired up because the tutorial's `docker-compose.yml` had one, and the app reads
`X-Forwarded-User` because that is the header the auth proxy happens to set — nobody asked what
stops a client from setting it directly. A `Cf-Access-Authenticated-User-Email` header shows up in
every request once Access is turned on, so it becomes the identity, because checking a header is
one line and verifying a JWT is not. Every one of these choices is the documented wrong answer,
and every one of them produces a working feature in staging.

The findings in this skill map to **A01:2025** (Broken Access Control) — a spoofed forwarded
header defeating an IP allowlist or a forward-auth gate is unauthorized access, not a
configuration nit — **A02:2025** (Security Misconfiguration) — the permissive trust-proxy default,
the missing Host allowlist, the unverified Access header are all settings, not code bugs — and
**A07:2025** (Authentication Failures) — an identity header that either side can forge is not
authentication.

## When to Use

- A framework's proxy-trust option is set or read: Express `trust proxy`, Koa `app.proxy` /
  `maxIpsCount`, Fastify `trustProxy`, Next.js `experimental.serverActions.allowedOrigins`, or any
  framework's `trustHost` / `USE_X_FORWARDED_HOST` equivalent.
- Code reads `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Prefix`, the
  `Forwarded` header, or builds an absolute URL / redirect / cookie domain from `req.hostname` /
  `ctx.host` / the `Host` header.
- A `forwardAuth` (Traefik), `forward_auth` (Caddy), or `auth_request` (nginx) block exists, or the
  compose file runs a `traefik`, `caddy`, `nginx`, or `nginx-proxy-manager` service in front of the
  app.
- The backend reads an identity header set by a proxy — `Remote-User`, `Remote-Groups`,
  `Remote-Email`, `X-Forwarded-User`, `X-Auth-Request-User`, `X-Auth-Request-Email`.
- The project uses Cloudflare Tunnel / Access (`cloudflared`, `Cf-Access-Jwt-Assertion`,
  `cf-connecting-ip`) or Tailscale Serve/Funnel.

Grep heuristics — these find most of it:

```bash
grep -rnE "trust proxy|app\.proxy|trustProxy|trustHost|USE_X_FORWARDED_HOST" --include='*.{js,ts,py}' .
grep -rniE 'x-forwarded-(for|proto|host|prefix)|forwarded:' --include='*.{js,ts,py,go}' .
grep -rniE 'forwardAuth|forward_auth|auth_request' . --include='*.yml' --include='*.yaml' --include='Caddyfile' --include='*.conf'
grep -rlE '^\s*(traefik|caddy|nginx|nginx-proxy-manager):' docker-compose*.yml compose*.yml 2>/dev/null
grep -rniE 'remote-user|remote-email|x-forwarded-user|x-auth-request-' --include='*.{js,ts,py,go}' .
grep -rniE 'cf-access-jwt-assertion|cf-connecting-ip|cloudflared|tailscale.*serve' .
```

## 1. What the Forwarded Headers Mean, and When a Framework Believes Them

**What to look for:** `app.set('trust proxy', true)` or `trustProxy: true` in Express/Fastify;
`app.proxy = true` in Koa with no IP restriction anywhere in front of it; a Fastify `trustProxy`
set to a bare number (`trustProxy: 1`); code that reads `req.ip`, `req.hostname`, `req.protocol`,
`ctx.host`, or `request.protocol` and treats the result as trustworthy without first confirming
the proxy chain is closed.

**Why it's exploitable:** none of these headers are self-authenticating. RFC 7239 says it
plainly: "The 'Forwarded' HTTP header field cannot be relied upon to be correct, as it may be
modified, whether mistakenly or for malicious reasons, by every node on the way to the server,
including the client making the request." A framework's trust setting exists to answer one
question — *how many of the rightmost hops in this header do I believe are my own proxies* — and
getting it wrong doesn't fail loudly, it just reports the wrong client.

- **Express `trust proxy`.** The boolean form is the trap: "If `true`, the client's IP address is
  understood as the left-most entry in the `X-Forwarded-For` header" — the *left-most* entry is
  the one furthest from your server, i.e. whatever the original client sent. Express's own warning
  is explicit: "it is important to ensure that the last reverse proxy trusted is
  removing/overwriting all of the following HTTP headers: `X-Forwarded-For`, `X-Forwarded-Host`,
  and `X-Forwarded-Proto`, otherwise it may be possible for the client to provide any value." The
  safe forms are a hop **count** ("the address that is at most `n` number of hops away… a value of
  `0` means there is no reverse proxy") or an explicit **IP/subnet list**, never the bare boolean.
  Once trusted, `req.hostname` and `req.protocol` are also derived from `X-Forwarded-Host` /
  `X-Forwarded-Proto` — the same trust decision governs identity, host, and scheme together.
- **Koa `app.proxy`.** `app.proxy` "when true[,] proxy header fields will be trusted";
  `app.proxyIpHeader` defaults to `X-Forwarded-For`; `app.maxIpsCount` — "max ips read from proxy
  ip header, default to 0 (means infinity)" — is the hop-count equivalent, and leaving it at the
  default lets an attacker pad the header with extra entries to walk `request.ips` off the end of
  what your proxy actually added.
- **Fastify `trustProxy`.** Modern Fastify explicitly refuses the naive number-only trust it used
  to offer: "Hop-count-only trust is disabled because it cannot validate the immediate peer and
  lets direct clients spoof X-Forwarded-* values. Use an IP/CIDR string, array, or custom function
  that validates the proxy address instead." That's not a style preference — it's the fix for two
  real CVEs (below). The docs underline the general rule too: these values "must be treated as
  untrusted input unless your proxy chain is explicitly trusted and validated," and "hop-count-only
  checks such as `hop < 1` are unsafe when the Fastify origin can be reached directly" — the same
  failure mode as a permissive Express boolean, just in a custom function instead of a config
  value.
  - **CVE-2026-3635** (fixed **5.8.3**): with a *restrictive* `trustProxy` (an IP, CIDR, or custom
    function — not `true`), `request.protocol` and `request.host` still read `X-Forwarded-Proto` /
    `X-Forwarded-Host` "from any connection — including connections from untrusted IPs," so an
    attacker who reaches Fastify directly spoofs the scheme and host the app believes it's serving
    even though the trust config looked strict.
  - **CVE-2026-16732** (fixed **5.12.1**): the 3635 fix added a guard, but it only checked forms
    that inspect the connecting address (IP, CIDR, function). "The hop-count form, where
    `trustProxy` is set to a number, compiles to a predicate that structurally ignores the
    address, so the guard is always satisfied for any hop count of one or more" — `trustProxy: 1`
    stayed spoofable. This is why the numeric form is gone entirely in current Fastify; if you see
    it in a codebase, the dependency predates the fix regardless of what the trust value looks
    like.
- **Next.js Server Actions.** The framework's own CSRF defense is a Host comparison: "Next.js
  compares the host in a request's `Origin` header against the app's own host, taken from
  `x-forwarded-host` or `host`, and rejects the action when the two differ." Two footguns follow.
  First, "a request that carries no `Origin` header at all is allowed through with a warning
  rather than rejected" — don't assume every request without an `Origin` was already stopped.
  Second, behind a reverse proxy that forwards its *own* hostname instead of the public one ("the
  browser sends `my-proxy.com` while the server reports something like `localhost:3000`"), the fix
  is `experimental.serverActions.allowedOrigins`, not disabling the check — and if an attacker can
  reach the origin directly, or the proxy passes through a client-supplied
  `x-forwarded-host`, they control the side of the comparison the server trusts.

**Fix:** never use the bare boolean/all-trusting form. Configure the exact number of hops your own
proxy chain adds, or an explicit list of proxy IPs/CIDRs, and make sure the proxy itself strips
any client-sent copy of these headers before adding its own (§4 goes into the strip-and-set
pattern for identity headers; the same logic applies here).

```js
// server.js — BAD: trusts whatever the client puts leftmost in X-Forwarded-For
const app = express();
app.set('trust proxy', true);              // req.ip is now attacker-chosen
app.get('/whoami', (req, res) => res.send(req.ip));
```

```js
// server.js — GOOD: exactly one hop trusted (this app's own load balancer)
const app = express();
app.set('trust proxy', 1);                 // or an explicit IP/CIDR list
```

```js
// fastify — BAD: numeric hop count, spoofable even on patched Fastify per CVE-2026-16732
const app = Fastify({ trustProxy: 1 });
```

```js
// fastify — GOOD: validate the connecting peer, not just count hops
const app = Fastify({
  trustProxy: (address) => address === '10.0.0.5',   // only this proxy's address
});
```

**Detection:**

```bash
grep -rnE "trust proxy'\s*,\s*true|trustProxy:\s*true|trustProxy:\s*[0-9]+" --include='*.{js,ts}' .
grep -rn "app.proxy\s*=\s*true" --include='*.{js,ts}' . ; grep -rn "maxIpsCount" --include='*.{js,ts}' .
node -p "require('./package.json').dependencies.fastify" 2>/dev/null   # compare against 5.12.1 floor
grep -rn "allowedOrigins" next.config.* 2>/dev/null || echo "check: proxy behind Next.js forwarding its own host?"
```

## 2. IP-Keyed Controls Bypass: Rate Limits, Allowlists, Audit Logs

**What to look for:** a rate limiter, an admin IP allowlist, or an audit-log "source IP" field
keyed on `X-Forwarded-For` (or `req.ip`/`ctx.ip` with an unverified trust setting from §1); the
first element of a parsed XFF list used as *the* client IP with no bound on how many entries are
trusted.

**Why it's exploitable:** MDN states the rule as plainly as it can be stated: "Any security-related
use of X-Forwarded-For (such as for rate limiting or IP-based access control) must only use IP
addresses added by a trusted proxy. Using untrustworthy values can result in rate-limiter
avoidance, access-control bypass, memory exhaustion, or other negative security or availability
consequences." And the header is attacker-writable by design: "If the server can be directly
connected to from the internet — even if it is also behind a trusted reverse proxy — no part of
the X-Forwarded-For IP list can be considered trustworthy or safe for security-related uses."

Concretely: if a rate limiter reads the leftmost XFF entry, an attacker defeats it by sending a
fresh, made-up value on every request — each request looks like it came from a new IP, so the
limiter never accumulates a count against the real source. express-rate-limit ships a dedicated
error for exactly this misconfiguration, `ERR_ERL_PERMISSIVE_TRUST_PROXY`: "If this is set to
true, it will cause express to return the leftmost entry in the `X-Forwarded-For` header as the
client's IP. This header could be set by the proxy or a malicious client, opening up avenues for
bypassing the rate limiter." The mirror-image misconfiguration also has its own error,
`ERR_ERL_UNEXPECTED_X_FORWARDED_FOR` — an `X-Forwarded-For` header arrives but `trust proxy` is
off, which "usually indicates a configuration issue that will cause express-rate-limit to apply
it's limits global rather than on a per-user basis" — every request pools into one bucket keyed on
the load balancer's own address, and one busy legitimate user locks out everyone.

Both directions come from the same root cause: the limiter's notion of "the client" and the
framework's trust-proxy configuration have to agree, or the limiter is either bypassable or
useless.

**Fix:** fix the trust-proxy setting first (§1) — a correct hop count or IP list makes `req.ip`
itself safe to key on, so most rate limiters need no special-case code once that's right. Verify
with a real request, not just a value in a header: express-rate-limit's own troubleshooting guide
recommends `app.get('/ip', (request, response) => response.send(request.ip))`, called from outside
the proxy, and "keep increasing the number [of trusted hops] until it does" match. Never derive an
allowlist decision or an audit-log identity from an XFF value that wasn't validated against a known
proxy count.

```js
// BAD — leftmost XFF entry is attacker-controlled; ERR_ERL_PERMISSIVE_TRUST_PROXY territory
app.set('trust proxy', true);
app.use(rateLimit({ windowMs: 60_000, max: 5 }));   // keyed on req.ip, which the client picked
```

```js
// GOOD — hop count matches the real proxy chain, so req.ip is the actual client
app.set('trust proxy', 1);                          // exactly one load balancer in front
app.use(rateLimit({
  windowMs: 60_000, max: 5,
  validate: { xForwardedForHeader: true },          // fail loudly on drift instead of silently
}));
```

**Detection:**

```bash
grep -rnE "req\.headers\['x-forwarded-for'\]|request\.header\('x-forwarded-for'\)" --include='*.{js,ts,py}' . \
  | xargs -I{} echo "check: is trust proxy / trustProxy set to a matching hop count nearby?"
grep -rn "ERR_ERL_PERMISSIVE_TRUST_PROXY\|ERR_ERL_UNEXPECTED_X_FORWARDED_FOR" .   # already firing?
```

## 3. Host-Header Trust: Absolute URLs, Password-Reset Poisoning, and Failing Closed

**What to look for:** a password-reset, email-verification, invite, or webhook-callback link built
from `req.hostname` / `ctx.host` / the raw `Host` header instead of a configured application URL;
no allowlist of accepted hostnames anywhere in the app; Koa's `ctx.hostname` used for anything
security-relevant on a version before the fix below.

**Why it's exploitable:** PortSwigger's framing is the canonical one: "HTTP Host header attacks
exploit vulnerable websites that handle the value of the Host header in an unsafe way." The classic
chain is password-reset poisoning — the attacker requests a reset with an injected `Host` (or
`X-Forwarded-Host`) header pointing at a server they control; the app builds the reset link from
that header; the victim's own inbox delivers a link whose domain is the attacker's; the victim
clicks it, and the reset token lands in the attacker's server logs. The same header, believed for
absolute-URL generation, poisons OAuth `redirect_uri` construction, cache keys, and any
canonical-URL logic the same way.

**Koa `ctx.hostname` — CVE-2026-27959** (fixed **3.1.2** / **2.16.4**): "Koa's `ctx.hostname` API
performs naive parsing of the HTTP Host header, extracting everything before the first colon
without validating the input conforms to RFC 3986 hostname syntax. When a malformed Host header
containing a `@` symbol is received, `ctx.hostname` returns `evil[.]com`" — an attacker-chosen
value slips out of a parser that looks like it's just reading metadata. Any app using
`ctx.hostname` for URL generation, reset links, or routing on an unpatched Koa is exploitable this
way with no other misconfiguration required.

**Fix — treat the Host header the way Django treats it.** `ALLOWED_HOSTS` is the model to copy in
any framework: "A list of strings representing the host/domain names that this Django site can
serve. This is a security measure to prevent HTTP Host header attacks, which are possible even
under many seemingly-safe web server configurations." Two details matter for the port to other
stacks: the check "only applies via `get_host()`; if your code accesses the `Host` header directly
… you are bypassing this security protection" — an allowlist that exists but isn't on the code path
that actually builds the URL protects nothing — and `X-Forwarded-Host` is honored *only* when
explicitly opted in (`USE_X_FORWARDED_HOST`, off by default), which "should only be enabled if you
have a proxy in front of Django that sets this header." Never derive the canonical origin for
security-sensitive URLs from a request header at all when you can hardcode or configure it —
PortSwigger's own mitigation says the same: "specify the current domain in config, not from the
request; disable Host-override headers such as `X-Forwarded-Host`." When a request's Host doesn't
match anything you expect, reject it — don't try to guess which domain the operator meant.

```js
// BAD — the reset link's domain comes straight from whatever the client sent
app.post('/reset-password', async (req, res) => {
  const link = `${req.protocol}://${req.hostname}/reset?token=${token}`;   // Host-poisonable
  await sendEmail(user.email, link);
});
```

```js
// GOOD — the origin is app config, never derived from the request
const APP_ORIGIN = process.env.APP_ORIGIN;    // e.g. "https://app.example.com" — not a header
const ALLOWED_HOSTS = new Set([new URL(APP_ORIGIN).host]);

app.use((req, res, next) => {
  if (!ALLOWED_HOSTS.has(req.headers.host)) return res.status(421).end();   // fail closed
  next();
});

app.post('/reset-password', async (req, res) => {
  const link = `${APP_ORIGIN}/reset?token=${token}`;   // config, not the request
  await sendEmail(user.email, link);
});
```

**Detection:**

```bash
grep -rnE 'req\.(hostname|headers\.host)|ctx\.(host|hostname)' --include='*.{js,ts}' . \
  | grep -iE 'reset|invite|verify|callback|redirect'          # Host used to build a sensitive URL
node -p "require('./package.json').dependencies.koa" 2>/dev/null   # compare against 3.1.2 / 2.16.4
grep -rn "ALLOWED_HOSTS\|USE_X_FORWARDED_HOST" **/settings*.py 2>/dev/null
```

## 4. Forward-Auth Deployments: Traefik, Caddy, nginx, and Identity-Header Injection

**What to look for:** a Traefik `forwardAuth` middleware, a Caddy `forward_auth` directive, or an
nginx `auth_request` block in front of an app that reads an identity header the gateway is
*supposed* to set — `Remote-User`, `Remote-Groups`, `Remote-Email`, `X-Forwarded-User`,
`X-Auth-Request-User`, `X-Auth-Request-Email`; no explicit strip of the same header names from the
*incoming* client request before the auth check runs; `trustForwardHeader` used without a
corresponding `forwardedHeaders.trustedIPs` on the entry point.

**Why it's exploitable:** the whole pattern rests on one guarantee — the app trusts an identity
header *only because* the app is unreachable except through the gateway that sets it. Break that
guarantee anywhere and the header becomes exactly as trustworthy as a client-typed string. Authelia
states the mechanism directly: "the backend application is not able to determine this reliably,
instead the TCP source address of the request to the application is used, which is made by the
reverse proxy. This also means your proxy must ensure only Authelia is setting these headers, and
any other headers are never forwarded to the backend and are instead replaced by the Authelia
headers." oauth2-proxy's warning about its own forwarded-header mode is the same idea from the
other side: "If you leave [`--trusted-proxy-ip`] unset, OAuth2 Proxy currently trusts all source
IPs for backwards compatibility, which means a client that can reach OAuth2 Proxy directly may be
able to spoof forwarded headers."

**How each gateway actually works:**

- **Traefik `forwardAuth`.** "If the service answers with a 2XX code, access is granted, and the
  original request is performed." Traefik forwards `X-Forwarded-Method`, `X-Forwarded-Proto`,
  `X-Forwarded-Host`, `X-Forwarded-Uri`, and `X-Forwarded-For` to the auth service; identity
  headers travel back via `authResponseHeaders` — "List of headers to copy from the authentication
  server response and set on forwarded request, replacing any existing conflicting headers" (the
  key phrase is *replacing* — that's what makes a spoofed client copy harmless once configured
  right) — and `authRequestHeaders` narrows what the app sends *to* the auth server. Traefik's
  `trustForwardHeader` option is marked deprecated in current docs; the current guidance is to set
  `forwardedHeaders.trustedIPs` on the entry point (so Traefik itself only believes forwarded
  headers from IPs you name) and pair that with `trustForwardHeader: true`, rather than trusting
  the option alone.
- **Caddy `forward_auth`.** "An opinionated directive which proxies a clone of the request to an
  authentication gateway, which can decide whether handling should continue, or needs to be sent to
  a login page." `copy_headers` controls what comes back: "HTTP header fields to copy from the
  response to the original request, when the request has a success status code" — on a 2xx, "the
  header fields in `copy_headers` are copied to the original request, and handling continues." Only
  list the identity headers you actually mean to trust; anything not named there is not
  overwritten by the auth response and could still carry through whatever the client sent.
- **nginx `auth_request`.** "implements client authorization based on the result of a subrequest.
  If the subrequest returns a 2xx response code, the access is allowed." `auth_request_set` pulls
  values *out of* the subrequest response ("`$upstream_http_*`") into variables you then explicitly
  assign to the headers sent upstream — nginx gives you no automatic identity-header passthrough at
  all, which is safer by default but means a copy-pasted config that forgets `auth_request_set`
  silently sends no identity at all, or a badly written one echoes the client's own header back
  unchanged.

**Traefik's own three CVEs are the "what does 'strip client headers' actually mean" lesson:**

- **CVE-2026-35051** (fixed **2.11.43**, **3.6.14**, **3.7.0-rc.2**) — "authentication bypass
  vulnerability in Traefik's ForwardAuth middleware when `trustForwardHeader=false` is configured
  and Traefik is deployed behind a trusted upstream proxy," via a spoofed `X-Forwarded-Prefix`.
  Setting the option to `false` was the documented "safe" choice and was not sufficient on its own.
- **CVE-2026-39858** (fixed **2.11.43**, **3.6.14**, **3.7.0-rc.2**) — "sanitization logic targets
  only canonical header names (e.g., `X-Forwarded-Proto`) and does not strip or normalize alias
  variants that use underscores instead of dashes (e.g., `X_Forwarded_Proto`). These unsanitized
  alias headers are forwarded intact to the authentication backend. When the backend normalizes
  underscore and dash header forms equivalently, an attacker can inject spoofed trust context" —
  the takeaway generalizes past Traefik: any header-stripping logic that matches on one exact
  spelling is bypassable by a backend (or a downstream framework) that treats `-` and `_` as
  interchangeable.
- **CVE-2026-54764** (fixed **v2.11.51**, **v3.6.22**, **v3.7.6**) — even with
  `trustForwardHeader: false`, Traefik "derives the `X-Forwarded-Port` header sent to the
  authentication service from the original incoming request instead of the sanitized forwarded
  request," so "an unauthenticated remote attacker can inject an `X-Forwarded-Proto: https` header
  over a plain HTTP connection and cause Traefik to forward `X-Forwarded-Port: 443`… bypassing
  port-based authorization checks."

The pattern across all three: a config flag that sounds like "don't trust client headers" covered
one code path and missed another. Pin to a fixed version — don't treat the flag alone as the
control.

**Fix:** pin Traefik ≥ 2.11.51 / 3.6.22 / 3.7.6 (which supersedes the two 2.11.43/3.6.14/3.7.0-rc.2
fixes above). Configure `forwardedHeaders.trustedIPs` on the entry point rather than relying on
`trustForwardHeader` alone. On every gateway, explicitly name which headers the auth response is
allowed to set (`authResponseHeaders`, `copy_headers`, `auth_request_set`) and never let the
client's own copy of an identity header reach the app unmodified — the gateway must *overwrite*,
not merge. Fail closed: if the gateway can't determine the Host or the auth subrequest errors,
return 401/421, don't fall through to "allow."

```yaml
# docker-compose.yml — BAD: forwardAuth wired up, but nothing strips the client's own headers
services:
  app:
    image: myapp
  traefik:
    image: traefik:v3.5
    command:
      - --providers.docker
    labels:
      - traefik.http.middlewares.auth.forwardauth.address=http://authelia:9091/api/verify
      - traefik.http.middlewares.auth.forwardauth.trustForwardHeader=true   # deprecated option, alone
```

```yaml
# docker-compose.yml — GOOD: entry point pins which IPs may set forwarded headers at all
services:
  traefik:
    image: traefik:v3.7.6                       # fixed: CVE-2026-35051/39858/54764
    command:
      - --providers.docker
      - --entrypoints.web.forwardedHeaders.trustedIPs=172.20.0.0/16   # only this compose network
    labels:
      - traefik.http.middlewares.auth.forwardauth.address=http://authelia:9091/api/verify
      - traefik.http.middlewares.auth.forwardauth.trustForwardHeader=true
      - traefik.http.middlewares.auth.forwardauth.authResponseHeaders=Remote-User,Remote-Groups,Remote-Email
```

```
# App-side — BAD: trusts the identity header unconditionally
user := r.Header.Get("Remote-User")   // set by Authelia when the gateway is intact,
if user == "" { http.Error(w, "unauthorized", 401); return }   // but just a header if it isn't
```

```
# App-side — GOOD: the app is unreachable except via the gateway (bind loopback / internal
# network only), AND it still verifies the gateway actually ran, not just that a header exists
if !isRequestFromTrustedProxy(r) { http.Error(w, "unauthorized", 401); return }
user := r.Header.Get("Remote-User")
```

**Detection:**

```bash
grep -rniE 'forwardauth|forward_auth|auth_request' -- docker-compose*.yml compose*.yml Caddyfile */nginx*.conf 2>/dev/null
grep -rn "trustForwardHeader" docker-compose*.yml compose*.yml 2>/dev/null \
  | xargs -I{} echo "check: entryPoint forwardedHeaders.trustedIPs also set?"
docker compose config 2>/dev/null | grep -A2 'image:.*traefik' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'   # compare to 2.11.51/3.6.22/3.7.6
grep -rniE 'remote-user|remote-email|x-forwarded-user|x-auth-request-' --include='*.{go,py,js,ts}' . \
  | xargs -I{} echo "check: is this port bound to loopback/internal network only?"
```

## 5. Cloudflare Tunnel / Access: the Header Is Not the Authorization

**What to look for:** code that reads `Cf-Access-Authenticated-User-Email` or trusts
`Cf-Access-Jwt-Assertion` without cryptographic verification; the origin server reachable on a
public IP in addition to (or instead of) the tunnel; `cf-connecting-ip` used for a security
decision with no check that the connection actually arrived from a Cloudflare IP range.

**Why it's exploitable:** Cloudflare Tunnel closes the network path — "You can then configure your
firewall to allow only these outbound connections and block all inbound traffic, effectively
blocking access to your origin from anything other than Cloudflare" — but Access closes the
*identity* path only if the token is checked. Cloudflare's own instruction: "To secure your origin,
you must validate the application token issued by Cloudflare Access." If the origin is *also*
publicly routable, Cloudflare says plainly: "a tunnel is not strictly required. However, you will
then need to protect your origin IP using other methods" — i.e. the tunnel alone protects nothing
if the same app answers on another path.

The token itself arrives as a header, and a header is just a string: "the request will include an
application token as a `Cf-Access-Jwt-Assertion` request header… You should validate the token
with your public key to ensure that the request came from Access and not a malicious third party.
We recommend validating the `Cf-Access-Jwt-Assertion` header instead of the `CF_Authorization`
cookie." Validation means fetching the team's JWKS at
`https://<your-team-name>.cloudflareaccess.com/cdn-cgi/access/certs`, verifying the signature,
matching `kid` (keys "rotate every 6 weeks"), and checking `aud` against *this* application's
Application Audience tag — skip `aud` and a token minted for any other app in the same Access
organization authenticates here too.

`cf-connecting-ip` is reliable only from Cloudflare itself — it "provides the client IP address
connecting to Cloudflare to the origin web server" and "has a consistent format containing only one
IP address," but that guarantee only holds if the connection reaching your origin actually came
from Cloudflare's network. To make that true at the web-server layer (not just via the tunnel),
Cloudflare's own restore-IP guidance for nginx is `set_real_ip_from <cloudflare prefixes>;
real_ip_header CF-Connecting-IP;`, sourced from the published, regularly-updated prefix lists —
"that list of prefixes needs to be updated regularly" — rather than hand-copied once. `X-Forwarded-For`
at the edge is the opposite shape of trustworthy: Cloudflare *appends* to whatever the client
already sent rather than replacing it, so "maintains proxy server and original visitor IP
addresses" includes the attacker's own claimed value still sitting in the list.

**Fix:** verify the JWT on every request — signature, issuer, `aud` — never fall back to reading
the unverified email header. Keep the origin reachable *only* via the tunnel where that's feasible;
where a direct path must also exist, restrict it to Cloudflare's published IP ranges and use
`CF-Connecting-IP` (never `X-Forwarded-For`) for any IP-based decision, refreshed against
Cloudflare's list rather than pinned once.

```ts
// BAD — the email header is the whole check
const email = req.headers['cf-access-authenticated-user-email'];
if (!email) return res.status(401).end();
req.user = { email };            // spoofable on any path that skips Access
```

```ts
// GOOD — signature, issuer and audience all verified against the team's live JWKS
import { createRemoteJWKSet, jwtVerify } from 'jose';
const TEAM_DOMAIN = process.env.CF_TEAM_DOMAIN;      // https://<team>.cloudflareaccess.com
const POLICY_AUD = process.env.CF_ACCESS_AUD;        // this app's Application Audience tag
const jwks = createRemoteJWKSet(new URL(`${TEAM_DOMAIN}/cdn-cgi/access/certs`));

async function requireAccess(req, res, next) {
  const token = req.headers['cf-access-jwt-assertion'];
  if (!token) return res.status(401).end();
  try {
    const { payload } = await jwtVerify(token, jwks, { issuer: TEAM_DOMAIN, audience: POLICY_AUD });
    req.user = { email: payload.email, sub: payload.sub };
  } catch {
    return res.status(401).end();   // fail closed; never fall back to a raw header
  }
  next();
}
```

```nginx
# nginx in front of an origin also reachable directly — restore and gate on the real edge IP
set_real_ip_from 173.245.48.0/20;    # ...full published Cloudflare prefix list
real_ip_header CF-Connecting-IP;
# then deny anything whose source isn't in Cloudflare's ranges before it reaches the app
```

**Detection:**

```bash
grep -rlniE 'cf-access-(jwt-assertion|authenticated-user-email)' --include='*.{js,ts,py,go}' . \
  | xargs grep -LiE 'jwtVerify|createRemoteJWKSet|jwks' 2>/dev/null   # header used with no verify call nearby
grep -rniE "header\(['\"]x-forwarded-for['\"]\)|cf-connecting-ip" --include='*.{js,ts,py,go}' .
grep -rn "set_real_ip_from\|real_ip_header" **/nginx*.conf 2>/dev/null
```

## 6. Tailscale Serve: Identity Headers Only Exist on the Path That Strips Them

**What to look for:** a backend that reads `Tailscale-User-Login`, `Tailscale-User-Name`, or
`Tailscale-User-Profile-Pic` and treats them as identity with no check on *how* the request could
have arrived; the same backend also bound to a LAN address, a public port, or reachable through
Funnel.

**Why it's exploitable:** the guarantee here is narrower than it looks. "Serve traffic includes
identity headers when serving traffic from your tailnet using Tailscale Serve. Funnel traffic,
which is publicly available, does not include identity headers" — the same app and code path
behave differently depending on which of the two a request came through, and nothing in the header
says which. Tailscale strips attacker-supplied copies on the way in — "If Serve finds the
following headers on an incoming request, it will remove them for security reasons, to avoid
header spoofing" — but that stripping happens *at the Serve proxy*, so it only protects a backend
reachable *only* through Serve; one also bound to a LAN address or public port gets requests that
never passed through Serve, unstripped. Two more edge cases: "these identity headers are not
populated for traffic originating from tagged devices," and "although identity headers are only
populated for tailnet traffic, this includes traffic from external users who have accepted a share
of your device" — a shared device's user is still a real, distinct identity the header will carry.

**Fix:** bind the backend to loopback (or an address reachable only from the Tailscale-Serve
proxy), never to `0.0.0.0` or a LAN interface, so no path exists that bypasses the header-stripping
proxy. Treat the absence of the identity header as "not authenticated," not as "trust some other
fallback" — a route reachable via Funnel will never carry it, by design, and that's the signal it's
public traffic, not a bug to work around.

```go
// BAD — the app listens on all interfaces; anyone on the LAN reaches it with no Serve proxy in front
http.ListenAndServe("0.0.0.0:8080", handler)
```

```go
// GOOD — reachable only via the Tailscale Serve proxy, so the stripped/set header is trustworthy
http.ListenAndServe("127.0.0.1:8080", handler)   // tailscale serve --bg 8080 fronts this
// handler:
login := r.Header.Get("Tailscale-User-Login")
if login == "" { http.Error(w, "unauthorized", 401); return }   // Funnel traffic never has it
```

**Detection:**

```bash
grep -rniE 'tailscale-user-(login|name|profile-pic)' --include='*.{go,js,ts,py}' .
grep -rnE 'ListenAndServe\("0\.0\.0\.0|listen\(.*0\.0\.0\.0' --include='*.go' --include='*.{js,ts}' .
grep -rn 'tailscale serve\|tailscale funnel' . 2>/dev/null
```

## Proxy-Trust Footgun Checklist

- Express `trust proxy` (or Fastify `trustProxy`) set to bare `true` — the leftmost, client-chosen
  `X-Forwarded-For` entry becomes `req.ip`.
- Koa `app.proxy = true` with `maxIpsCount` left at its infinite default.
- Fastify `trustProxy` set to a plain number — hop-count trust doesn't validate the connecting
  peer; confirm the installed version is ≥ 5.12.1 (CVE-2026-3635 / CVE-2026-16732).
- A rate limiter, allowlist, or audit log keyed on an XFF value with no matching hop-count/IP trust
  configuration — bypassable or globally-bucketed, in either direction.
- A password-reset, invite, or callback URL built from `req.hostname` / the raw `Host` header
  instead of a configured origin — Host-header poisoning; no `ALLOWED_HOSTS`-style check anywhere
  on that code path.
- Koa `ctx.hostname` in a security-relevant path on a version before 3.1.2 / 2.16.4
  (CVE-2026-27959).
- No explicit rejection (421/400) of requests whose Host doesn't match a known value — silent
  fallback instead of fail-closed.
- `forwardAuth` / `forward_auth` / `auth_request` wired up with no explicit list of which headers
  the auth response is allowed to set — a client-sent copy of `Remote-User` can ride along
  unmodified.
- Traefik pinned below 2.11.51 / 3.6.22 / 3.7.6 — three separate ForwardAuth bypasses
  (CVE-2026-35051, -39858, -54764) live below that floor.
- An app that trusts an identity header (`Remote-User`, `X-Forwarded-User`, `X-Auth-Request-*`)
  while also being reachable on a path that doesn't go through the gateway that sets it.
- `Cf-Access-Authenticated-User-Email` (or any `Cf-Access-*` header) read without verifying
  `Cf-Access-Jwt-Assertion` — signature, issuer, and `aud` — against the team's JWKS.
- An origin also reachable on its own public IP alongside a Cloudflare Tunnel — the tunnel
  protects nothing on the path that bypasses it.
- `X-Forwarded-For` (rather than `CF-Connecting-IP`) used for any Cloudflare-edge security
  decision.
- A backend bound to `0.0.0.0` or a LAN interface behind Tailscale Serve — traffic that never
  passed through Serve gets no header stripping, so a shared/unstripped header could reach it.
- Absence of a Tailscale identity header treated as anything other than "unauthenticated" — Funnel
  traffic never carries one, by design.

## Cross-References

- `secaudit:rate-limiting` — this skill covers *which* client identifier a limiter can safely key
  on (§2); that skill covers limit design, tamper-proof counters, and combining per-IP with
  per-user limits once the identifier itself is trustworthy.
- `secaudit:deployment` — CORS, security headers, and environment separation live there; this skill
  is specifically about what to believe *about the request's origin* once it's behind a proxy,
  including the Host-trust and 421-on-unknown-host pattern in §3.
- `secaudit:docker-security` — a Traefik/Caddy/nginx service defined in the same compose file this
  skill audits for `forwardAuth`/`forward_auth`/`auth_request` also needs the port-exposure and
  hardening review in that skill (no `0.0.0.0` binding on the app service itself, §6's Tailscale
  concern in miniature).
- `secaudit:auth` — Auth.js/NextAuth's `trustHost` (`AUTH_TRUST_HOST`) is this skill's §1 problem
  under a different name: enabling it means the app trusts `X-Forwarded-Host` to build its own
  callback and cookie URLs, so it needs the same closed-proxy-chain guarantee before it's safe to
  turn on.

## Sources

- https://expressjs.com/en/guide/behind-proxies/ -- `trust proxy` boolean/number/IP forms; header-stripping warning
- https://express-rate-limit.mintlify.app/reference/error-codes -- `ERR_ERL_PERMISSIVE_TRUST_PROXY`, `ERR_ERL_UNEXPECTED_X_FORWARDED_FOR`
- https://express-rate-limit.mintlify.app/guides/troubleshooting-proxy-issues -- verifying the hop count against a real request
- https://koajs.com/ -- `app.proxy`, `app.proxyIpHeader`, `app.maxIpsCount`, `ctx.hostname`/`ctx.protocol` semantics
- https://fastify.dev/docs/latest/Reference/Server/ -- `trustProxy` forms; numeric hop-count trust disabled
- https://api.osv.dev/v1/vulns/CVE-2026-3635 -- Fastify request.protocol/host spoofable under a restrictive trustProxy; fixed 5.8.3
- https://github.com/advisories/GHSA-444r-cwp2-x5xf -- CVE-2026-3635 advisory
- https://api.osv.dev/v1/vulns/CVE-2026-16732 -- Fastify numeric trustProxy still spoofable after the 3635 fix; fixed 5.12.1
- https://github.com/fastify/fastify/security/advisories/GHSA-3m5p-2c4r-xxw2 -- CVE-2026-16732 advisory
- https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions -- Origin vs `x-forwarded-host`/`host` comparison; no-Origin-allowed-with-warning; `allowedOrigins`
- https://www.rfc-editor.org/info/rfc7239/ -- RFC 7239 `Forwarded` header; cannot be relied upon to be correct
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For -- security-use rule; leftmost values untrustworthy; trusted-proxy-count/list selection
- https://portswigger.net/web-security/host-header -- Host header attacks; password-reset poisoning; config-not-request mitigation
- https://docs.djangoproject.com/en/6.1/ref/settings/ -- `ALLOWED_HOSTS`, `get_host()` scope, `USE_X_FORWARDED_HOST` opt-in
- https://api.osv.dev/v1/vulns/CVE-2026-27959 -- Koa `ctx.hostname` Host-header injection; fixed 3.1.2 / 2.16.4
- https://github.com/advisories/GHSA-7gcc-r8m5-44qm -- CVE-2026-27959 advisory
- https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/ -- ForwardAuth headers, `authResponseHeaders`/`authRequestHeaders`, `trustForwardHeader` deprecation
- https://api.osv.dev/v1/vulns/CVE-2026-35051 -- Traefik ForwardAuth X-Forwarded-Prefix bypass; fixed 2.11.43/3.6.14/3.7.0-rc.2
- https://github.com/traefik/traefik/security/advisories/GHSA-6384-m2mw-rf54 -- CVE-2026-35051 advisory
- https://api.osv.dev/v1/vulns/CVE-2026-39858 -- Traefik underscore-alias header bypass; fixed 2.11.43/3.6.14/3.7.0-rc.2
- https://github.com/advisories/GHSA-5m6w-wvh7-57vm -- CVE-2026-39858 advisory
- https://api.osv.dev/v1/vulns/CVE-2026-54764 -- Traefik X-Forwarded-Port derived from unsanitized request; fixed v2.11.51/v3.6.22/v3.7.6
- https://github.com/traefik/traefik/security/advisories/GHSA-3q9r-p662-5j8m -- CVE-2026-54764 advisory
- https://caddyserver.com/docs/caddyfile/directives/forward_auth -- `forward_auth`, `copy_headers`, success-status header copy behavior
- https://nginx.org/en/docs/http/ngx_http_auth_request_module.html -- `auth_request`, `auth_request_set`, 2xx/401/403 semantics
- https://www.authelia.com/integration/trusted-header-sso/introduction/ -- `Remote-User`/`Remote-Groups`/`Remote-Email`; proxy must set these exclusively
- https://www.authelia.com/integration/proxies/forwarded-headers/ -- forwarded headers must come from trusted sources
- https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/ -- `--pass-user-headers`, `--set-xauthrequest`, `--reverse-proxy`/`--trusted-proxy-ip` warning
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/ -- Tunnel blocks inbound traffic except via Cloudflare
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/ -- origin token validation requirement; tunnel-optional-if-public caveat
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/ -- `Cf-Access-Jwt-Assertion`, team JWKS endpoint, `aud` claim, key rotation
- https://developers.cloudflare.com/fundamentals/reference/http-headers/ -- `CF-Connecting-IP` vs appended `X-Forwarded-For`
- https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/ -- `set_real_ip_from`/`real_ip_header`; prefix list must stay current
- https://www.cloudflare.com/ips/ -- current Cloudflare IP ranges (definitive source)
- https://tailscale.com/docs/features/tailscale-serve -- identity headers on Serve vs absent on Funnel; header stripping on ingress; tagged-device and shared-device behavior
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where §2 and §4's forward-auth bypass land
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ -- A02:2025, where §1, §3, §5 and §6 land
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ -- A07:2025, where §4's identity-header trust and §5's Access JWT verification land
