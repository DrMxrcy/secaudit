# Sources

Every claim in the secaudit skills is backed by a primary source: official documentation,
vendor security advisories, the NVD / GitHub Advisory Database, OWASP, or primary research. Each
skill also lists its own sources in a `## Sources` section. This file is the consolidated index.

Last verified: 2026-09-15.

## Frameworks (`framework-versions`)
- https://nvd.nist.gov/vuln/detail/cve-2025-55182 — React2Shell RSC RCE (CVSS 10.0)
- https://nvd.nist.gov/vuln/detail/cve-2025-66478 — confirms the Next.js-side ID is a rejected duplicate of CVE-2025-55182
- https://api.first.org/data/v1/epss — EPSS exploitation-probability API (no key, batched)
- https://www.first.org/epss/ — EPSS model documentation
- https://endoflife.date/ — runtime and framework end-of-life dates (no key)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — CISA KEV (React2Shell actively exploited)
- https://github.com/advisories/GHSA-f82v-jwr5-mffw — CVE-2025-29927 middleware bypass; ranges start at 12.0.0, confirming 11.x has no patched release
- https://github.com/advisories/GHSA-67rr-84xm-4c7r — CVE-2025-49826 cache-poisoning DoS; range is `>=15.0.4-canary.51 <15.1.8`
- https://github.com/advisories/GHSA-925w-6v3x-g4j4 — CVE-2025-55183 source exposure, fixed 19.0.2 / 19.1.3 / 19.2.2 (one patch later than CVE-2025-55182)
- https://github.com/advisories/GHSA-2m3v-v2m8-q956 — CVE-2025-55184 DoS, same one-patch-later fix line
- https://github.com/advisories/GHSA-rv95-896h-c2vc — CVE-2024-29041 Express open redirect, fixed 4.19.2 (not 4.19.0) and 5.0.0-beta.3
- https://github.com/advisories/GHSA-36qx-fr4f-26g5 — CVE-2026-44573 middleware/proxy bypass, Pages Router
- https://github.com/advisories/GHSA-492v-c6pp-mqqv — CVE-2026-44574 middleware/proxy bypass via dynamic routes
- https://github.com/advisories/GHSA-267c-6grr-h53f — CVE-2026-44575 middleware/proxy bypass, App Router
- https://github.com/advisories/GHSA-26hh-7cqf-hhc6 — CVE-2026-45109 incomplete fix for CVE-2026-44575
- https://github.com/advisories/GHSA-6gpp-xcg3-4w24 — CVE-2026-64642 middleware/proxy bypass, App Router + Turbopack
- https://github.com/advisories/GHSA-955p-x3mx-jcvp — CVE-2026-64643 unauthenticated Server Function endpoint disclosure; sets the 15.5.21 / 16.2.11 floors
- https://github.com/advisories/GHSA-89xv-2m56-2m9x — CVE-2026-64649 SSRF in Server Actions
- https://github.com/advisories/GHSA-ggv3-7p47-pfv8 — CVE-2026-29057 HTTP request smuggling in rewrites
- https://github.com/advisories/GHSA-ffhc-5mcf-pf4q — CVE-2026-44581 XSS in App Router with CSP nonces
- https://github.com/advisories/GHSA-399j-vxmf-hjvr — CVE-2025-11953 React Native CLI Metro dev-server RCE (CISA KEV 2026-02-05)
- https://github.com/advisories/GHSA-4r4m-qw57-chr8 — CVE-2025-31125 Vite server.fs.deny bypass (CISA KEV 2026-01-22)
- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json — CISA KEV feed (machine-readable; check dateAdded)
- https://github.com/advisories/GHSA-qwww-vcr4-c8h2 — React Router RSC-mode CSRF bypass
- https://nodejs.org/en/blog/vulnerability/ — Node.js security releases (the runtime is not OSV-indexed)
- https://nuxt.com/blog — Nuxt release and security announcements
- https://github.com/remix-run/react-router/security — React Router / Remix advisories
- https://github.com/vitejs/vite/security — Vite advisories (server.fs.deny is a repeat-offender control)
- https://nextjs.org/blog — official Next.js security releases
- https://github.com/advisories/GHSA-crvj-82cr-hjcx — CVE-2026-84363 Hono query parser reads past the URL fragment; the 2026-09-08 trio sets the 4.13.5 floor
- https://github.com/advisories/GHSA-f23p-vx2j-j53r — CVE-2026-71850 Hono `memo()` cross-user SSR disclosure, fixed 4.12.34
- https://github.com/advisories/GHSA-w332-q679-j88p — CVE-2026-24473 Hono serve-static env-key read; its fix release 4.11.7 still carries 33 open advisories
- https://github.com/advisories/GHSA-x445-f3h2-j279 — CVE-2026-73419 Auth.js OAuth check cookies not bound to the provider (account-linking takeover)
- https://github.com/advisories/GHSA-8fpg-xm3f-6cx3 — CVE-2026-73421 NextAuth config errors make existence-based auth checks fail open (5.x only)
- https://github.com/advisories/GHSA-gpj5-g38j-94v9 — CVE-2026-39356 Drizzle ORM identifier injection via `escapeName()` in every SQL dialect
- https://github.com/advisories/GHSA-7gcc-r8m5-44qm — CVE-2026-27959 Koa Host header injection via `ctx.hostname`
- https://github.com/advisories/GHSA-3m5p-2c4r-xxw2 — CVE-2026-16732 Fastify `X-Forwarded-*` spoofing under trustProxy hop-count
- https://github.com/advisories/GHSA-444r-cwp2-x5xf — CVE-2026-3635 Fastify request.protocol/host spoofable from an untrusted peer
- https://github.com/advisories/GHSA-8hq9-phh3-p2wp — CVE-2026-31865 Elysia cookie value prototype pollution
- https://github.com/advisories/GHSA-g7cv-rxg3-hmpx — CVE-2026-45321 malware in 42 @tanstack/* releases (credential/token/SSH-key exfiltration)
- https://github.com/advisories/GHSA-6384-m2mw-rf54 — CVE-2026-35051 Traefik ForwardAuth bypass via X-Forwarded-Prefix
- https://github.com/advisories/GHSA-5m6w-wvh7-57vm — CVE-2026-39858 Traefik forwarded alias-header bypass (same middleware)
- https://github.com/advisories/GHSA-3q9r-p662-5j8m — CVE-2026-54764 Traefik ForwardAuth X-Forwarded-Port spoofing
- https://github.com/advisories/GHSA-6765-c87h-8mrf — CVE-2026-71326 Traefik BasicAuth singleflight identity spoof
- https://github.com/advisories/GHSA-2xp9-vwfh-vxw4 — Next.js AVIF image-optimization RCE, 2026-09-08
- https://github.com/advisories/GHSA-26w7-cxv4-gfx2 — Astro AVIF image-optimization RCE, same day; the shared sharp/libvips pipeline
- https://google.github.io/osv.dev/api/ — OSV.dev API (live advisory lookup, no key, multi-ecosystem)
- https://google.github.io/osv.dev/post-v1-querybatch/ — OSV.dev querybatch request/response shape
- https://github.com/google/osv-scanner — osv-scanner CLI for lockfile scanning
- https://github.com/advisories — GitHub Security Advisory Database
- https://nvd.nist.gov/developers/vulnerabilities — NVD CVE API (live CVE detail lookup)

## Secrets & environment (`secrets`)
- https://nextjs.org/docs/app/guides/environment-variables — NEXT_PUBLIC_ inlining
- https://vite.dev/guide/env-and-mode — VITE_ inlining
- https://docs.expo.dev/guides/environment-variables/ — EXPO_PUBLIC_ inlining
- https://supabase.com/docs/guides/getting-started/api-keys — Supabase publishable vs secret keys

## Database access (`database`)
- https://supabase.com/docs/guides/database/postgres/row-level-security — RLS
- https://supabase.com/docs/guides/getting-started/api-keys — key model (BYPASSRLS)
- https://supabase.com/docs/guides/functions/auth — Edge Functions JWT
- https://supabase.com/docs/guides/auth — Supabase Auth (GoTrue)
- https://firebase.google.com/docs/rules — Firebase Security Rules
- https://firebase.google.com/docs/firestore/quickstart — locked vs test mode

## Convex (`convex-security`)
- https://docs.convex.dev/functions/internal-functions — public vs internal
- https://docs.convex.dev/functions/validation — argument validators
- https://docs.convex.dev/auth/functions-auth — ctx.auth.getUserIdentity()
- https://docs.convex.dev/understanding/best-practices/ — don't trust spoofable args
- https://docs.convex.dev/functions/http-actions — httpAction is public
- https://docs.convex.dev/file-storage/overview — file URLs are unauthenticated
- https://stack.convex.dev/row-level-security — no built-in RLS
- https://docs.convex.dev/cli/deploy-key-types — deploy key types; scope a key to one deployment
- https://docs.convex.dev/ai/agent-skills — official Convex agent-skills (build patterns)

## Authentication (`auth`)
- https://nvd.nist.gov/vuln/detail/cve-2025-29927 — Next.js middleware authorization bypass
- https://vercel.com/blog/postmortem-on-next-js-middleware-bypass — bypass mechanism + fixed versions
- https://nextjs.org/blog/security-nextjs-server-components-actions — Server Actions are public endpoints
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — cookies, timeouts, session fixation
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — CSRF
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — auth, WebAuthn, error messages
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html — enumeration-safe reset
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie — cookie attributes
- https://www.w3.org/TR/webauthn-2/ — passkeys / WebAuthn
- https://github.com/advisories/GHSA-x445-f3h2-j279 — CVE-2026-73419 Auth.js check cookies not bound to their provider
- https://github.com/advisories/GHSA-8fpg-xm3f-6cx3 — CVE-2026-73421 auth() existence checks fail open on a config error
- https://github.com/advisories/GHSA-7rqj-j65f-68wh — CVE-2026-73420 email normalizer fullwidth-@ bypass
- https://github.com/advisories/GHSA-xmf8-cvqr-rfgj — CVE-2026-73418 getToken() malformed Bearer DoS
- https://authjs.dev/security — updates only for the current latest version
- https://authjs.dev/reference/core/providers — allowDangerousEmailAccountLinking; default checks
- https://authjs.dev/reference/core — trustHost; secret array rotation; jwt/session callbacks
- https://authjs.dev/getting-started/deployment — AUTH_SECRET, AUTH_TRUST_HOST, AUTH_URL
- https://authjs.dev/concepts/session-strategies — JWT vs database sessions
- https://authjs.dev/concepts/database-models — Account stores provider tokens; linking by email
- https://authjs.dev/guides/extending-the-session — what the session object persists
- https://authjs.dev/getting-started/authentication/credentials — hashing and rate limiting are yours
- https://authjs.dev/getting-started/session-management/protecting — authorized: !!auth; proxy is not the boundary
- https://next-auth.js.org/configuration/options — v4 NEXTAUTH_SECRET / NEXTAUTH_URL
- https://nextjs.org/docs/app/guides/authentication — proxy is not your only line of defense

## Privilege escalation (`privilege-escalation`)
- https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/ — OWASP API A05 (BFLA)
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ — OWASP A01:2025 Broken Access Control (absorbs SSRF as of 2025)
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — authorization design, default-deny
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html — mass assignment / allowlisting
- https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation — WSTG privilege-escalation testing

## Rate limiting (`rate-limiting`)
- https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html — rate limiting
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — brute-force throttling
- https://upstash.com/docs/redis/sdks/ratelimit-ts/overview — Upstash sliding window

## Payments (`payments`)
- https://docs.stripe.com/webhooks — replay tolerance ("don't use 0"), duplicate events, IP allowlisting, secret rolling, 3xx treated as failure
- https://docs.stripe.com/webhooks/signature — raw-body signature verification
- https://docs.stripe.com/webhooks — constructEvent, endpoint secret
- https://docs.stripe.com/products-prices/how-products-and-prices-work — server-side Price IDs

## Webhooks (`webhook-security`)
- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries — `X-Hub-Signature-256`, HMAC-SHA256 hex, header absent when no secret configured
- https://docs.slack.dev/authentication/verifying-requests-from-slack/ — `X-Slack-Signature`/`X-Slack-Request-Timestamp`, `v0:` basestring, 5-minute tolerance
- https://docs.discord.com/developers/interactions/overview — `X-Signature-Ed25519`/`X-Signature-Timestamp`, Ed25519 over timestamp+body, 401 on failure, PING/PONG
- https://docs.svix.com/receiving/verifying-payloads/how-manual — `svix-id`/`svix-timestamp`/`svix-signature`, `id.timestamp.body`, `v1,` prefix, `whsec_` secret
- https://docs.svix.com/receiving/verifying-payloads/how — framework raw-body notes (Express, Next.js, NestJS, FastAPI, Django)
- https://docs.svix.com/receiving/verifying-payloads/why — why raw-body and constant-time comparison matter
- https://www.standardwebhooks.com/ — Standard Webhooks spec overview; Svix implements this spec
- https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md — `webhook-id`/`webhook-timestamp`/`webhook-signature`, tolerance requirement
- https://clerk.com/docs/guides/development/webhooks/overview — Clerk uses Svix; `verifyWebhook` helper
- https://resend.com/docs/webhooks/verify-webhooks-requests — Resend's Svix-backed webhooks, raw-body requirement
- https://core.telegram.org/bots/api — `setWebhook` `secret_token`: optional, shared secret via `X-Telegram-Bot-Api-Secret-Token`
- https://www.twilio.com/docs/usage/webhooks/webhooks-security — Twilio webhook security overview, SDK validator recommendation
- https://www.twilio.com/docs/usage/security — full URL + sorted POST params + HMAC-SHA1 + base64 steps
- https://shopify.dev/docs/apps/build/webhooks/verify-deliveries — `X-Shopify-Hmac-SHA256`, verify-before-parsing, `X-Shopify-Webhook-Id` dedupe
- https://linear.app/developers/webhooks — `Linear-Signature`/`Linear-Event`, in-body `webhookTimestamp`, 1-minute replay window
- https://vercel.com/docs/webhooks/webhooks-api — `x-vercel-signature`, HMAC-SHA1 over raw body; sample compares with `===`
- https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b — `timingSafeEqual` is constant-time; throws on unequal byte length
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ — A07:2025 mapping
- https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/ — A08:2025 mapping
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ — A01:2025 mapping

## Supply chain (`supply-chain`)
- https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen — USENIX 2025 package-hallucination study
- https://arxiv.org/abs/2406.10279 — preprint of the same study
- https://www.lasso.security/blog/ai-package-hallucinations — Lasso Security huggingface-cli PoC
- https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks — Socket
- https://snyk.io/articles/slopsquatting-mitigation-strategies/ — mitigation
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/ — lockfiles
- https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain — CHAINDROP/Shai-Hulud npm worm (2026-08-04): preinstall-hook delivery, 400+ packages, 300+ credential patterns, self-propagation via npm publish tokens
- https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack — same incident, independent analysis: keyv/cacheable ecosystem, IDE persistence attempts, no CVE assigned

## React Native (`react-native-security`)
- https://reactnative.dev/docs/security — official RN security guide
- https://owasp.github.io/www-project-mobile-top-10/ — OWASP Mobile Top 10 (2024)
- https://mas.owasp.org/MASVS/ — OWASP MASVS
- https://github.com/oblador/react-native-keychain — Keychain/Keystore storage
- https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md — WebView security props

## Expo / EAS (`expo-security`)
- https://docs.expo.dev/guides/environment-variables/ — EXPO_PUBLIC_ visibility
- https://docs.expo.dev/eas/environment-variables/ — EAS visibility levels don't secure embedded values
- https://docs.expo.dev/versions/latest/sdk/securestore/ — expo-secure-store
- https://docs.expo.dev/eas-update/code-signing/ — OTA code signing
- https://docs.expo.dev/config-plugins/introduction/ — config plugins run at prebuild
- https://docs.expo.dev/skills/ — official Expo skills (build patterns)

## AI / LLM (`ai-integration`)
- https://genai.owasp.org/llm-top-10/ — OWASP Top 10 for LLM Applications (landing page; may lag the current edition)
- https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ — current edition (2026, published 2026-08-03)
- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices — MCP security (2026-07-28)
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization — MCP token-audience binding (2026-07-28)

## Prisma & Postgres (`prisma-security`)
- https://www.prisma.io/docs/orm/v7/prisma-client/using-raw-sql/raw-queries — $queryRaw vs Prisma.raw / Prisma.join
- https://www.prisma.io/docs/orm/v7/prisma-client/client-extensions/query — query extensions cannot mutate include/select
- https://www.prisma.io/docs/guides/upgrade-prisma-orm/v7 — $use middleware removed in Prisma 7
- https://www.prisma.io/docs/orm/v7/prisma-client/queries/excluding-fields — omit, local and global
- https://www.prisma.io/docs/orm/v7/core-concepts/supported-databases/postgresql — sslaccept defaults to accept_invalid_certs
- https://www.prisma.io/docs/orm/v7/more/best-practices — migrate deploy only in production
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html — table owners bypass RLS; FORCE ROW LEVEL SECURITY; constraint checks always bypass RLS
- https://www.postgresql.org/docs/current/functions-admin.html — set_config is_local transaction scope; current_setting missing_ok
- https://github.com/pgvector/pgvector — filtered search, partial HNSW indexes, hnsw.iterative_scan
- https://github.com/pgvector/pgvector-node — Prisma + pgvector integration
- https://node-postgres.com/features/ssl — ssl object overwritten when the connection string carries sslmode

## Better Auth (`better-auth-security`)
- https://better-auth.com/docs/integrations/next — getSessionCookie is not secure; auth.api.getSession({ headers })
- https://better-auth.com/docs/reference/security — trustedOrigins, OAuth state, disableOriginCheck
- https://better-auth.com/docs/concepts/session-management — cookieCache staleness, disableCookieCache, freshAge
- https://better-auth.com/docs/concepts/cookies — useSecureCookies, cookie attributes
- https://better-auth.com/docs/concepts/rate-limit — production-only default, storage backends, customRules
- https://better-auth.com/docs/reference/options — advanced.* flags, trustedProxyHeaders, accountLinking
- https://better-auth.com/docs/concepts/users-accounts — accountLinking trustedProviders
- https://better-auth.com/docs/plugins/organization — hasPermission, activeOrganizationId
- https://better-auth.com/docs/plugins/admin — userHasPermission, adminUserIds, impersonation
- https://better-auth.com/docs/plugins/api-key — verifyApiKey with permissions
- https://better-auth.com/docs/installation — BETTER_AUTH_SECRET requirements
- https://nextjs.org/docs/app/guides/authentication — data access layer; re-verify in every action
- https://nextjs.org/docs/app/api-reference/file-conventions/proxy — middleware renamed to proxy in Next.js 16
- https://nextjs.org/docs/app/api-reference/directives/use-cache — cached data is keyed by arguments, not session

## Docker & containers (`docker-security`)
- https://docs.docker.com/build/building/best-practices/ — Dockerfile best practices, non-root, pinning
- https://docs.docker.com/build/building/secrets/ — BuildKit build secrets
- https://docs.docker.com/reference/dockerfile/ — ARG visible in image history and provenance
- https://docs.docker.com/build/concepts/context/ — .dockerignore and build context
- https://docs.docker.com/reference/compose-file/services/ — cap_drop, security_opt, read_only, pids_limit, ports
- https://docs.docker.com/reference/compose-file/secrets/ — compose secrets
- https://docs.docker.com/engine/security/ — the Docker socket is root-equivalent
- https://docs.docker.com/engine/network/packet-filtering-firewalls/ — Docker bypasses host firewall rules
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html — OWASP Docker cheat sheet
- https://www.cisecurity.org/benchmark/docker — CIS Docker Benchmark

## Python web (`python-web-security`)
- https://fastapi.tiangolo.com/tutorial/response-model/ — response_model output filtering
- https://fastapi.tiangolo.com/tutorial/extra-models/ — separate input/output/DB models
- https://fastapi.tiangolo.com/tutorial/bigger-applications/ — router- and app-level dependencies
- https://fastapi.tiangolo.com/reference/dependencies/ — Security() and OAuth2 scopes
- https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/ — Django deployment checklist
- https://docs.djangoproject.com/en/6.0/ref/checks/ — check --deploy warning IDs (does not cover ALLOWED_HOSTS=['*'])
- https://requests.readthedocs.io/en/latest/user/advanced/ — certificate verification
- https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html — Django hardening

## Python language-level (in `data-access`, `logging-monitoring`, `supply-chain`)
- https://docs.sqlalchemy.org/en/20/core/sqlelement.html — text(), bindparam()
- https://pydantic.dev/docs/validation/latest/concepts/models/ — extra='forbid'
- https://docs.python.org/3/library/pickle.html — not secure against maliciously constructed data
- https://pyyaml.org/wiki/PyYAMLDocumentation — loader classes and safe_load
- https://github.com/jsonpickle/jsonpickle/issues/178 — safe=True does not prevent py/reduce execution
- https://docs.python.org/3/library/subprocess.html — shell=True security considerations
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — deserialization
- https://pip.pypa.io/en/stable/cli/pip_install/ — --extra-index-url dependency confusion
- https://pip.pypa.io/en/stable/topics/secure-installs/ — hash-checking mode
- https://docs.astral.sh/uv/concepts/indexes/ — first-index default
- https://peps.python.org/pep-0751/ — pylock.toml
- https://docs.pypi.org/trusted-publishers/ — PyPI Trusted Publishing
- https://docs.pypi.org/attestations/ — PyPI attestations
- https://packaging.python.org/en/latest/specifications/name-normalization/ — PEP 503 name folding

## AI chat & RAG (`ai-integration`)
- https://ai-sdk.dev/docs/ai-sdk-ui/chatbot-message-persistence — send last message only; validateUIMessages
- https://ai-sdk.dev/docs/ai-sdk-ui/chatbot-tool-usage — server-side tools, step limits, approval
- https://ai-sdk.dev/docs/ai-sdk-ui/error-handling — stream errors masked by default
- https://ai-sdk.dev/docs/ai-sdk-core/telemetry — recordInputs / recordOutputs
- https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/ — BOLA (chat-thread IDOR)

## MCP & agents (`mcp-agent-security`)
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization — MCP authorization (current revision)
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations — token audience, confused deputy
- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices — MCP security best practices
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools — tool definitions and handler responsibilities
- https://modelcontextprotocol.io/specification/2026-07-28/server/resources — resource URIs (traversal surface)
- https://modelcontextprotocol.io/specification/2026-07-28/basic/index — protocol basics; stateless, no protocol-level sessions
- https://ts.sdk.modelcontextprotocol.io/v2/serving/authorization — server-side authorization in the TS SDK
- https://ts.sdk.modelcontextprotocol.io/v2/serving/http — HTTP transport
- https://ai-sdk.dev/docs/agents/overview — agent loops
- https://ai-sdk.dev/docs/agents/loop-control — step limits and loop control
- https://ai-sdk.dev/docs/reference/ai-sdk-core/tool-loop-agent — ToolLoopAgent
- https://ai-sdk.dev/docs/agents/workflow-agent — workflow agents
- https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling — tool definitions, approval
- https://datatracker.ietf.org/doc/html/rfc8707 — RFC 8707 resource indicators (token audience binding)

## Mobile in-app purchase (`revenuecat-security`)
- https://www.revenuecat.com/docs/integrations/webhooks — webhook delivery; authorization header and HMAC signing are both opt-in
- https://www.revenuecat.com/docs/integrations/webhooks/event-types-and-fields — event types; there is no REFUND event (refunds arrive as CANCELLATION)
- https://www.revenuecat.com/docs/integrations/webhooks/sample-events — event payload shapes
- https://www.revenuecat.com/docs/api-v1 — REST v1; GET /subscribers is get-or-create, so a 200 is not authorization
- https://www.revenuecat.com/docs/api-v2 — REST v2
- https://www.revenuecat.com/docs/projects/authentication — public SDK key vs secret API key
- https://www.revenuecat.com/docs/customers/customer-info — entitlements object, client-side cache
- https://www.revenuecat.com/docs/customers/identifying-customers — logIn and the anonymous alias flow
- https://www.revenuecat.com/docs/customers/user-ids — App User ID guidance
- https://www.revenuecat.com/docs/customers/trusted-entitlements — signature verification of customer info
- https://www.revenuecat.com/docs/getting-started/entitlements — entitlement model
- https://www.revenuecat.com/docs/test-and-launch/sandbox — sandbox environment flag
- https://www.revenuecat.com/docs/test-and-launch/sandbox/apple-app-store — sandbox receipts

## OAuth / OIDC (`oauth-oidc-security`)
- https://www.rfc-editor.org/rfc/rfc9700.txt — OAuth 2.0 Security BCP: §2.1.1 PKCE and transaction-bound challenges, §4.1.3 exact redirect matching, §4.4.2 mix-up, §4.5 code injection, §4.7.1 CSRF/state, §4.11.1 open redirectors, §4.14.2 refresh rotation and reuse detection
- https://www.rfc-editor.org/rfc/rfc7636.txt — PKCE: §4.2 S256 is mandatory to implement, §4.3 `code_challenge_method` defaults to `plain`, §7.2 no downgrade
- https://www.rfc-editor.org/rfc/rfc9207.txt — the `iss` authorization response parameter (mix-up countermeasure)
- https://www.rfc-editor.org/rfc/rfc8252.txt — OAuth for native apps: §6 PKCE required, §8.12 no embedded user-agents
- https://openid.net/specs/openid-connect-core-1_0.html — OIDC Core: §3.1.3.7 ID token validation, §5.1 `email_verified` semantics, §8.1 pairwise subject identifiers
- https://openid.net/specs/openid-connect-backchannel-1_0.html — Back-Channel Logout §2.6 logout token validation rules
- https://www.descope.com/blog/post/noauth — nOAuth: mutable, unverified `email` claims and account takeover by email linking
- https://next-auth.js.org/faq — why automatic account linking between arbitrary providers is unsafe
- https://developer.okta.com/docs/guides/add-an-external-idp/openidconnect/main/ — match on email if you must, but key the user on the static `sub` claim
- https://arcticjs.dev/ — Arctic deprecated July 2026; replacement code published in the repository
- https://pilcrowonpaper.com/blog/18 — the deprecation announcement for Arctic and most Oslo packages
- https://raw.githubusercontent.com/pilcrowonpaper/arctic/refs/heads/main/code/authorization_request-pkce.ts — the hand-rolled authorization request: 32-byte hex verifier, S256 challenge, scoped `HttpOnly; Secure; SameSite=Lax; Max-Age=600` cookie
- https://raw.githubusercontent.com/pilcrowonpaper/arctic/refs/heads/main/code/authorization_code_exchange-pkce.ts — reading the stored verifier back and aborting when it is missing
- https://lucia-auth.com/ — Lucia deprecated March 2025; the site now hosts single-file replacement code
- https://raw.githubusercontent.com/panva/openid-client/main/docs/functions/authorizationCodeGrant.md — `authorizationCodeGrant(config, currentUrl, checks?, ...)`; the checks argument is optional
- https://raw.githubusercontent.com/panva/openid-client/main/docs/interfaces/AuthorizationCodeGrantChecks.md — `expectedState` / `expectedNonce` semantics when undefined; `skipStateCheck`
- https://raw.githubusercontent.com/panva/node-oidc-provider/main/docs/README.md — `pkce.required` default, `clientAuthMethods`, `rotateRefreshToken` chain revocation, `subjectTypes` / `pairwiseIdentifier` placeholder, the four-step JWKS rotation
- https://nodejs.org/api/crypto.html — `createCipheriv`, `setAAD`, `getAuthTag` after `final()`, `hkdfSync`
- https://www.rfc-editor.org/rfc/rfc5869.txt — HKDF extract-then-expand; `info` for purpose separation
- https://csrc.nist.gov/pubs/sp/800/38/d/final — NIST SP 800-38D, GCM authenticated encryption with associated data
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/ — A07:2025, where §1, §3, §4 and §7 land
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ — A01:2025, where §2, §5, §6 and §8 land

## Object storage (`object-storage-security`)
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html — presigned URLs are bearer credentials
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html — presigned PUT
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html — Block Public Access
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html — bucket policy
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html — bucket CORS
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html — versioning; "deleted" objects remain retrievable
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html — lifecycle rules
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html — S3 security best practices
- https://developers.cloudflare.com/r2/api/s3/presigned-urls/ — R2 presigned URLs (no presigned POST; 604800s cap)
- https://developers.cloudflare.com/r2/buckets/public-buckets/ — r2.dev is development-only and rate-limited
- https://developers.cloudflare.com/r2/api/tokens/ — scoping R2 API tokens to a bucket
- https://developers.cloudflare.com/r2/buckets/cors/ — R2 CORS
- https://developers.cloudflare.com/r2/buckets/object-lifecycles/ — R2 lifecycle rules
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — upload validation
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Disposition — forcing download instead of inline render

## CI/CD (`ci-cd-security`)
- https://docs.github.com/en/actions/reference/security/secure-use — privileged triggers, SHA pinning, redaction limits, self-hosted runner guidance
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows — `pull_request_target`, `workflow_run`, `issue_comment` semantics
- https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/ — pwn requests and the artifact/`workflow_run` split
- https://securitylab.github.com/resources/github-actions-untrusted-input/ — the attacker-controlled context list; env-indirection fix
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax — `permissions: {}`; fork tokens cannot be granted write
- https://docs.github.com/en/actions/tutorials/authenticate-with-github_token — least-privilege `GITHUB_TOKEN` pattern
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository — default workflow permissions and org inheritance
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets — secrets are not passed to fork-triggered runs
- https://docs.github.com/en/actions/how-tos/monitor-workflows/enable-debug-logging — `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG`
- https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching — cache scopes, untrusted triggers, the `cache-mode: write` opt-out
- https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 — CVE-2025-30066, tj-actions/changed-files tag repointing
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — CISA KEV: CVE-2025-30066 listed 2025-03-18
- https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions — AsyncAPI, July 2026: `pull_request_target` + PR-head checkout
- https://tanstack.com/blog/npm-supply-chain-compromise-postmortem — TanStack, May 2026: pwn request, cache poisoning, OIDC token theft
- https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised — secondary analysis of the TanStack compromise
- https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/ — branches as the cache security boundary
- https://www.legitsecurity.com/blog/artifact-poisoning-vulnerability-discovered-in-rust — artifact poisoning via `workflow_run` + `download-artifact`
- https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/ — ArtiPACKED: `persist-credentials` leaking tokens through artifacts
- https://docs.github.com/en/actions/reference/security/oidc — `id-token: write`, `sub` formats, immutable subject claims, Dependabot `event_name`
- https://docs.github.com/en/actions/concepts/security/openid-connect — how the cloud side evaluates OIDC claims
- https://raw.githubusercontent.com/sigstore/cosign/main/doc/cosign_verify.md — `--certificate-identity-regexp`, `--certificate-oidc-issuer`
- https://docs.sigstore.dev/cosign/verifying/verify/ — cosign keyless verification walkthrough
- https://github.com/actions/attest-build-provenance — producing signed build provenance; required permissions
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations — artifact attestations end to end
- https://cli.github.com/manual/gh_attestation_verify — `--signer-workflow` / `--signer-repo`
- https://github.com/zizmorcore/zizmor — static analysis for CI/CD
- https://docs.zizmor.sh/audits/ — the audit list mapped to sections 1-7
- https://github.com/rhysd/actionlint — workflow linter with script-injection checks
- https://github.com/ossf/scorecard/blob/main/docs/checks.md — Dangerous-Workflow, Token-Permissions, Pinned-Dependencies
- https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/ — fork MR pipelines run in the parent project
- https://docs.gitlab.com/ci/jobs/ci_job_token/ — `CI_JOB_TOKEN` scope and the job-token allowlist
- https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/ — A03:2025, where §3, §6, §9 and §10 land
- https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/ — A08:2025, where §1, §6, §8 and §9 land

## Cloudflare Workers (`cloudflare-workers-security`)
- https://developers.cloudflare.com/workers/configuration/environment-variables/ — `[vars]` are plaintext; "Do not use plaintext environment variables to store sensitive information"
- https://developers.cloudflare.com/workers/configuration/secrets/ — `wrangler secret put`; secrets not visible in Wrangler or dashboard; `.dev.vars` gitignore guidance
- https://developers.cloudflare.com/workers/wrangler/environments/ — non-inheritable keys; secrets per environment; environment-specific `.dev.vars.<name>`
- https://developers.cloudflare.com/workers/wrangler/configuration/ — the non-inheritable key list (bindings, environment variables)
- https://developers.cloudflare.com/workers/runtime-apis/bindings/ — `env` passed to every handler; "the permission is embedded within the API itself"
- https://developers.cloudflare.com/workers/runtime-apis/nodejs/ — the `nodejs_compat` compatibility flag and dates
- https://developers.cloudflare.com/workers/runtime-apis/nodejs/process/ — `nodejs_compat_populate_process_env` puts secrets in `process.env`
- https://developers.cloudflare.com/r2/api/workers/workers-api-usage/ — an unguarded Worker makes the bucket public; authorization logic lives in your Worker
- https://developers.cloudflare.com/d1/worker-api/prepared-statements/ — `prepare()` + `bind()` prevents SQL injection
- https://developers.cloudflare.com/kv/concepts/how-kv-works/ — eventual consistency, up-to-60s staleness, write-heavy workloads, "consider using Durable Objects"
- https://developers.cloudflare.com/durable-objects/concepts/what-are-durable-objects/ — transactional, strongly consistent, single-threaded storage
- https://developers.cloudflare.com/ai-gateway/configuration/authentication/ — `cf-aig-authorization`; an `AI Gateway Run` token reaches every gateway and BYOK key
- https://developers.cloudflare.com/workers-ai/ — the `env.AI` binding
- https://developers.cloudflare.com/fundamentals/reference/http-headers/ — `CF-Connecting-IP` vs appended `X-Forwarded-For`
- https://developers.cloudflare.com/workers/runtime-apis/request/ — `request.cf` and where it is unavailable
- https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/ — origin IP discovery bypasses Cloudflare; block non-Cloudflare traffic
- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/ — AOP ensures requests come from the Cloudflare network
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/ — `Cf-Access-Jwt-Assertion`, team JWKS endpoint, `aud` claim, Workers example
- https://developers.cloudflare.com/pages/functions/bindings/ — Pages Functions read bindings from `context.env`; Production and Preview are separate
- https://hono.dev/docs/guides/middleware — middleware executes in registration order
- https://hono.dev/docs/getting-started/cloudflare-workers — `c.env` bindings, typed `Bindings`, local `.dev.vars`
- https://hono.dev/docs/middleware/builtin/cors — `origin` defaults to `*`
- https://hono.dev/docs/middleware/builtin/csrf — Origin / `Sec-Fetch-Site` checks; form-submittable content types only
- https://hono.dev/docs/middleware/builtin/secure-headers — default header pack; CSP is "No Setting" by default
- https://hono.dev/docs/middleware/builtin/jwt — `secret`, `alg`, `Authorization` handling, `c.get('jwtPayload')`
- https://hono.dev/docs/middleware/builtin/ip-restriction — requires the environment's `getConnInfo`
- https://hono.dev/docs/helpers/conninfo — `getConnInfo` from `hono/cloudflare-workers`
- https://raw.githubusercontent.com/honojs/hono/main/src/adapter/cloudflare-workers/conninfo.ts — the Workers adapter reads `cf-connecting-ip`
- https://github.com/advisories/GHSA-w332-q679-j88p — CVE-2026-24473 serveStatic Workers-env key disclosure
- https://github.com/advisories/GHSA-gqvv-2mrq-wpjv — CVE-2026-84365 `toSSG()` writes outside the output directory
- https://github.com/advisories/GHSA-88fw-hqm2-52qc — CVE-2026-54290 cors() reflected origin with credentials
- https://github.com/advisories/GHSA-f23p-vx2j-j53r — CVE-2026-71850 `memo()` cross-user SSR disclosure
- https://github.com/advisories/GHSA-f67f-6cw9-8mq4 — CVE-2026-22817 JWK algorithm confusion
- https://github.com/advisories/GHSA-r354-f388-2fhh — CVE-2026-24398 ipRestriction IPv4 range bypass
- https://github.com/advisories/GHSA-xpcf-pg52-r92g — CVE-2026-39409 ipRestriction IPv4-mapped-IPv6 bypass
- https://github.com/advisories/GHSA-xrhx-7g5j-rcj5 — CVE-2026-47674 ipRestriction non-canonical IPv6 bypass
- https://github.com/advisories/GHSA-f577-qrjj-4474 — CVE-2026-47673 jwt middleware accepts any Authorization scheme
- https://github.com/advisories/GHSA-hm8q-7f3q-5f36 — CVE-2026-44459 improper exp/nbf/iat validation
- https://github.com/advisories/GHSA-p77w-8qqv-26rm — CVE-2026-44457 cache middleware ignores Vary
- https://github.com/advisories/GHSA-q5qw-h33p-qvwr — CVE-2026-29045 serveStatic arbitrary file access
- https://github.com/advisories/GHSA-wmmm-f939-6g9c — CVE-2026-39407 serveStatic middleware bypass via repeated slashes
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ — A01:2025, where §2, §3 and §7 land
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ — A02:2025, where §1, §3, §4 and §5 land
- https://top10.owasp.org/2025/A05_2025-Injection/ — A05:2025, where §6 lands

## Deployment (`deployment`)
- https://owasp.github.io/www-project-secure-headers/ — security headers (incl. clickjacking / frame-ancestors)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy — CSP
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security — HSTS
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS — CORS
- https://vercel.com/docs/deployment-protection — preview deployment protection

## Data access (`data-access`)
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — parameterized queries
- https://www.prisma.io/docs/orm/v7/prisma-client/using-raw-sql/raw-queries — $queryRaw vs $queryRawUnsafe
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html — mass assignment
- https://zod.dev/ — runtime validation
- https://orm.drizzle.team/docs/sql — Drizzle sql template parameterization vs sql.raw()
- https://github.com/drizzle-team/drizzle-orm/security/advisories/GHSA-gpj5-g38j-94v9 — Drizzle identifier escaping (CVE-2026-39356)
- https://osv.dev/vulnerability/GHSA-gpj5-g38j-94v9 — affected and fixed versions
- https://orm.drizzle.team/docs/dynamic-query-building — $dynamic() conditional query building
- https://orm.drizzle.team/docs/perf-queries — sql.placeholder in prepared statements
- https://sqlite.org/wal.html — the -wal and -shm sibling files
- https://sqlite.org/backup.html — file-copy backups can be corrupt
- https://sqlite.org/uri.html — mode=ro and immutable=1
- https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md — .prepare() binding vs .exec()
- https://docs.turso.tech/sdk/ts/reference — libSQL execute() with bound args
- https://docs.turso.tech/cli/db/tokens/create — --read-only and --expiration token flags
- https://developers.cloudflare.com/d1/worker-api/prepared-statements/ — D1 prepare().bind()

## Web vulnerabilities (`web-vulns`)
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — XSS
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — DOM XSS
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — SSRF
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — file upload
- https://community.owasp.org/attacks/Path_Traversal — path traversal
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html — IDOR
- https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/ — BOLA
- https://portswigger.net/web-security — worked examples

## Cryptography (`cryptography`)
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — hashing parameters
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html — algorithms, randomness, keys
- https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/ — OWASP A04:2025 Cryptographic Failures
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — key management
- https://nodejs.org/api/crypto.html — Node crypto

## Logging & monitoring (`logging-monitoring`)
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — what to log / exclude
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html — safe error responses
- https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/ — OWASP A09:2025 Security Logging and Alerting Failures
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — insecure deserialization
- https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/ — OWASP A08:2025 Software or Data Integrity Failures
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — command injection
- https://nodejs.org/api/child_process.html — execFile/spawn

## Dynamic verification (`dynamic-verification`)
- https://owasp.github.io/www-project-web-security-testing-guide/latest/ — OWASP Web Security Testing Guide (WSTG)
- https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security — WSTG HSTS test
- https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing — WSTG CORS test
- https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References — WSTG IDOR test
- https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting — WSTG reflected XSS test

## Orchestrator (`audit`)
- https://top10.owasp.org/2025/ — OWASP Top 10 (2025)
- https://genai.owasp.org/llm-top-10/ — OWASP LLM Top 10
- https://owasp.github.io/www-project-mobile-top-10/ — OWASP Mobile Top 10
