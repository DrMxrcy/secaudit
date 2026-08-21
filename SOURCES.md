# Sources

Every claim in the secaudit skills is backed by a primary source: official documentation,
vendor security advisories, the NVD / GitHub Advisory Database, OWASP, or primary research. Each
skill also lists its own sources in a `## Sources` section. This file is the consolidated index.

Last verified: 2026-08-21.

## Frameworks (`framework-versions`)
- https://nvd.nist.gov/vuln/detail/CVE-2025-55182 — React2Shell RSC RCE (CVSS 10.0)
- https://nvd.nist.gov/vuln/detail/CVE-2025-66478 — confirms the Next.js-side ID is a rejected duplicate of CVE-2025-55182
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
- https://nextjs.org/blog — official Next.js security releases
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
- https://nvd.nist.gov/vuln/detail/CVE-2025-29927 — Next.js middleware authorization bypass
- https://vercel.com/blog/postmortem-on-next-js-middleware-bypass — bypass mechanism + fixed versions
- https://nextjs.org/blog/security-nextjs-server-components-actions — Server Actions are public endpoints
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — cookies, timeouts, session fixation
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — CSRF
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — auth, WebAuthn, error messages
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html — enumeration-safe reset
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie — cookie attributes
- https://www.w3.org/TR/webauthn-2/ — passkeys / WebAuthn

## Privilege escalation (`privilege-escalation`)
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ — OWASP API A05 (BFLA)
- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ — OWASP A01:2025 Broken Access Control (absorbs SSRF as of 2025)
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — authorization design, default-deny
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html — mass assignment / allowlisting
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation — WSTG privilege-escalation testing

## Rate limiting (`rate-limiting`)
- https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html — rate limiting
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — brute-force throttling
- https://upstash.com/docs/redis/sdks/ratelimit-ts/overview — Upstash sliding window

## Payments (`payments`)
- https://docs.stripe.com/webhooks/signature — raw-body signature verification
- https://docs.stripe.com/webhooks — constructEvent, endpoint secret
- https://docs.stripe.com/products-prices/how-products-and-prices-work — server-side Price IDs

## Supply chain (`supply-chain`)
- https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen — USENIX 2025 package-hallucination study
- https://arxiv.org/abs/2406.10279 — preprint of the same study
- https://www.lasso.security/blog/ai-package-hallucinations — Lasso Security huggingface-cli PoC
- https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks — Socket
- https://snyk.io/articles/slopsquatting-mitigation-strategies/ — mitigation
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json/ — lockfiles
- https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain — CHAINDROP/Shai-Hulud npm worm (2026-08-04): preinstall-hook delivery, 400+ packages, 300+ credential patterns, self-propagation via npm publish tokens
- https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack — same incident, independent analysis: keyv/cacheable ecosystem, IDE persistence attempts, no CVE assigned

## React Native (`react-native-security`)
- https://reactnative.dev/docs/security — official RN security guide
- https://owasp.org/www-project-mobile-top-10/ — OWASP Mobile Top 10 (2024)
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

## Deployment (`deployment`)
- https://owasp.org/www-project-secure-headers/ — security headers (incl. clickjacking / frame-ancestors)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy — CSP
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security — HSTS
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS — CORS
- https://vercel.com/docs/deployment-protection — preview deployment protection

## Data access (`data-access`)
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — parameterized queries
- https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries — $queryRaw vs $queryRawUnsafe
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html — mass assignment
- https://zod.dev/ — runtime validation

## Web vulnerabilities (`web-vulns`)
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — XSS
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html — DOM XSS
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — SSRF
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — file upload
- https://owasp.org/www-community/attacks/Path_Traversal — path traversal
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html — IDOR
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ — BOLA
- https://portswigger.net/web-security — worked examples

## Cryptography (`cryptography`)
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — hashing parameters
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html — algorithms, randomness, keys
- https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/ — OWASP A04:2025 Cryptographic Failures
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — key management
- https://nodejs.org/api/crypto.html — Node crypto

## Logging & monitoring (`logging-monitoring`)
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — what to log / exclude
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html — safe error responses
- https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/ — OWASP A09:2025 Security Logging and Alerting Failures
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — insecure deserialization
- https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/ — OWASP A08:2025 Software or Data Integrity Failures
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — command injection
- https://nodejs.org/api/child_process.html — execFile/spawn

## Dynamic verification (`dynamic-verification`)
- https://owasp.org/www-project-web-security-testing-guide/latest/ — OWASP Web Security Testing Guide (WSTG)
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security — WSTG HSTS test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing — WSTG CORS test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References — WSTG IDOR test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting — WSTG reflected XSS test

## Orchestrator (`audit`)
- https://owasp.org/Top10/2025/ — OWASP Top 10 (2025)
- https://genai.owasp.org/llm-top-10/ — OWASP LLM Top 10
- https://owasp.org/www-project-mobile-top-10/ — OWASP Mobile Top 10
