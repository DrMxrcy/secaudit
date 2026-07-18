# Sources

Every claim in the secaudit skills is backed by a primary source: official documentation,
vendor security advisories, the NVD / GitHub Advisory Database, OWASP, or primary research. Each
skill also lists its own sources in a `## Sources` section. This file is the consolidated index.

Last verified: 2026-06-28.

## Frameworks (`framework-versions`)
- https://nvd.nist.gov/vuln/detail/CVE-2025-55182 — React2Shell RSC RCE (CVSS 10.0)
- https://nvd.nist.gov/vuln/detail/CVE-2025-66478 — confirms the Next.js-side ID is a rejected duplicate of CVE-2025-55182
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — CISA KEV (React2Shell actively exploited)
- https://github.com/advisories/GHSA-f82v-jwr5-mffw — CVE-2025-29927 middleware bypass
- https://github.com/advisories/GHSA-67rr-84xm-4c7r — CVE-2025-49826 cache-poisoning DoS
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
- https://supabase.com/docs/guides/api/api-keys — Supabase publishable vs secret keys

## Database access (`database`)
- https://supabase.com/docs/guides/database/postgres/row-level-security — RLS
- https://supabase.com/docs/guides/api/api-keys — key model (BYPASSRLS)
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
- https://docs.convex.dev/file-storage — file URLs are unauthenticated
- https://stack.convex.dev/row-level-security — no built-in RLS

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
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/ — OWASP A01 Broken Access Control
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
- https://docs.stripe.com/payments/checkout/price-options — server-side Price IDs

## Supply chain (`supply-chain`)
- https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen — USENIX 2025 package-hallucination study
- https://arxiv.org/abs/2406.10279 — preprint of the same study
- https://www.lasso.security/blog/ai-package-hallucinations — Lasso Security huggingface-cli PoC
- https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks — Socket
- https://snyk.io/articles/slopsquatting-mitigation-strategies/ — mitigation
- https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json — lockfiles

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

## AI / LLM (`ai-integration`)
- https://genai.owasp.org/llm-top-10/ — OWASP Top 10 for LLM Applications (2025)
- https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ — official 2025 list
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices — MCP security
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization — MCP token-audience binding

## Deployment (`deployment`)
- https://owasp.org/www-project-secure-headers/ — security headers (incl. clickjacking / frame-ancestors)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy — CSP
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security — HSTS
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS — CORS
- https://vercel.com/docs/deployment-protection — preview deployment protection

## Data access (`data-access`)
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — parameterized queries
- https://www.prisma.io/docs/orm/prisma-client/queries/raw-database-access/raw-queries — $queryRaw vs $queryRawUnsafe
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
- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/ — OWASP A02
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — key management
- https://nodejs.org/api/crypto.html — Node crypto

## Logging & monitoring (`logging-monitoring`)
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html — what to log / exclude
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html — safe error responses
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/ — OWASP A09
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — insecure deserialization
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/ — OWASP A08
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — command injection
- https://nodejs.org/api/child_process.html — execFile/spawn

## Dynamic verification (`dynamic-verification`)
- https://owasp.org/www-project-web-security-testing-guide/latest/ — OWASP Web Security Testing Guide (WSTG)
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security — WSTG HSTS test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing — WSTG CORS test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References — WSTG IDOR test
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting — WSTG reflected XSS test

## Orchestrator (`audit`)
- https://owasp.org/Top10/ — OWASP Top 10 (2021)
- https://genai.owasp.org/llm-top-10/ — OWASP LLM Top 10
- https://owasp.org/www-project-mobile-top-10/ — OWASP Mobile Top 10
