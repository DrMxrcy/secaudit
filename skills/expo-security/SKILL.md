---
name: expo-security
description: Audits Expo and EAS-specific mobile security — EXPO_PUBLIC_ env vars inlined into the bundle, the misconception that EAS "Secret" vars are safe in the app, expo-secure-store vs AsyncStorage, EAS Update / OTA code signing, app.json/app.config.js extra exposure, config plugins running arbitrary build code, deep links in Expo Router, and the +api.ts backend-proxy pattern. Use when the project uses Expo or EAS (app.json/app.config, eas.json, expo-updates, Expo Router). For framework-agnostic React Native, use secaudit:react-native-security.
license: MIT
---

# Expo + EAS Security

> **Redaction:** When you find a real secret inlined into the bundle or config, report its
> **location** and a **masked** form (`***`, last 4 chars) — never echo the literal key/token into
> your output. Treat it as compromised and tell the user to rotate it.

Expo/EAS-specific concerns. For framework-agnostic React Native (Keychain, WebView, native bridge,
ATS), use `secaudit:react-native-security`. The mental model to repeat throughout:
**everything shipped in the JS bundle, the app binary, or `app.json` is public and trivially
extractable from a downloaded app.**

## When to Use

- The project uses Expo or EAS (`app.json` / `app.config.js`, `eas.json`, `expo-updates`,
  Expo Router, `expo-secure-store`).
- Reviewing environment variables, OTA updates, deep links, or app config in an Expo app.
- (For bare React Native concerns, use `secaudit:react-native-security`.)

## 1. `EXPO_PUBLIC_` Vars Holding Secrets

Expo's Metro config statically replaces `process.env.EXPO_PUBLIC_*` with the literal value at build
time, inlining it into the JS bundle. Expo's docs are explicit: do not store sensitive info in
`EXPO_PUBLIC_` variables. They are visible in plain text in the compiled app.

```js
// BAD — secret inlined into the bundle, extractable by anyone
const res = await fetch('https://api.openai.com/v1/chat/completions', {
  headers: { Authorization: `Bearer ${process.env.EXPO_PUBLIC_OPENAI_API_KEY}` },
});

// GOOD — call your own backend; secret stays server-side (see §8)
const res = await fetch(`${process.env.EXPO_PUBLIC_API_URL}/api/chat`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${userSessionToken}` },
  body: JSON.stringify({ prompt }),
});
```

`EXPO_PUBLIC_` is fine ONLY for inherently public values (public API base URLs, a Supabase anon key
protected by RLS, a Stripe publishable key). Never the secret half of a pair.

## 2. EAS "Secret" Vars vs Build-Time Inlining (the dangerous misconception)

EAS visibility levels (Plain text / Sensitive / Secret) only control who can read the value **in
the EAS dashboard, CLI, and build logs** — not whether it ends up in the app. Expo: *"Secrets do
not provide any additional security for values that you end up embedding in your application
itself."* A "Secret" EAS var inlined at build time is still public in the binary.

- EAS Secret vars are for values that influence the build job and never reach the client
  (`NPM_TOKEN`, an Apple API key, a Sentry auth token for source-map upload).
- Anything the running app needs to keep secret must live behind a backend (§8), not in any EAS var.
- Watch for `eas.json` build profiles mapping a real secret into an `EXPO_PUBLIC_`-prefixed name —
  that re-exposes it.

## 3. Token Storage: `expo-secure-store` vs AsyncStorage

AsyncStorage is unencrypted plaintext on disk. Use `expo-secure-store` (iOS Keychain / Android
Keystore) for tokens, session JWTs, and PII.

```js
// BAD — token in plaintext
await AsyncStorage.setItem('authToken', token);

// GOOD — encrypted, hardware-backed where available
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('authToken', token, {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY, // not migrated to new devices
  requireAuthentication: true, // optional: gate behind biometrics/passcode
});
```

Notes: SecureStore has a ~2KB per-value practical limit (don't store large blobs); on iOS, Keychain
data persists across app uninstalls for the same bundle ID — clear it on logout.

## 4. EAS Update / OTA Integrity — Code Signing

OTA updates ship new JS to installed apps outside App Store / Play review. Without code signing,
anyone in the delivery path (ISPs, CDNs, cloud providers, even EAS) could tamper with an update and
inject malicious code. Code signing verifies signatures on the client before applying an update.

```sh
# 1. Generate keys + embedded certificate
npx expo-updates codesigning:generate \
  --key-output-directory ../keys \
  --certificate-output-directory certs \
  --certificate-validity-duration-years 10 \
  --certificate-common-name "Your Org"
```
```jsonc
// 2. app.json — certificate embedded in the binary
{ "expo": { "updates": {
  "url": "https://u.expo.dev/<project-id>",
  "codeSigningCertificate": "./certs/certificate.pem",
  "codeSigningMetadata": { "keyid": "main", "alg": "rsa-v1_5-sha256" }
}}}
```
```sh
# 3. Sign every published update locally (private key never leaves your machine)
eas update --private-key-path ../keys/private-key.pem
```

Flag: an `updates` block present in app config with **no** `codeSigningCertificate`, or `eas update`
invoked without `--private-key-path`. Never commit the private key (see §6); expired certs stop
applying updates, so track key rotation.

## 5. App Config (`app.json` / `app.config.js`) Secrets Exposure

The resolved app config is serialized and embedded in the app binary; `extra` is readable at
runtime via `expo-constants`. Committed `app.json` also lands in git history forever.

```js
// BAD — secret pulled into extra, ends up in the bundle
export default { expo: { extra: { mapsServerKey: process.env.MAPS_SERVER_KEY } } };

// GOOD — only public-safe values in extra; secrets stay server-side
export default { expo: { extra: { apiBaseUrl: process.env.EXPO_PUBLIC_API_URL } } };
```

Restrict map/SDK keys by bundle ID + API at the vendor console as defense-in-depth.

## 6. Secrets Committed to Git

Add `.env`, OTA `*private-key*.pem`, `credentials.json`, `*.keystore`, `*.p8`/`*.p12`, and
`google-services.json`/`GoogleService-Info.plist` (when they hold secrets) to `.gitignore`. Check
git history, not just the working tree. The OTA code-signing private key (§4) leaking is
catastrophic — it lets an attacker sign malicious updates.

```gitignore
.env
.env*.local
credentials.json
*.keystore
*.p8
*.p12
keys/            # OTA code-signing private keys
```

If already committed: rotate the secret/key and purge history; use EAS env vars / `eas credentials`
instead of in-repo files.

## 7. Deep Linking / Universal Links (Expo Router)

Custom schemes (`myapp://`) have no domain verification — any app can register the same scheme and
intercept the link. Expo Router auto-enables deep links for all routes, so every screen is reachable
via a crafted link and every param is attacker-controlled.

```ts
// BAD — trusts deep-link params: open redirect + unvalidated identity
const { next, userId } = useLocalSearchParams();
router.replace(next as string);   // open redirect / phishing
loadProfile(userId);              // identity from URL, not session

// GOOD — validate/allowlist params; identity from authenticated session
const { next } = useLocalSearchParams();
const safe = typeof next === 'string' && next.startsWith('/') && !next.startsWith('//');
router.replace(safe ? next : '/home');
loadProfile(session.userId);
```

For OAuth / magic links, prefer Universal Links / App Links (verified domain) over custom schemes,
and host a valid `apple-app-site-association` and `assetlinks.json`.

## 8. API Keys in the Bundle → Backend Proxy (`+api.ts`)

A secret read inside an Expo Router API route (`+api.ts`) and anything it imports is **not** included
in the client bundle.

```ts
// app/api/chat+api.ts — runs on the server (EAS Hosting); secret never bundled
export async function POST(req: Request) {
  const session = await requireSession(req);                 // 1. authenticate first
  if (!session) return Response.json({ error: 'unauthorized' }, { status: 401 });
  await rateLimit(session.userId);                           // 2. throttle abuse
  const { prompt } = await req.json();                       // 3. validate input
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` }, // server-only, NOT EXPO_PUBLIC_
    body: JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] }),
  });
  return Response.json(await r.json());
}
```

The proxy must authenticate the session (an unauthenticated proxy just relocates the leak), apply
rate limiting, validate inputs, and use least-privilege keys.

## 9. Config Plugins — Supply-Chain / Arbitrary-Code Risk

Config plugins are JavaScript executed during `npx expo prebuild` and can modify native iOS/Android
files — i.e. they run arbitrary code on your build machine / CI and can exfiltrate build-time secrets
(EAS env vars, signing creds) or inject native backdoors. Pin exact versions, prefer first-party /
official plugins, review source, and scope EAS build secrets to least privilege.

## Detection Cheat-Sheet

- `EXPO_PUBLIC_\w*(KEY|SECRET|TOKEN|PASSWORD|SERVICE_ROLE)` in `.env*` and source
- `AsyncStorage.setItem\(.*(token|jwt|secret|password|refresh)`
- `Authorization.*Bearer.*(process\.env|sk_live|sk-)` in client code (not in `*+api.ts`)
- `updates` block present in app config but no `codeSigningCertificate`
- `extra:` in `app.config.*` containing key/secret/token values
- `.env`, `*.pem`, `*.keystore`, `*.p8`, `credentials.json` tracked by git (`git ls-files`)
- custom `scheme` used as OAuth/magic-link redirect with no hosted AASA / `assetlinks.json`

## Sources

- https://docs.expo.dev/guides/environment-variables/ -- EXPO_PUBLIC_ visible in the compiled app
- https://docs.expo.dev/eas/environment-variables/ -- EAS visibility levels do not secure embedded values
- https://docs.expo.dev/versions/latest/sdk/securestore/ -- expo-secure-store (Keychain/Keystore)
- https://docs.expo.dev/eas-update/code-signing/ -- OTA code signing verified on-client
- https://docs.expo.dev/config-plugins/introduction/ -- config plugins run during prebuild
