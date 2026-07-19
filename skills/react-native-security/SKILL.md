---
name: react-native-security
description: Audits React Native (framework-agnostic) mobile security — secrets in the JS bundle, secure token storage with react-native-keychain vs AsyncStorage, deep link / URL scheme validation, WebView risks (onMessage, injectedJavaScript, file access), native bridge trust, network security (ATS, cleartext, SSL pinning), OAuth PKCE, and logging leaks. Use when building or reviewing a React Native app's storage, networking, deep links, WebViews, or native modules. For Expo/EAS-specific concerns (EXPO_PUBLIC_, EAS secrets, OTA updates), use secaudit:expo-security.
license: MIT
---

# React Native Security (Core)

> **Redaction:** When you find a real secret in the JS bundle or source, report its **location**
> and a **masked** form (`***`, last 4 chars) — never echo the literal key/token into your output.
> Treat it as compromised and tell the user to rotate it.

Framework-agnostic React Native. For Expo/EAS-specific items (`EXPO_PUBLIC_`, EAS secrets,
`expo-secure-store`, OTA/EAS Update), use `secaudit:expo-security`. Maps to the OWASP Mobile
Top 10 (2024).

## When to Use

- Building or reviewing a bare/framework-agnostic React Native app.
- Auditing token storage, networking, deep links, WebViews, or custom native modules.
- (For Expo/EAS toolchain concerns, use `secaudit:expo-security`.)

## 1. Secrets / API Keys in the JS Bundle

The JS bundle ships to the device. On iOS it is minified (not obfuscated) JS inside the `.ipa`; on
Android it is in the APK (Hermes bytecode is still decompilable). Anyone can unzip the app and
extract strings. `react-native-config` / `react-native-dotenv` values are inlined at build time and
are **not** secret.

```typescript
// BAD: key shipped in the bundle, extractable
const r = await fetch("https://api.openai.com/v1/chat/completions", {
  headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
});

// GOOD: secret stays server-side; the app calls your backend, which injects the key
const r = await fetch("https://api.myapp.com/ai/chat", {
  headers: { Authorization: `Bearer ${userSessionToken}` },
});
```

Only publishable/restricted client keys (Stripe publishable key, Firebase web API key) belong in
the app, and those must be paired with server-side authorization, not treated as secrets.

## 2. Insecure Token Storage: AsyncStorage vs Keychain/Keystore

AsyncStorage is an unencrypted, app-sandboxed key-value store (the mobile equivalent of
localStorage). On a rooted/jailbroken device, in a backup, or via debugging it is readable in
plaintext. Never store tokens, refresh tokens, passwords, or encryption keys there.

```typescript
// BAD
await AsyncStorage.setItem("accessToken", token); // plaintext on disk

// GOOD — react-native-keychain (iOS Keychain / Android Keystore-backed)
import * as Keychain from "react-native-keychain";
await Keychain.setGenericPassword("auth", token, {
  accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY,            // optional gating
  accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY, // not in iCloud/backups
  securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,         // prefer hardware
});
```

Watch for `redux-persist` backed by AsyncStorage accidentally persisting a state tree that contains
tokens. `react-native-mmkv` is **not** encrypted by default — pass an `encryptionKey` and store
that key in Keychain/Keystore, never in AsyncStorage.

## 3. Logging / Debug Tools Leaking Sensitive Data

`console.*` calls remain in release bundles and surface in device logs (logcat / Console.app).
Crash/analytics SDKs (Sentry, Crashlytics) can ship tokens off-device in breadcrumbs or network
logs.

```typescript
// Strip console.* in production (babel-plugin-transform-remove-console)
// Scrub before sending to crash reporters:
Sentry.init({ beforeSend(e) { delete e.request?.headers?.Authorization; return e; } });
// Keep debug tooling dev-only:
if (__DEV__) { /* init Flipper / Reactotron */ }
```

## 4. Deep Link / URL Scheme Validation

Custom URL schemes (`myapp://`) have **no ownership registration** — any app can register the same
scheme and intercept the link (and any token in it). Treat deep links as untrusted input.

```typescript
// BAD: trust token straight from the link
Linking.addEventListener("url", ({ url }) => { const t = parse(url).query.token; login(t); });

// GOOD:
//  - iOS: Universal Links (apple-app-site-association)
//  - Android: App Links with android:autoVerify="true" + assetlinks.json
//  - Never put secrets in links; whitelist hosts/paths, reject unexpected params,
//    never auto-execute privileged actions from a link
```

## 5. OAuth on Mobile — Use PKCE

A hand-rolled authorization-code flow over a custom redirect scheme can be intercepted by a
malicious app registering the same scheme. Use `react-native-app-auth` (wraps native AppAuth) with
PKCE; never embed an OAuth client secret in the app.

```typescript
import { authorize } from "react-native-app-auth";
const result = await authorize({ issuer, clientId, redirectUrl, scopes, usePKCE: true });
```

## 6. Network Security: HTTPS, ATS, Cleartext, SSL Pinning

- No `http://` endpoints.
- iOS: do not set `NSAppTransportSecurity → NSAllowsArbitraryLoads = true` (disables ATS globally).
- Android: do not set `usesCleartextTraffic="true"`; use a restrictive `network_security_config.xml`.
- For high-value APIs, pin the public key / intermediate CA (e.g. `react-native-ssl-pinning`) — but
  pin to the key, coordinate rotation with releases, and keep HTTPS as the baseline, or a cert
  renewal bricks the app.

```xml
<!-- Android res/xml/network_security_config.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false"/>
</network-security-config>
```

## 7. WebView Risks (high-severity)

A WebView is a full browser. If untrusted content (including a child iframe) loads, it can reach
the JS↔native bridge: on Android `addJavascriptInterface` is exposed to all frames; on iOS any
iframe can call the message handler. XSS in the page then becomes native code/data access.

```jsx
<WebView
  source={{ uri: TRUSTED_URL }}
  originWhitelist={["https://app.myapp.com"]}    // positive allowlist
  javaScriptEnabled={false}                       // true only when required
  allowFileAccess={false}
  allowUniversalAccessFromFileURLs={false}
  allowFileAccessFromFileURLs={false}
  onMessage={(e) => { /* validate sender + shape; never eval; never auto-run native actions */ }}
/>
```

Load only trusted HTTPS first-party content; open untrusted links in the external browser
(`Linking.openURL`). Validate origin inside injected JS using immutable `location.origin`. Keep
`react-native-webview` up to date (older versions had arbitrary-navigation CVEs).

## 8. Native Module / Bridge Trust Boundary

The JS↔native bridge is a trust boundary; JS is fully attacker-controllable on a tampered device or
via a WebView/XSS pivot. Custom native modules must treat every argument as untrusted: validate /
whitelist file paths, parameterize SQL, and never expose generic `eval`/`exec`/arbitrary-file
primitives to JS. Keep modules narrow and enforce authorization in native code.

## 9. Jailbreak / Root & Binary Protection (defense-in-depth)

On rooted/jailbroken devices, sandbox and Keychain/Keystore protections weaken and attackers can
hook the app (Frida/Objection). For high-value apps (fintech, health), add root/jailbreak + hook
detection (`jail-monkey` or commercial RASP) to gate sensitive flows — but always enforce real
security server-side; client-side controls are bypassable.

```typescript
import JailMonkey from "jail-monkey";
if (JailMonkey.isJailBroken()) { /* degrade, warn, or block sensitive features */ }
```

Reduce reverse-engineering payoff: enable Hermes, ship release builds (no source maps / dev menu),
and strip console logs.

## Sources

- https://reactnative.dev/docs/security -- official RN security guide (keys, storage, deep links, PKCE, pinning)
- https://owasp.org/www-project-mobile-top-10/ -- OWASP Mobile Top 10 (2024)
- https://mas.owasp.org/MASVS/ -- OWASP MASVS
- https://github.com/oblador/react-native-keychain -- Keychain/Keystore-backed storage
- https://github.com/react-native-webview/react-native-webview/blob/master/docs/Reference.md -- WebView security props
