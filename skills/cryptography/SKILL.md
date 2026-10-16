---
name: cryptography
description: Audits cryptographic failures (OWASP A04:2025) - password storage with fast hashes or no salt, insecure randomness for tokens/session IDs, weak or legacy algorithms and modes (DES, RC4, MD5, ECB), reused or hardcoded IVs and keys, JWT algorithm confusion, and storing app-issued secrets by entropy (API keys as prefix + SHA-256, join/invite codes and PINs via peppered HMAC, AES-256-GCM with AAD for stored webhook URLs and third-party keys). Use when handling passwords, generating tokens or reset links or session IDs or API keys, encrypting data, or storing keys. Recommends current OWASP and NIST parameters.
license: MIT
---

# Cryptography (OWASP A04:2025 — Cryptographic Failures)

> **Redaction:** When a finding exposes a real key, IV, or secret, report its **location** and a
> **masked** form (`***`, last 4 chars) — never paste the literal value into your output. Treat it
> as compromised and tell the user to rotate it.

## When to Use

- Hashing or verifying passwords.
- Generating tokens, password-reset links, session IDs, API keys, or OTPs.
- Encrypting data at rest or choosing a cipher/mode.
- Storing or rotating encryption keys.
- Storing API keys, session or handoff tokens, or invite links at rest (hash scheme by entropy, §6–7).
- Storing short join/invite codes or PINs that are looked up by value (§8).
- Storing a secret you must use later: webhook URLs, third-party API keys (§9).
- Configuring JWT verification (cross-links `secaudit:auth`).

## 1. Password Storage

**What to look for:** fast hashes on passwords (`createHash('md5'|'sha1'|'sha256')`), plaintext
comparison (`user.password === input`), no per-user salt or a single global salt, bcrypt cost below 10.

**Why it's exploitable:** MD5/SHA-family hashes are designed to be fast, so a stolen DB can be
brute-forced at billions of guesses/sec on GPUs. No salt enables rainbow tables and reveals identical
passwords across accounts. Plaintext means one leak is total compromise plus cross-site reuse.

**Current OWASP parameters (preference order):**
1. **Argon2id** - minimum `m=19456 (19 MiB), t=2, p=1`.
2. **scrypt** - minimum `N=2^17, r=8, p=1`.
3. **bcrypt** - work factor >= 10; note the 72-byte input limit.
4. **PBKDF2** (FIPS only) - PBKDF2-HMAC-SHA256 at 600,000 iterations.

Salts are generated automatically by these algorithms. Re-hash lazily on next login to raise the work
factor. An optional app-wide pepper (stored in a KMS/env, not the DB) can be applied via HMAC first.

```ts
// src/auth/password.ts — BEFORE: fast, unsalted hash (GPU-crackable)
import crypto from "node:crypto";
export const hashPw = (pw: string) => crypto.createHash("sha256").update(pw).digest("hex");

// AFTER: Argon2id with OWASP parameters (salt embedded automatically)
import argon2 from "argon2";
export const hashPw = (pw: string) =>
  argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
export const verifyPw = (hash: string, pw: string) => argon2.verify(hash, pw); // constant-time
```

## 2. Secure Randomness

**What to look for:** a non-cryptographic PRNG (`Math.random()`), timestamps, or counters used to build
session IDs, password-reset tokens, API keys, OTPs, or CSRF tokens.

**Why it's exploitable:** `Math.random()` is a non-cryptographic PRNG; its internal state can be
recovered from a few outputs, letting an attacker predict future tokens and hijack sessions or forge
reset links. It is never safe for security values.

```ts
// src/tokens.ts — BEFORE: predictable, low-entropy
export const resetToken = () => Math.random().toString(36).slice(2);

// AFTER: CSPRNG
import crypto from "node:crypto";
export const resetToken = () => crypto.randomBytes(32).toString("base64url");      // 256-bit
export const otp = () => crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
// Browser/edge: crypto.getRandomValues(new Uint8Array(32)). Also: crypto.randomUUID().
```

Reset tokens should be single-use, expiring, and stored hashed.

## 3. Weak Algorithms, Modes, and Hardcoded Keys/IVs

**What to look for:** DES/3DES/RC4 ciphers, **ECB** mode, MD5/SHA1 for signatures/HMAC, hardcoded
keys/IVs in source, a static or zero IV reused across messages, and the deprecated `createCipher` (no
IV control).

**Why it's exploitable:** ECB encrypts identical plaintext blocks to identical ciphertext, leaking
structure. DES/3DES/RC4 are broken or deprecated. A reused IV/nonce destroys confidentiality - and in
**GCM a nonce reuse leaks the auth key**, enabling forgery. Hardcoded keys in the repo let anyone with
source access decrypt everything.

```ts
// src/crypto.ts — BEFORE: ECB + hardcoded key, no integrity
import crypto from "node:crypto";
const KEY = "mysecretkey12345"; // committed to git
const c = crypto.createCipheriv("aes-128-ecb", KEY, null);

// AFTER: AES-256-GCM, key from env/KMS, unique nonce per message
import crypto from "node:crypto";
const KEY = Buffer.from(process.env.ENC_KEY_B64!, "base64"); // 32 bytes, never in source
export function encrypt(plain: Buffer) {
  const iv = crypto.randomBytes(12);                 // unique 96-bit nonce per message
  const c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { iv, ct, tag: c.getAuthTag() };            // tag = integrity + authenticity
}
```

Prefer authenticated modes (AES-GCM/AES-CCM, key >= 128-bit). Never use ECB; never reuse an IV/nonce.

## 4. JWT Algorithm Confusion (cross-link: auth)

**What to look for:** `jwt.verify(token, key)` with no explicit `algorithms` allowlist; accepting
`alg: "none"`; using one value as both HMAC secret and RSA public key.

**Why it's exploitable:** if the verifier trusts the token's own `alg` header, `alg:none` strips the
signature, and HS256/RS256 confusion lets an attacker sign with HS256 using the public RSA key (treated
as the HMAC secret) to forge tokens.

```ts
// src/auth/jwt.ts — pin algorithms explicitly; never trust the header alg
jwt.verify(token, publicKey, { algorithms: ["RS256"] });
```

Full token-lifecycle guidance lives in `secaudit:auth`.

## 5. Encryption at Rest + Key Management

Store keys outside the codebase (env injected at runtime, or KMS/Vault); never commit them or bake them
into images. Use distinct keys per environment, tag ciphertext with a key ID, and have a rotation
procedure before you need it (rotate on suspected compromise or cryptoperiod expiry). Prefer envelope
encryption (separate data-encryption and key-encryption keys). See `secaudit:secrets`.

For the concrete token-vault pattern — AES-256-GCM with the row's identity as AAD so ciphertext
cannot be moved between rows, and HKDF `info` purpose separation so the token key is not the cookie
key — see `secaudit:oauth-oidc-security` §5 (storing provider access/refresh tokens at rest).

## 6. Storing Secrets You Must Look Up: The Entropy Rule

**What to look for:** every column holding a credential the app issues or receives. For each one,
find the generator (how many random bits?) and the storage call (`createHash`, `createHmac`,
`argon2.hash`, `createCipheriv`, or none).

**Why it matters:** whether a hash protects a leaked secret depends on the secret's entropy, not on
the hash's name. An attacker holding a DB dump runs offline guesses, and NIST SP 800-63B-4 puts the
attacker's speed at "many billions of hashes per second in an offline environment that is not
subject to rate limiting". At an assumed 10^10 SHA-256 guesses/sec on one rig:

| Secret shape | Keyspace | Exhaust the keyspace offline |
|---|---|---|
| 6 decimal digits | 10^6 ≈ 2^20 | ~0.1 ms |
| 6 chars, `A-Z0-9` | 36^6 ≈ 2^31 | ~0.2 s |
| 8 chars, 32-symbol alphabet | 32^8 = 2^40 ≈ 1.1 × 10^12 | ~110 s |
| 10 chars, 32-symbol alphabet | 32^10 = 2^50 | ~31 hours |
| 32 bytes from a CSPRNG | 2^256 | not possible (2^128 alone is ~10^21 years) |

**The rule:**
- **≥128 bits from a CSPRNG** (`randomBytes(32)`, §2): store a fast unkeyed hash, `SHA-256(secret)`.
  Brute force is not an option at this size, and the hash has to be deterministic so the lookup can
  hit an index. NIST SP 800-63B-4 §3.1.2.2 draws the line at 112 bits: "All look-up secrets SHALL be
  stored in a hashed form using an approved hashing function", and those shorter than "112 bits as of
  the date of this publication" "SHALL be stored in a salted and hashed form using a suitable password
  hashing scheme".
- **Short or human-typed** (join/invite codes, PINs, 6-digit codes): a deterministic unkeyed hash
  gives no protection. Use one of the schemes in §8, and put attempt limits in front of it.
- **Chosen by a human** (passwords): argon2id, §1.
- **You need the plaintext back** (a webhook URL you post to, a third-party API key, an OAuth
  refresh token): hashing doesn't work at all. Encrypt it, §9.

A slow salted hash (argon2id, bcrypt) **cannot back a lookup by value.** Each row has its own random
salt, so `hash(input)` comes out different for every row and there is nothing to put in a `WHERE`
clause. Code that argon2-hashes an API key or a join code either scans every row with `verify()`
(a CPU-exhaustion DoS, and it gets slower as the table grows) or quietly uses a fixed salt (which
makes it a deterministic hash again, only slower). Look up by a public id, then run the slow verify
on that one row.

**Classify every stored secret:**

| Stored secret | Typical entropy | Plaintext needed later? | Store as |
|---|---|---|---|
| Password | low, human-chosen | no | argon2id (§1) |
| API key / personal access token | 256-bit CSPRNG | no | public id/prefix + `SHA-256(secret)` (§7) |
| Opaque session token | ≥64 bits (NIST §5.1 floor); issue 256 | no | `SHA-256(token)`, indexed |
| Reset, magic-link, email-verify, handoff token | 256-bit CSPRNG | no | `SHA-256(token)` + expiry + single use |
| Invite *link* token | 256-bit CSPRNG | no | `SHA-256(token)` + expiry + usage cap |
| Typed join/invite code, PIN, emailed 6-digit code | 20–50 bits | no | HMAC-SHA256 with pepper, or id + argon2id; throttled (§8) |
| Recovery codes | ≥64 bits (NIST §4.2.1.1) | no | salted password hash per code (NIST §4.2.1.1 → §3.1.1.2), throttled per §3.2.2 |
| Outbound webhook URL, third-party API key, OAuth token | not yours to choose | yes | AES-256-GCM with AAD (§9) |
| Your own signing secret for an outbound HMAC | 256-bit | yes | secret manager, or encrypted as in §9 |

## 7. API Keys: Public Prefix, Lookup Id, Hashed Secret

**What to look for:** API keys stored in plaintext; keys that are a bare `randomUUID()` with no
prefix; lookup by `findFirst({ where: { key } })` against a plaintext column; argon2/bcrypt over the
key with a full-table `verify()` loop; keys that can be shown again after creation; no scopes,
expiry, revocation or `lastUsedAt`; full keys in logs or error reports.

**Why it's exploitable:** a plaintext key column means any read-only leak (a backup, a logged query,
a read-only SQL injection) hands out working credentials for every customer. A key without a
recognisable shape is also hard for secret scanners to spot once it gets committed. GitHub moved
to prefixed tokens because their old hex tokens were "indistinguishable from other encoded data like
SHA hashes". The `_` separator is there because "An underscore is not a Base64 character". And a
checksum "virtually eliminates false positives for secret scanning offline" — they use "A 32 bit
checksum in the last 6 digits of each token", CRC32 encoded as Base62. GitHub's secret-scanning
partner program lists the same three properties for scannable secrets: "A uniquely defined prefix",
"High entropy random strings", "A 32-bit checksum".

**Fix:** format the key as `<app>_<env>_<public id>_<secret><checksum>` (or `<app>_<secret>` plus a
unique index on `SHA-256(full key)` if you don't need a separate id). The id is not a secret: show it
in the dashboard, log it, rate-limit on it. Store only `SHA-256(secret)`. When a key comes in, check
its shape and checksum (no DB round-trip for typos or scanner noise), look the row up by id, then
compare digests in constant time.

```ts
// lib/apiKeys.ts — the full key is shown once; the DB keeps the id + SHA-256(secret)
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { crc32 } from "node:zlib";                                // Node >= 22.2 / 20.15
const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const b62 = (buf: Buffer, len: number) => {                       // fixed-width base62 (no "_" or "-")
  let n = BigInt("0x" + buf.toString("hex")), s = "";
  while (n > 0n) { s = B62[Number(n % 62n)] + s; n /= 62n; }
  return s.padStart(len, "0");
};
const sha256 = (s: string) => createHash("sha256").update(s).digest();
const checksum = (body: string) => { const b = Buffer.alloc(4); b.writeUInt32BE(crc32(body)); return b62(b, 6); };

export function issueApiKey() {
  const id = b62(randomBytes(8), 11);                             // public lookup id
  const secret = b62(randomBytes(32), 43);                        // 256-bit CSPRNG secret
  const body = `myapp_live_${id}_${secret}`;
  return { key: body + checksum(body), row: { id, secretHash: sha256(secret) } };
}

const KEY_RE = /^myapp_live_([0-9A-Za-z]{11})_([0-9A-Za-z]{43})([0-9A-Za-z]{6})$/;
export async function verifyApiKey(presented: string) {
  const m = KEY_RE.exec(presented);
  if (!m || checksum(`myapp_live_${m[1]}_${m[2]}`) !== m[3]) return null;  // no DB hit
  const row = await db.apiKey.findUnique({ where: { id: m[1] } });
  if (!row || row.revokedAt || (row.expiresAt && row.expiresAt < new Date())) return null;
  if (!timingSafeEqual(sha256(m[2]), row.secretHash)) return null;   // both 32 bytes
  return row;  // authorize from row.scopes / row.tenantId, never from the request
}
```

`timingSafeEqual` throws if the two buffers differ in length (Node: "An error is thrown if `a` and
`b` have different byte lengths"), so compare fixed-size digests, never raw strings. A checksum is
there to catch typos and filter scanner hits. It is not authentication, since anyone can compute it.

**Lifecycle the review should find:**
- **Shown once**: after creation the UI shows only the prefix and id (`myapp_live_C44ab8Z9vAq_…`).
- **Scoped and owned**: the row carries `tenantId`, `scopes`, `expiresAt`, `revokedAt`, and the
  handler authorizes from those columns.
- **`lastUsedAt`** recorded (throttled to about one write per minute per key), so stale keys can be
  reaped and a leak can be scoped.
- **Rotation with overlap**: issue the new key, keep both valid for a stated window, then revoke.
  Revocation applies on the next request, with no cached "valid" past `revokedAt`.
- **Never log the full key**: log the id, and redact `KEY_RE` matches before the logger or crash
  reporter sees them (`secaudit:logging-monitoring`).
- **Leak response**: GitHub's partner program sends matches to "a service provider's verify
  endpoint". Revoke on receipt; GitHub recommends treating reported secrets "as public and
  compromised".

## 8. Low-Entropy Codes: Join/Invite Codes, PINs, Short OTPs

**What to look for:** a 6–10 character code that people type in (community join code, team invite
code, device-pairing PIN, emailed 6-digit code) stored as `sha256(code)` or `md5(code)`, or as
plaintext; a spec or comment that says "argon2id **or** deterministic hash"; a redeem endpoint with
no attempt limit; codes with no expiry or usage cap.

**Why it's exploitable:** offline, an unkeyed deterministic hash of an 8-character code from a
32-symbol alphabet falls in about two minutes (§6 table), and every code in the dump falls in the
same pass. Online, one guess matches *any* live code, so the attacker's odds grow with the number of
codes outstanding: with 10,000 live 8-character codes (2^40 keyspace), each guess hits with
probability ~9 × 10^-9, and an unthrottled 1,000 guesses/sec finds one in about 30 hours.

**"argon2id or deterministic hash" are not interchangeable choices.** argon2id with a per-row salt
can't be looked up by the code's value (§6). A deterministic SHA-256 can, but it's reversible from a
dump. Pick one of these:

1. **Don't make users type it.** Invite *links* carry a 256-bit token. Store `SHA-256(token)` (§6).
2. **Lookup by value:** HMAC-SHA256 with a pepper kept outside the database. OWASP: a pepper
   "prevents an attacker from being able to crack any of the hashes if they only have access to the
   database, for example, if they have exploited a SQL injection vulnerability or obtained a backup
   of the database", and it "should be stored separately from the password database", in "secrets
   vaults" or HSMs. Their post-hashing variant uses an HMAC where "the pepper is acting as the HMAC
   key". The protection only holds while the pepper stays secret: if the pepper leaks along with the
   DB, the §6 numbers apply again.
3. **Id + secret split:** show the code as `<public id>-<secret>`, look up by id, and store the
   secret as argon2id (§1). This is the scheme NIST requires for look-up secrets below 112 bits (a
   salted password hashing scheme, salt "at least 32 bits"), and the only one that holds up when
   the pepper leaks with the DB.

```ts
// lib/joinCodes.ts — option 2: keyed hash, so a DB dump alone can't reverse the codes
import { createHmac, randomInt } from "node:crypto";
const PEPPER = Buffer.from(process.env.JOIN_CODE_PEPPER_B64!, "base64");  // 32 bytes; secret manager, never the DB
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   // Crockford base32: 32 symbols, no I/L/O/U
export const newJoinCode = () => Array.from({ length: 10 }, () => ALPHABET[randomInt(32)]).join(""); // 50 bits
export const codeDigest = (code: string) =>             // store and index this, never the code itself
  createHmac("sha256", PEPPER).update(`join-code:v1:${code.trim().toUpperCase()}`).digest();
// Redeem: rate-limit per IP + per account + globally FIRST, then consume atomically:
//   UPDATE join_codes SET uses = uses + 1 WHERE digest = $1 AND revoked_at IS NULL
//     AND expires_at > now() AND uses < max_uses RETURNING community_id
```

Attempt limits are mandatory however the code is stored. NIST SP 800-63B-4 §3.2.2: "the verifier
SHALL limit consecutive failed authentication attempts using a specific authenticator on a single
subscriber account to no more than 100". For out-of-band secrets: "If the authentication secret is
less than 64 bits long, the verifier SHALL implement a rate-limiting mechanism". A join code isn't
tied to an account, so throttle on the guesser (IP, user, device) *and* add a global failed-redeem
budget with alerting. Counters belong in server-side storage (`secaudit:rate-limiting`). Also expire
codes, cap uses (single-use where possible), let owners revoke, and return the same error for "wrong
code" and "expired code".

## 9. Encrypting Stored Secrets You Must Use Later (Webhook URLs, Third-Party Keys)

**What to look for:** plaintext `discord_webhook_url` / `slack_webhook_url` / `smtp_password` /
third-party API key columns; AES-GCM with no `setAAD`; no key id (so the key can never rotate); the
key stored in the DB or shipped with its backups; plaintext or ciphertext returned on a settings `GET`.

**Why it's exploitable:** a Discord channel webhook needs no bot user or authentication to post
(Discord: webhooks "do not require a bot user or authentication to use"), and Slack says "Your
webhook URL contains a secret". So a leaked URL lets anyone post as your app into a customer's
channel, which makes it a ready-made phishing channel (treating the URL as a credential is covered
in `secaudit:webhook-security` §1). You have to call the URL, so hashing can't work. Without AAD, an
attacker with write access to one tenant's row can copy another tenant's ciphertext into it and the
decrypt still succeeds.

**The rule:**
- **AES-256-GCM** with a **fresh 96-bit random IV per encryption** (`randomBytes(12)`). Never
  reuse an IV under the same key. NIST SP 800-38D §8 allows the chance of a repeated IV to be "no
  greater than 2^-32", and with random IVs §8.3 applies: "The total number of invocations of the
  authenticated encryption function shall not exceed 2^32, including all IV lengths and all instances
  of the authenticated encryption function with the given key." Count writes per key and rotate
  well before that.
- **AAD = purpose + tenant id + row id**, encoded unambiguously (prefer a JSON array; a
  delimiter form like `a:b` — as in `secaudit:oauth-oidc-security` §5 — is safe only if no field can
  contain the delimiter). The ciphertext then only decrypts for that row, that tenant, that use. Generate the
  row id before encrypting.
- **Key id prefix** on every stored value. New writes use the current key, older ids stay available
  for decrypts, and a re-encryption job moves rows over. OWASP prefers this ("Decrypting it and
  re-encrypting it with the new key"), and notes that old keys "should generally be stored for a
  certain period after they have been retired, in case old backups ... need to be decrypted".
- **Keys outside the DB and outside DB backups.** OWASP: "encryption keys should be stored in a
  separate location from encrypted data", so a SQL injection or a stolen backup yields only
  ciphertext. Prefer a KMS or secret manager. OWASP also says to "Avoid storing keys in environment
  variables" (exposed via `/proc/self/environ` and debug pages), so an injected env var is the floor.
- **Decrypt only at the point of use**, meaning the worker that sends the Discord message. The
  settings API returns `{ configured: true, channelName }`, never the plaintext or the ciphertext.
- **On Node 22, pass `authTagLength: 16` to `createDecipheriv`.** Node deprecated accepting GCM tags
  shorter than 128 bits without that option in v22.0.0 / v20.13.0, and only rejects them from
  v26.0.0. Without it, Node 22 still accepts a 4-byte tag (DEP0182 warning only), cutting
  forgery resistance to a 32-bit tag.

```ts
// lib/sealed.ts — key id + IV + tag + ciphertext in one string; AAD binds it to purpose/tenant/row
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
// SEAL_KEYS = {"k1":"<b64 32 bytes>","k2":"<b64 32 bytes>"} — injected from KMS/secret manager
const RING = new Map(Object.entries(JSON.parse(process.env.SEAL_KEYS!) as Record<string, string>)
  .map(([kid, b64]) => [kid, Buffer.from(b64, "base64")]));
const CURRENT = process.env.SEAL_KEY_CURRENT!;                   // e.g. "k2"
const aad = (purpose: string, tenantId: string, rowId: string) =>
  Buffer.from(JSON.stringify([purpose, tenantId, rowId]));

export function seal(plain: string, purpose: string, tenantId: string, rowId: string) {
  const iv = randomBytes(12);                                     // fresh per encryption
  const c = createCipheriv("aes-256-gcm", RING.get(CURRENT)!, iv);
  c.setAAD(aad(purpose, tenantId, rowId));
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return `${CURRENT}.${Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64url")}`;
}
export function open(sealed: string, purpose: string, tenantId: string, rowId: string) {
  const [kid, b64] = sealed.split(".");
  const key = RING.get(kid);
  if (!key) throw new Error(`unknown key id ${kid}`);
  const buf = Buffer.from(b64, "base64url");
  const d = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12), { authTagLength: 16 });
  d.setAAD(aad(purpose, tenantId, rowId));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8"); // throws if moved/tampered
}
// worker: const url = open(row.webhookSealed, "discord-webhook", row.tenantId, row.id); await post(url, msg);
```

Node: if the ciphertext "has been tampered with, `decipher.final()` will throw". Treat that as an
alert, not a retry. For the full provider-token vault (HKDF `info` purpose separation from one master
key, access vs refresh token AAD, plaintext columns in auth adapters), see
`secaudit:oauth-oidc-security` §5. This section is the general rule, so it doesn't repeat that.

## 10. Review Heuristics

```bash
# Fast hash over something short or typed (join/invite codes, PINs) — check the generator's entropy
grep -rnE "createHash\(['\"](sha256|sha1|md5)['\"]\)\.update\([^)]*([Cc]ode|[Pp]in|[Ii]nvite)" --include='*.ts' --include='*.js' .
# Slow hash used where a lookup is needed (argon2/bcrypt over keys, codes, tokens)
grep -rnE "(argon2\.hash|bcrypt\.hash)\([^)]*([Kk]ey|[Tt]oken|[Cc]ode)" --include='*.ts' --include='*.js' .
# Plaintext secret columns
grep -rnE "(api_?[Kk]ey|webhook_?[Uu]rl|join_?[Cc]ode|invite_?[Cc]ode|secret)[[:space:]]+(String|Text|text|varchar)" \
  --include='*.prisma' --include='*.sql' --include='*.ts' .
# Non-constant-time comparison of a digest or key
grep -rnE "(Hash|hash|digest|[Kk]ey)[A-Za-z]*[[:space:]]*(===|!==|==)[[:space:]]" --include='*.ts' --include='*.js' .
# GCM without AAD, and decipher without authTagLength
grep -rlE "aes-256-gcm" --include='*.ts' --include='*.js' . | xargs grep -LE "setAAD" 2>/dev/null
grep -rnE "createDecipheriv\(['\"]aes-[0-9]+-gcm['\"][^)]*\)" --include='*.ts' --include='*.js' . | grep -v authTagLength
# Unprefixed API keys (bare UUID / hex) — check whether they're scanner-detectable
grep -rnE "(apiKey|api_key)[^=]*=[[:space:]]*(crypto\.)?(randomUUID\(\)|randomBytes\([0-9]+\)\.toString\(['\"]hex)" --include='*.ts' --include='*.js' .
```

## Sources

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html -- Argon2id/scrypt/bcrypt parameters
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html -- algorithms, modes, secure random, key management
- https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/ -- OWASP A04:2025 overview
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html -- key/secret storage and rotation
- https://nodejs.org/api/crypto.html -- Node crypto (randomBytes, createCipheriv, randomUUID)
- https://pages.nist.gov/800-63-4/sp800-63b.html -- NIST SP 800-63B-4 (final, July 2025): look-up secret storage, rate limiting, session secrets
- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf -- NIST SP 800-38D: GCM IV uniqueness and the 2^32 invocation limit
- https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/ -- prefixed tokens, `_` separator, CRC32 checksum
- https://docs.github.com/en/code-security/tutorials/secret-scanning-partner-program -- scannable secret format, verify endpoint, revoke on report
- https://nodejs.org/api/zlib.html -- zlib.crc32 (v22.2.0 / v20.15.0)
- https://docs.discord.com/developers/resources/webhook -- channel webhooks need no authentication
- https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/ -- "Your webhook URL contains a secret"
