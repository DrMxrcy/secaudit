---
name: cryptography
description: Audits cryptographic failures (OWASP A02) - password storage with fast hashes or no salt, insecure randomness for tokens/session IDs, weak or legacy algorithms and modes (DES, RC4, MD5, ECB), reused or hardcoded IVs and keys, and JWT algorithm confusion. Use when handling passwords, generating tokens or reset links or session IDs, encrypting data, or storing keys. Recommends current OWASP parameters.
license: MIT
---

# Cryptography (OWASP A02: Cryptographic Failures)

## When to Use

- Hashing or verifying passwords.
- Generating tokens, password-reset links, session IDs, API keys, or OTPs.
- Encrypting data at rest or choosing a cipher/mode.
- Storing or rotating encryption keys.
- Configuring JWT verification (cross-links `vibe-security:auth`).

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

Full token-lifecycle guidance lives in `vibe-security:auth`.

## 5. Encryption at Rest + Key Management

Store keys outside the codebase (env injected at runtime, or KMS/Vault); never commit them or bake them
into images. Use distinct keys per environment, tag ciphertext with a key ID, and have a rotation
procedure before you need it (rotate on suspected compromise or cryptoperiod expiry). Prefer envelope
encryption (separate data-encryption and key-encryption keys). See `vibe-security:secrets`.

## Sources

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html -- Argon2id/scrypt/bcrypt parameters
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html -- algorithms, modes, secure random, key management
- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/ -- OWASP A02 overview
- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html -- key/secret storage and rotation
- https://nodejs.org/api/crypto.html -- Node crypto (randomBytes, createCipheriv, randomUUID)
