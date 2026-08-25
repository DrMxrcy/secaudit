---
name: object-storage-security
description: Audits object storage — Cloudflare R2, AWS S3, and S3-compatible stores — where user uploads actually live. Covers presigned URLs as bearer credentials (over-long expiry, unscoped PUTs, URLs leaking into logs), server-minted object keys vs client-supplied ones, public buckets and r2.dev dev URLs, content-type and size enforced only in the browser, bucket CORS set to `*`, unscoped long-lived storage credentials, object-level authorization on read, and lifecycle/deletion/versioning gaps. Use whenever the project uploads, stores, or serves user files from a bucket, generates a presigned URL, or configures bucket access. For Supabase Storage policies see secaudit:database; for Convex file storage see secaudit:convex-security.
license: MIT
---

# Object Storage Security (R2, S3, and S3-Compatible)

A bucket is a second database with a completely separate access-control model, and almost nothing
your application framework does applies to it. Session middleware does not run in front of it. Your
ORM's ownership filters do not apply. The one control most apps lean on — the presigned URL — is
a bearer credential in a string, and AWS says so in plain words: "presigned URLs are bearer
tokens that grant access to those who possess them."

The recurring AI-codegen failure mode is generating a working upload flow and treating storage as a
dumb filesystem: the client picks the key, the presign lasts a week, the bucket is public "so the
image renders", and the download route serves whatever key it is handed. Findings here map to
OWASP **A01:2025** (Broken Access Control) and **A02:2025** (Security Misconfiguration).

`secaudit:web-vulns` covers upload validation, path traversal, and IDOR as general web problems.
This skill covers the storage layer specifically: the presign, the key namespace, the bucket
config, and the credential. For Supabase Storage bucket policies see `secaudit:database`; for
Convex file storage — whose URLs are unauthenticated by design — see `secaudit:convex-security`.

## When to Use

- The project uploads, stores, or serves user files from R2, S3, MinIO, B2, Spaces, or similar.
- Any code calls `getSignedUrl`, `createPresignedPost`, `generate_presigned_url`, or `s3 presign`.
- Reviewing bucket configuration: public access, CORS, lifecycle rules, IAM policy, API tokens.
- A route serves a file by key/id, or hands the browser a URL that fetches object bytes.

Review grep heuristics: `expiresIn`, `PutObjectCommand`, `r2.dev`, `PublicRead`, `AllowedOrigins`,
`AWS_SECRET_ACCESS_KEY`, and any `Key:` built from `req.body` / `searchParams`.

## 1. Presigned URLs Are Bearer Credentials With a Timer

**What to look for:** `expiresIn` measured in days or weeks (the copy-paste default
`60 * 60 * 24 * 7` from vendor docs is the SigV4 maximum, seven days); a presigned PUT with no
`ContentType` bound; presigned URLs written to application logs, returned in analytics events, put
in an `<img src>` on a page that links off-site (referrer leak), or pasted into a shared chat or a
support ticket.

**Why it's exploitable:** the URL *is* the authorization. Anyone who obtains the string gets exactly
what it grants, from any IP, with no session, until it expires — and it can be replayed as many
times as they like within that window. A seven-day presigned PUT scoped only to a key is a
week-long anonymous write primitive: whoever has it can upload arbitrary bytes of arbitrary type to
your bucket, repeatedly, and overwrite what is already at that key. A seven-day GET outlives every
revocation you perform in your own app — you can delete the user, cancel the share, flip the
permission bit, and the URL keeps working.

**Fix:** presign for the shortest window the operation actually needs (seconds to a couple of
minutes for a browser upload, minutes for a download), bind the method and the exact key, bind
`ContentType` so the upload cannot be something else, and treat the URL like a password — never
log it, never include it in telemetry, never render it into a page that leaks referrers.

```ts
// lib/upload.ts — BAD: week-long anonymous write to a client-chosen key, and then logged
const url = await getSignedUrl(
  s3,
  new PutObjectCommand({ Bucket: "user-uploads", Key: body.filename }),
  { expiresIn: 60 * 60 * 24 * 7 },            // 7d — the maximum the provider allows
);
logger.info("presigned upload url", { url }); // the credential is now in your log pipeline
return Response.json({ url });
```

```ts
// lib/upload.ts — GOOD: 60s, one method, one server-minted key, content-type bound
import { randomUUID } from "node:crypto";
import { PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const EXT = new Map([["image/png", "png"], ["image/jpeg", "jpg"], ["image/webp", "webp"]]);

export async function presignAvatarUpload(userId: string, contentType: string) {
  const ext = EXT.get(contentType);
  if (!ext) throw new Error("Unsupported type");
  const key = `avatars/${userId}/${randomUUID()}.${ext}`;      // §2: server mints the key
  const url = await getSignedUrl(
    s3,
    new PutObjectCommand({ Bucket: "user-uploads", Key: key, ContentType: contentType }),
    { expiresIn: 60 },                                          // one minute is plenty
  );
  return { url, key };            // log the key if you must log something; never the url
}
```

On S3 you can enforce the ceiling at the bucket, so a mistake in one code path cannot mint a
long-lived URL — `s3:signatureAge` is evaluated at request time, in milliseconds:

```json
{
  "Sid": "DenyStalePresignedRequests",
  "Effect": "Deny",
  "Principal": { "AWS": "*" },
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::user-uploads/*",
  "Condition": { "NumericGreaterThan": { "s3:signatureAge": "300000" } }
}
```

Two provider details worth knowing. A presign made with temporary credentials (an assumed role, an
EC2/ECS instance profile) dies when those credentials expire regardless of `expiresIn` — so a
"7 day" URL from a Lambda may really last an hour, which is luck, not a control. And R2 caps
presigned URL validity at seven days (604,800 seconds) the same way S3 does.

**Detection:**

```bash
# Long presign windows: anything with a day/week arithmetic pattern or a big literal
grep -rnE 'expiresIn[[:space:]]*:[[:space:]]*([0-9_]{5,}|[0-9*[:space:]]*24[[:space:]]*\*)' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rnE 'ExpiresIn[[:space:]]*=[[:space:]]*[0-9_]{5,}|--expires-in[[:space:]]+[0-9]{5,}' .

# Presigned URLs reaching a log/telemetry sink
grep -rnE '(console\.(log|info)|logger\.[a-z]+|captureMessage|track)\(.*\b(signedUrl|presigned|uploadUrl|getSignedUrl)' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
```

## 2. The Server Must Mint the Object Key, Never the Client

**What to look for:** the object key built from request data — `Key: body.filename`,
`Key: \`uploads/${searchParams.get("name")}\``, `Key: file.name` — and any presign endpoint that
accepts a `key` or `path` argument and signs it as given.

**Why it's exploitable:** two separate bugs wearing one costume.

- **Cross-prefix write.** If your app keys objects `avatars/<userId>/…`, a client that supplies
  the key simply sends `avatars/<other-id>/photo.png`. No traversal characters are needed at all
  — the prefix is not a security boundary, it is a naming convention, and the presign signs
  whatever string it was handed.
- **Overwrite.** A presigned PUT to an existing key does not conflict; S3 "replaces the existing
  object with the uploaded object." So guessing or reading one key is enough to silently replace
  another user's file — swap someone's invoice PDF, or replace an avatar with a payload.

`../` sequences on top of that matter wherever the key stops being an opaque S3 string and becomes
a path: when a worker downloads the object and joins the key into a local filesystem path, when a
proxy or CDN in front of the bucket normalizes the URL, or when the key is echoed into a
`Content-Disposition` filename. See `secaudit:web-vulns` §3 for the traversal mechanics.

**Fix:** the client sends *metadata* (content type, declared size, a display name to store in your
database) and never the storage key. The server derives the key from the **session** user id plus a
random component, returns it alongside the presigned URL, and records it in the database. Preserve
the user's original filename as a DB column for display, not as part of the key.

```ts
// api/uploads/presign/route.ts — BAD: the client names the object
const { filename } = await req.json();
const key = `avatars/${filename}`;   // "../invoices/2026-03.pdf", "<victim-id>/avatar.png"
```

```ts
// api/uploads/presign/route.ts — GOOD: identity from the session, key from the server
const session = await auth();
if (!session) return new Response("Unauthorized", { status: 401 });
const { contentType, displayName } = await req.json();
const key = `avatars/${session.user.id}/${randomUUID()}.${EXT.get(contentType) ?? "bin"}`;
await db.upload.create({ data: { key, ownerId: session.user.id, displayName } });
```

**Detection:**

```bash
# Object keys interpolated from request data
grep -rnE 'Key[[:space:]]*:[[:space:]]*.*(req\.|request\.|body\.|params\.|searchParams|file\.name|originalname)' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
# Presign endpoints that accept a key/path from the caller
grep -rnE '(key|path|objectKey|filename)[[:space:]]*[,}]' -l --include='*.ts' . \
  | xargs grep -lE 'getSignedUrl|createPresignedPost' 2>/dev/null
```

## 3. The Bucket Is Public

**What to look for:** an R2 bucket with the `r2.dev` development URL enabled and object URLs of the
form `https://<bucket>.<hash>.r2.dev/...` in application code; an S3 bucket policy with
`"Principal": "*"` and `s3:GetObject`; `ACL: "public-read"` on a `PutObjectCommand`; S3 Block Public
Access disabled at the account or bucket level; a static-site bucket that also receives user
uploads.

**Why it's exploitable:** "public" means world-readable *and* guessable. Sequential or
weakly-derived keys (`avatars/1.png`, `receipts/<email>.pdf`) turn a public bucket into an
enumeration target, and even with random keys, a public bucket removes every future opportunity to
revoke: the moment a URL leaks it is permanent. Cloudflare is explicit that `r2.dev` access "is
rate-limited and should only be used for development purposes" — shipping it means a public,
unsupported, throttled path to every object in the bucket.

Public is legitimate when the objects are *genuinely* public assets — marketing images, a CSS
bundle, published avatars you would happily print on a billboard — and you want CDN caching
without signing. It is not legitimate for anything a user uploaded expecting privacy, and the two
must not share a bucket, because bucket-level public access has no per-object exceptions.

**Fix:** two buckets. A public CDN bucket for public assets, fronted by a custom domain (not
`r2.dev`) so you keep WAF rules, cache control, and the ability to move it. A private bucket for
user content, served either by a short-lived signed GET (§1) or through an authenticated proxy
route in your app that checks ownership first (§7). On AWS, turn on all four Block Public Access
settings at the **account** level so no future bucket policy or ACL can undo it:

```ts
// infra/s3.ts — GOOD: account-level block, so a bad bucket policy later cannot open a hole
await s3control.send(new PutPublicAccessBlockCommand({
  AccountId: process.env.AWS_ACCOUNT_ID,
  PublicAccessBlockConfiguration: {
    BlockPublicAcls: true,        // reject PutObject/PutBucketAcl carrying a public ACL
    IgnorePublicAcls: true,       // ignore public ACLs that already exist
    BlockPublicPolicy: true,      // reject a bucket policy that would be public
    RestrictPublicBuckets: true,  // and neuter any public policy already attached
  },
}));
```

```bash
# R2 — turn the development URL off; use a custom domain for genuinely public assets
wrangler r2 bucket dev-url disable user-uploads
wrangler r2 bucket dev-url status  user-uploads
```

Note the ordering trap in the AWS docs: Block Public Access "doesn't alter existing policies or
ACLs", so turning it off later re-exposes whatever was public before. Removing the public policy
and turning on BPA are two separate jobs; do both.

**Detection:**

```bash
# Public R2 dev URLs and public-read ACLs in application code and IaC
grep -rn 'r2\.dev' --include='*.ts' --include='*.tsx' --include='*.env*' --include='*.tf' .
grep -rniE 'public-read|PublicRead|acl[[:space:]]*[:=][[:space:]]*.public' \
  --include='*.ts' --include='*.js' --include='*.tf' --include='*.yml' .
# IaC that switches Block Public Access off
grep -rniE 'block_public_(acls|policy)[[:space:]]*=[[:space:]]*false|restrict_public_buckets[[:space:]]*=[[:space:]]*false' .
# Live truth (read-only)
aws s3api get-public-access-block --bucket user-uploads
aws s3api get-bucket-policy-status --bucket user-uploads
```

## 4. Content-Type and Size Enforced Only in the Browser

**What to look for:** `<input accept="image/*">` and a `file.size > MAX` check in a React component
as the *only* limits; a presign endpoint that passes the client's declared `contentType` straight
through with no allowlist; validation of `file.type` or the filename extension; nothing that ever
looks at the actual bytes.

**Why it's exploitable:** `accept=` is a file-picker filter, `file.size` is a number in a page you
do not control, and `Content-Type` is a string the uploader types. With a presigned PUT in hand, an
attacker never opens your page at all — they `curl -X PUT` whatever they want. Consequences:
unbounded uploads (a storage bill and a denial-of-wallet, see `secaudit:rate-limiting`), and
**stored XSS from your own origin**. An uploaded `.html` or `.svg` served inline from a domain that
shares cookies or `localStorage` with your app executes as your app: SVG carries `<script>` and
event handlers, and a "JPEG" that is actually HTML will be sniffed and rendered by browsers if you
let it.

**Fix:** four layers, and you need all four.

1. **Cap the size in the signature itself.** On S3 use a presigned POST — `content-length-range`
   is a policy condition S3 enforces server-side, so an over-size upload is rejected by the service,
   not by your code.
2. **Cap and verify server-side after the fact.** R2 does not support presigned POST (its presigned
   URLs are GET/HEAD/PUT/DELETE only), so there the signature binds `ContentType` but not size —
   `HeadObject` the key after upload, and delete anything over the cap before you make it visible.
3. **Sniff the magic bytes.** Read the leading bytes and match them against the allowlist; reject
   anything whose real type disagrees with the declared one. Re-encode images where you can — it
   strips polyglots and EXIF along with the payload (`secaudit:web-vulns` §3).
4. **Serve it defensively.** Never echo the user's `Content-Type` back on download. Send a type you
   determined, plus `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, and
   host user content on a separate domain from the app so that even a successful script upload
   lands in a different origin with no session to steal.

```tsx
// components/Upload.tsx — BAD: the entire enforcement, and it lives in the attacker's browser
<input type="file" accept="image/png,image/jpeg"
       onChange={e => { const f = e.target.files![0];
                        if (f.size > 5_000_000) return alert("Too big");
                        upload(f); }} />
```

```ts
// api/uploads/presign/route.ts — GOOD (S3): the service enforces size and type, not your UI
import { createPresignedPost } from "@aws-sdk/s3-presigned-post";

const { url, fields } = await createPresignedPost(s3, {
  Bucket: "user-uploads",
  Key: key,                                        // server-minted, per §2
  Expires: 60,
  Fields: { "Content-Type": contentType },         // conditions need matching Fields
  Conditions: [
    ["content-length-range", 1, 5_242_880],        // 1 byte .. 5 MiB, enforced by S3
    ["eq", "$Content-Type", contentType],          // and it must be the type we allowlisted
  ],
});
```

```ts
// lib/verifyUpload.ts — GOOD (works everywhere, required on R2): verify bytes, then publish
import { fileTypeFromBuffer } from "file-type";
const ALLOWED = new Set(["image/png", "image/jpeg", "image/webp"]);
const MAX_BYTES = 5_242_880;

export async function verifyUpload(key: string) {
  const head = await s3.send(new HeadObjectCommand({ Bucket: "user-uploads", Key: key }));
  const head_ok = (head.ContentLength ?? Infinity) <= MAX_BYTES;
  const body = await s3.send(new GetObjectCommand({ Bucket: "user-uploads", Key: key, Range: "bytes=0-4095" }));
  const sniffed = await fileTypeFromBuffer(await body.Body!.transformToByteArray());
  if (!head_ok || !sniffed || !ALLOWED.has(sniffed.mime)) {
    await s3.send(new DeleteObjectCommand({ Bucket: "user-uploads", Key: key }));
    throw new Error("Rejected upload");            // never became visible to anyone
  }
  await db.upload.update({ where: { key }, data: { status: "ready", mime: sniffed.mime } });
}
```

**Detection:**

```bash
# Client-side-only gates
grep -rnE '\baccept=|\.size[[:space:]]*[<>]=?[[:space:]]*[0-9_]+' --include='*.tsx' --include='*.jsx' .
# Client-declared type flowing into the presign or the download response
grep -rnE 'ContentType[[:space:]]*:[[:space:]]*(body|req|request|file)\.' --include='*.ts' .
grep -rnE 'Content-Type.*(object\.|head\.|metadata\.)ContentType' --include='*.ts' .
# Is anything sniffing bytes at all? No hits on an app that accepts uploads is the finding.
grep -rniE 'file-type|fileTypeFrom|magic *bytes|sharp\(|image-size' --include='*.ts' --include='*.js' .
# Download routes that never set a disposition
grep -rnL 'Content-Disposition' $(grep -rlE 'GetObjectCommand|createReadStream' --include='*.ts' . 2>/dev/null)
```

## 5. Bucket CORS Set to `*`

**What to look for:** an R2 or S3 CORS rule with `AllowedOrigins: ["*"]`, especially combined with
`AllowedMethods` containing `PUT`, `POST`, or `DELETE`, or with `AllowedHeaders: ["*"]` and a wide
`ExposeHeaders`.

**Why it's exploitable:** bucket CORS decides which *web origins* may read the bucket's responses
from a browser. With `*` plus write methods, any page on the internet can script an upload to your
bucket using a presigned URL it obtained — from a leaked log, a shared link, or a URL your own
frontend handed to a page that later navigates away. Combined with §4 it becomes a hosted-content
problem: attacker's site, your bucket, your domain's reputation. With `*` on GET plus
`ExposeHeaders`, a malicious page can read object bodies and metadata that the browser would
otherwise keep to your origin.

CORS is not authentication — a `*` rule does not make a private object public — but it removes
the browser's protection against *your* credentials and *your* presigned URLs being used from
someone else's page. Bucket CORS is also separate from the response headers your app sets — see
`secaudit:deployment` for application CORS.

**Fix:** list exactly your origins, exactly the methods the browser performs directly against the
bucket (usually `PUT` for uploads and `GET` for reads), and only the headers you need.

```json
// BAD — any origin, any method, any header
[{ "AllowedOrigins": ["*"], "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
   "AllowedHeaders": ["*"], "ExposeHeaders": ["*"] }]
```

```json
// GOOD — one origin per environment, the two methods the browser actually issues
[
  {
    "AllowedOrigins": ["https://app.example.com"],
    "AllowedMethods": ["GET", "PUT"],
    "AllowedHeaders": ["content-type"],
    "ExposeHeaders": ["etag"],
    "MaxAgeSeconds": 3600
  },
  {
    "AllowedOrigins": ["http://localhost:3000"],
    "AllowedMethods": ["GET", "PUT"],
    "AllowedHeaders": ["content-type"]
  }
]
```

**Detection:**

```bash
# Wildcard origins in a CORS document (JSON or IaC)
grep -rnE '"?AllowedOrigins"?[^]]*\[[^]]*"\*"' --include='*.json' --include='*.ts' --include='*.tf' .
grep -rniE 'allowed_origins[[:space:]]*=[[:space:]]*\[[^]]*"\*"' --include='*.tf' .
# Live truth (read-only)
aws s3api get-bucket-cors --bucket user-uploads
wrangler r2 bucket cors list user-uploads
```

## 6. Long-Lived, Over-Scoped Storage Credentials

**What to look for:** an AWS root or account-wide access key pair in a serverless function's
environment; an IAM policy granting `s3:*` on `arn:aws:s3:::*`; an R2 token created with admin
permissions across every bucket; the same key used by CI, the app, and a developer laptop; and —
the fatal one — any `accessKeyId`/`secretAccessKey` reaching the client bundle.

**Why it's exploitable:** a storage credential is not scoped by anything your app does. Whoever has
it can list every bucket in the account, read every object, and delete or ransom the lot, from
anywhere, with no session. Unlike a presigned URL it does not expire — R2 account tokens "remain
valid until manually revoked." And a key in a client bundle is not a leak risk, it is a leak: the
bundle is served to every visitor. `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` prefixes on a storage
secret are the common shape (`secaudit:secrets` covers the prefix rules and the redaction rule for
reporting a found key).

**Fix:** the client gets a presigned URL, never a key — that is why presigning exists at all.
Server-side, mint one credential per workload, scoped to one bucket and the minimum verbs, and give
CI a different one from production. On R2, the `Object Read & Write` and `Object Read` permissions
can be scoped to a specific set of buckets — use that rather than an account-wide admin token. On
AWS, prefer an assumed role over a static key pair so the credential is short-lived by construction.

```ts
// BAD — the key is in the browser; every visitor now has full bucket access
const s3 = new S3Client({
  region: "auto",
  endpoint: process.env.NEXT_PUBLIC_R2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.NEXT_PUBLIC_R2_ACCESS_KEY_ID!,
    secretAccessKey: process.env.NEXT_PUBLIC_R2_SECRET_ACCESS_KEY!,
  },
});
```

```json
// GOOD — least-privilege IAM policy for the upload service: one prefix, three verbs, no listing
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
    "Resource": "arn:aws:s3:::user-uploads/avatars/*"
  }]
}
```

**Detection:**

```bash
# Storage credentials behind a client-exposed env prefix — treat any hit as compromised
grep -rnE '(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP)_[A-Z0-9_]*(ACCESS_KEY|SECRET|R2|S3|BUCKET)' .
# An S3 client constructed in client-side code at all
grep -rln 'new S3Client\|new AWS.S3(' --include='*.tsx' --include='*.jsx' .
# Wildcard IAM
grep -rnE '"s3:\*"|"Resource"[[:space:]]*:[[:space:]]*"\*"' --include='*.json' --include='*.tf' .
```

## 7. Object-Level Authorization on Read — Unguessable Is Not a Control

**What to look for:** a download or preview route that takes a key/id and signs or streams it with
no database lookup; a route that checks only "is the user logged in" before signing; comments to
the effect that the UUID makes it safe; and list endpoints that return every key in a prefix.

**Why it's exploitable:** this is IDOR in storage form (`secaudit:web-vulns` §4). If knowing the
key is enough to fetch the object, then every place a key travels is an access-control bypass —
and keys travel constantly: into browser history, `Referer` headers, proxy and CDN logs, error
trackers, analytics payloads, screenshots, and any list endpoint that forgot its own ownership
filter. A random key raises the cost of *guessing* and does nothing about *leaking*. Unguessability
is a delay, not a boundary.

**Fix:** the route resolves an application-level id to a row, checks that the session user may
access that row, and only then signs a short-lived URL (or streams the bytes through the app). The
storage key is an internal detail the client never sees or supplies. Return 404 rather than 403 so
the route does not confirm which ids exist.

```ts
// api/files/[id]/route.ts — BAD: signs whatever key it is handed
const key = new URL(req.url).searchParams.get("key")!;
return Response.json({ url: await getSignedUrl(s3, new GetObjectCommand({ Bucket, Key: key })) });
```

```ts
// api/files/[id]/route.ts — GOOD: ownership checked in the DB, then a 60s scoped GET
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });

  const file = await db.upload.findFirst({
    where: { id: params.id, ownerId: session.user.id, status: "ready" },
  });
  if (!file) return new Response("Not found", { status: 404 });   // no existence oracle

  const url = await getSignedUrl(
    s3,
    new GetObjectCommand({
      Bucket: "user-uploads",
      Key: file.key,                                   // from the DB row, never the request
      ResponseContentType: file.mime,                  // the type we verified, not the user's
      ResponseContentDisposition: `attachment; filename="${encodeURIComponent(file.displayName)}"`,
    }),
    { expiresIn: 60 },
  );
  return Response.json({ url });
}
```

**Detection:**

```bash
# Signing or streaming a key taken straight from the request
grep -rnE '(GetObjectCommand|getSignedUrl|get_object)\(.*\b(searchParams|params\.|body\.|query\.)' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
# Storage routes with no ownership predicate anywhere in the file
grep -rlE 'GetObjectCommand|getSignedUrl' --include='*.ts' . \
  | xargs grep -LE 'ownerId|userId|session\.user|tenantId' 2>/dev/null
```

## 8. Lifecycle, Deletion, and Versioning

**What to look for:** a "delete" that only removes the database row and leaves the object; deletion
on a versioning-enabled S3 bucket with no handling of prior versions; no lifecycle rules on
`tmp/`, `uploads/`, or scratch prefixes; abandoned multipart uploads accumulating invisibly; and
replicas, backups, or a staging clone of the bucket configured more loosely than the source.

**Why it's exploitable:** four distinct ways "deleted" turns out to be false.

- **Versioning.** On a versioning-enabled bucket, a plain `DeleteObject` writes a *delete marker*
  and keeps the previous version, retrievable by anyone with `s3:GetObjectVersion` and the version
  id. Your GDPR deletion, your "unshare", and your incident cleanup all did nothing to the bytes.
- **Un-expired presigns.** Revoking access in your app has no effect on a presigned GET already in
  the wild (§1) — another reason the window should be a minute, not a week. If a URL must die
  immediately, you have to remove the object or rotate the signing credential; there is no "revoke
  this URL" button.
- **Orphans.** Objects whose DB row is gone are unreachable by your app and therefore unaudited,
  but still fully present, still billed, and still readable by anything holding the key. Incomplete
  multipart uploads are the same problem with no object to show for it.
- **Copies.** A replication target, a nightly sync bucket, or a "prod data in staging" clone
  inherits the *data* but not the source bucket's Block Public Access, policy, or CORS. The strict
  bucket is only as private as its loosest copy.

**Fix:** delete the object in the same transaction-ish path as the row, and on a versioned bucket
delete the versions (or use lifecycle expiration for noncurrent versions) when the intent is
erasure. Put lifecycle rules on every temp prefix and on incomplete multipart uploads so garbage
expires without a cron job you will forget to write. Audit every copy of the bucket with the same
checks in §3 and §5.

```ts
// lib/deleteUpload.ts — GOOD: the bytes go too, and on a versioned bucket so do the versions
const file = await db.upload.findFirst({ where: { id, ownerId: session.user.id } });
if (!file) return new Response("Not found", { status: 404 });

const { Versions = [], DeleteMarkers = [] } = await s3.send(
  new ListObjectVersionsCommand({ Bucket: "user-uploads", Prefix: file.key }),
);
const Objects = [...Versions, ...DeleteMarkers]
  .filter(v => v.Key === file.key)
  .map(v => ({ Key: v.Key!, VersionId: v.VersionId }));
if (Objects.length) {
  await s3.send(new DeleteObjectsCommand({ Bucket: "user-uploads", Delete: { Objects } }));
}
await db.upload.delete({ where: { id: file.id } });
```

```json
// Lifecycle: expire scratch objects and reap abandoned multipart uploads (S3 and R2 both)
{
  "Rules": [
    { "ID": "expire-tmp", "Status": "Enabled",
      "Filter": { "Prefix": "tmp/" }, "Expiration": { "Days": 1 } },
    { "ID": "abort-stale-multipart", "Status": "Enabled", "Filter": { "Prefix": "" },
      "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 7 } }
  ]
}
```

**Detection:**

```bash
# DB deletes with no corresponding object delete in the same file
grep -rlE '\.delete\(|\.destroy\(|DELETE FROM' --include='*.ts' . \
  | xargs grep -LE 'DeleteObjectCommand|deleteObject|delete_object' 2>/dev/null
# Live truth (read-only)
aws s3api get-bucket-versioning        --bucket user-uploads
aws s3api get-bucket-lifecycle-configuration --bucket user-uploads
aws s3api list-multipart-uploads       --bucket user-uploads
wrangler r2 bucket lifecycle list user-uploads
```

## Cross-References

- `secaudit:web-vulns` — upload validation, path traversal, and IDOR as general web problems.
- `secaudit:database` — Supabase Storage bucket policies (`storage.objects` RLS) and Firebase
  Cloud Storage rules; this skill deliberately does not repeat them.
- `secaudit:convex-security` — Convex file-storage URLs are unauthenticated by design, which makes
  §7 mandatory rather than optional on that stack.
- `secaudit:secrets` — env-var prefixes, key rotation, and how to report a discovered credential.
- `secaudit:deployment` — application CORS and response security headers (distinct from §5's
  bucket CORS).
- `secaudit:rate-limiting` — upload endpoints as a denial-of-wallet surface.

## Sources

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html -- presigned URLs are bearer tokens; expiry limits; `s3:signatureAge`
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html -- presigned PUT replaces an existing key; content-type must match the signature
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html -- sharing objects with presigned GETs
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html -- the four Block Public Access settings and what "public" means
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-bucket.html -- applying BPA per bucket
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html -- bucket policy structure and evaluation
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html -- S3 CORS configuration
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html -- managing a CORS document
- https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/Package/-aws-sdk-s3-presigned-post/ -- `createPresignedPost` (POST policy conditions)
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html -- checksums on presigned uploads
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html -- versioning; a delete keeps prior versions
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html -- delete markers hide, they do not erase
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeletingObjectVersions.html -- deleting specific versions
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html -- lifecycle rules
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html -- reaping incomplete multipart uploads
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html -- replicas are separate buckets with separate permissions
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html -- S3 security best practices
- https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html -- least privilege; prefer roles over static keys
- https://developers.cloudflare.com/r2/api/s3/presigned-urls/ -- R2 presigned URLs: 1s–7d, GET/HEAD/PUT/DELETE only, no POST
- https://developers.cloudflare.com/r2/buckets/public-buckets/ -- `r2.dev` is rate-limited and development-only; use a custom domain
- https://developers.cloudflare.com/r2/api/tokens/ -- R2 token permissions; scoping a token to specific buckets
- https://developers.cloudflare.com/r2/buckets/cors/ -- R2 bucket CORS policy
- https://developers.cloudflare.com/r2/buckets/object-lifecycles/ -- R2 lifecycle rules and multipart abort
- https://developers.cloudflare.com/r2/api/s3/api/ -- R2's S3 API compatibility surface
- https://developers.cloudflare.com/r2/reference/data-security/ -- R2 encryption and data-handling model
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html -- upload validation, magic bytes, safe serving
- https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html -- why SVG/HTML uploads execute in your origin
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Disposition -- forcing download instead of inline render
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options -- `nosniff`
- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where §2, §7, and §3 land
- https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/ -- A02:2025, where §3, §5, and §6 land
