---
name: web-vulns
description: Audits classic web application vulnerabilities that AI assistants generate by omitting the validation or authorization guard - XSS (stored, reflected, DOM-based), SSRF (user-supplied URLs, webhooks, image/preview fetchers), file upload and path traversal, and IDOR / broken object-level authorization. Use when handling untrusted input that is rendered as HTML, used to build an outbound request, used as a file path or upload, or used to look up an object by ID. Covers OWASP A01/A03/A10.
license: MIT
---

# Web Vulnerabilities (XSS, SSRF, File Upload, IDOR)

All four of these are the same root cause in different clothes: **trusting client-controlled input**
(HTML, a URL, a filename/path, an object ID) without server-side validation against an allowlist or
an authorization check. The recurring AI-codegen failure mode is generating the happy-path data flow
and omitting the guard.

## When to Use

- Rendering user/DB content as HTML, or building URLs/attributes from input (XSS).
- Making a server-side request to a user-supplied URL (SSRF): webhooks, "import from URL", link
  previews, avatar-by-URL, PDF/screenshot/thumbnail generators.
- Accepting file uploads or using request input as a file path (upload / path traversal).
- Looking up, updating, or deleting an object by an ID from the request (IDOR).

Review grep heuristics: raw-HTML render sinks, `innerHTML`, server-side `fetch(`/`axios(` on user
input, `path.join(` with request data, and object lookups `where: { id }` with no user/tenant scope.

## 1. XSS (Cross-Site Scripting)

**What to look for:** React raw-HTML render props, Vue `v-html`, DOM sinks (`innerHTML`,
`document.write`, `insertAdjacentHTML`), `href`/`src` taking a value that can start with
`javascript:`/`data:`, server templates interpolating raw request data, markdown renderers with raw
HTML enabled, and regex/blacklist "sanitization."

**Why it's exploitable:** Untrusted input reaches an HTML/JS execution sink without context-correct
escaping, so the browser parses attacker markup as script. Stored XSS persists and fires for every
viewer; reflected fires from a crafted link; DOM-based never touches the server. Impact: session/cookie
theft, account takeover, full compromise if the victim is an admin.

**Fix:** Prefer plain text (frameworks auto-escape interpolated children). If you must render rich
HTML, sanitize with an allowlist sanitizer (DOMPurify). Block dangerous URL schemes. Add a
Content-Security-Policy as defense-in-depth, not a substitute for escaping.

```tsx
// components/Comment.tsx — BEFORE (stored XSS: raw DB content into an HTML sink)
export const Comment = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: html }} />;

// AFTER — render as text (React escapes it); or sanitize if rich HTML is required
import DOMPurify from "isomorphic-dompurify";
export const Comment = ({ text }: { text: string }) => <div>{text}</div>;
export const RichComment = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html, { USE_PROFILES: { html: true } }) }} />;
```

```ts
// lib/safeUrl.ts — block javascript:/data:/vbscript: in user-supplied hrefs
export function safeUrl(raw: string): string {
  try {
    const u = new URL(raw, location.origin);
    return ["http:", "https:", "mailto:"].includes(u.protocol) ? u.href : "#";
  } catch { return "#"; }
}
```

## 2. SSRF (Server-Side Request Forgery)

**What to look for:** server-side `fetch`/`axios`/`got`/`http.request` where the URL or host comes from
the request; features that fetch a user-supplied URL (webhooks, import-from-URL, link unfurl, image
fetch, PDF/screenshot generators); no allowlist; redirects followed.

**Why it's exploitable:** the server makes an attacker-directed request from inside the trust boundary.
Targets: cloud metadata `http://169.254.169.254/` (steal IAM credentials), private/link-local ranges,
internal-only services, and `file://`/`gopher://` schemes. Result: credential theft, internal port
scanning, reaching unauthenticated internal APIs. Checking the hostname string alone is bypassable via
DNS rebinding and redirects.

**Fix:** allowlist scheme + host, resolve DNS and reject private/link-local IPs, and disable redirects
(or re-validate each hop). Run fetchers in an isolated network segment with no metadata access.

```ts
// lib/fetchUrl.ts — AFTER: HTTPS-only, host allowlist, DNS-resolved IP check, no redirects
import dns from "node:dns/promises";
import net from "node:net";
import ipaddr from "ipaddr.js";
const ALLOWED = new Set(["images.example-cdn.com", "api.partner.com"]);

export async function fetchUrl(userUrl: string): Promise<Response> {
  const u = new URL(userUrl);
  if (u.protocol !== "https:") throw new Error("HTTPS only");
  if (!ALLOWED.has(u.hostname)) throw new Error("Host not allowed");
  const { address } = await dns.lookup(u.hostname);             // defeat DNS rebinding
  if (!net.isIP(address) || ipaddr.parse(address).range() !== "unicast")
    throw new Error("Blocked IP");                              // blocks loopback/link-local/private
  return fetch(u, { redirect: "error", signal: AbortSignal.timeout(5000) });
}
```

## 3. File Upload + Path Traversal

**What to look for:** upload handlers trusting `file.originalname`/`mimetype`/extension; building a
destination from user input (`path.join(uploadDir, userName)`) allowing `../`, absolute paths, or null
bytes; no size limit; files written inside the webroot; images stored without re-encoding (SVG/HTML can
carry script).

**Why it's exploitable:** path traversal lets an attacker write outside the intended directory (drop a
webshell, overwrite config) or read arbitrary files; a malicious upload (`.php`/`.svg`/`.html`) saved
under the webroot and requested directly runs server-side or delivers stored XSS. Client-supplied type
and extension are trivially forged.

**Fix:** validate real content-type + size against an allowlist, generate the filename server-side
(user input never touches the path), store outside the webroot (prefer object storage with private
ACLs + signed URLs), assert the resolved path stays inside the base dir, and re-encode images.

```ts
// api/upload.ts — AFTER (validated type/size, server-generated name, stored outside webroot)
import { randomUUID } from "node:crypto";
import path from "node:path";
const ALLOWED = new Map([["image/png","png"],["image/jpeg","jpg"],["image/webp","webp"]]);
const UPLOAD_DIR = "/var/app/uploads";                 // not under the web root

export async function POST(req: Request) {
  const file = (await req.formData()).get("file") as File;
  const buf = Buffer.from(await file.arrayBuffer());
  if (buf.byteLength > 5_000_000) return new Response("Too large", { status: 413 });
  const ext = ALLOWED.get(file.type);
  if (!ext) return new Response("Unsupported type", { status: 415 });
  const dest = path.join(UPLOAD_DIR, `${randomUUID()}.${ext}`);   // user input never in the path
  if (!path.resolve(dest).startsWith(path.resolve(UPLOAD_DIR) + path.sep))
    return new Response("Invalid path", { status: 400 });
  // re-encode images (strips polyglots/EXIF/embedded scripts) before writing
  return Response.json({ ok: true });
}
```

## 4. IDOR / Broken Object-Level Authorization

**What to look for:** an object fetched directly by a request-supplied ID with no ownership check
(`findUnique({ where: { id: params.id } })`); queries keyed only on the object ID, not scoped to the
current user/tenant; trusting a `userId`/email from the request body instead of the session; relying on
IDs being non-obvious.

**Why it's exploitable:** the server uses client input to select an object but never verifies the
authenticated user may access that specific object. Swapping an ID (`/orders/1001` -> `1002`) returns or
modifies another user's data. This is OWASP API #1 (BOLA) and part of A01. Unguessable IDs only slow
enumeration; they leak via referrers, logs, and list endpoints, so they are defense-in-depth, never the
control.

**Fix:** derive identity from the session, scope every query to the owner, and check ownership on every
reference (read, update, delete, list, nested, bulk). Centralize the check.

```ts
// api/orders/[id]/route.ts — AFTER: verify ownership; 404 (not 403) avoids confirming existence
import { auth } from "@/lib/auth";
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const order = await db.order.findFirst({ where: { id: params.id, userId: session.user.id } });
  if (!order) return new Response("Not found", { status: 404 });
  return Response.json(order);
}
```

See also `vibe-security:auth` (authorization), `vibe-security:database` (RLS as a second layer), and
`vibe-security:deployment` (CSP and security headers).

## Open Redirects (cross-cutting)

A `redirect`/`next`/`returnTo` parameter taken from the request and followed without validation lets an
attacker send users to a phishing page under your domain's trust. Allowlist internal paths: accept only
values starting with a single `/` (reject `//host` and absolute URLs), or match against a known-safe
list. This also appears in `vibe-security:database` (Supabase GoTrue `redirectTo`),
`vibe-security:react-native-security`, and `vibe-security:expo-security` (deep links).

## Sources

- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html -- XSS prevention (context-correct escaping)
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html -- DOM-based XSS sinks and fixes
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html -- SSRF allowlisting, IP/DNS validation
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html -- upload validation, storage, re-encoding
- https://owasp.org/www-community/attacks/Path_Traversal -- path traversal mechanics
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html -- IDOR prevention
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ -- OWASP API #1 (BOLA)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP -- Content-Security-Policy as defense-in-depth
- https://portswigger.net/web-security -- worked examples (XSS, SSRF, file upload, access control)
