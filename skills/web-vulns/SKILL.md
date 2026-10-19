---
name: web-vulns
description: Audits classic web application vulnerabilities that AI assistants generate by omitting the validation or authorization guard - XSS (stored, reflected, DOM-based), SSRF (user-supplied URLs, webhooks, image/preview fetchers), file upload and path traversal, and IDOR / broken object-level authorization. Use when handling untrusted input that is rendered as HTML, used to build an outbound request, used as a file path or upload, or used to look up an object by ID. Covers OWASP A01 and A05 (2025 edition; SSRF is folded into A01 as of 2025).
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
Rich-text editors (TipTap/ProseMirror), .docx import, and sanitizer configuration (rehype-sanitize,
DOMPurify, sanitize-html) are covered in depth by `secaudit:rich-text-security`.

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

A user-configurable "outgoing webhook" or "custom notification URL" feature is this same SSRF
problem, not a signature-verification one — see `secaudit:webhook-security` §9 for the hand-off
from that skill's *inbound* verification recipes to this section's *outbound* fix.

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
modifies another user's data. This is OWASP API #1 (BOLA) and part of A01:2025. Unguessable IDs only slow
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

See also `secaudit:auth` (authorization), `secaudit:database` (RLS as a second layer), and
`secaudit:deployment` (CSP and security headers).
Cross-tenant access outside the object lookup (tenant id from a header or subdomain, cache keys, jobs,
webhooks, search indexes, impersonation) is covered by `secaudit:multi-tenant-isolation`.

## Open Redirects (cross-cutting)

A `redirect`/`next`/`returnTo` parameter taken from the request and followed without validation lets an
attacker send users to a phishing page under your domain's trust. Allowlist internal paths: accept only
values starting with a single `/` (reject `//host` and absolute URLs), or match against a known-safe
list. This also appears in `secaudit:database` (Supabase GoTrue `redirectTo`),
`secaudit:react-native-security`, and `secaudit:expo-security` (deep links).

## Next.js Config: Image Optimizer, JSON-LD, Rewrites, Taint

Four Next.js-specific holes that come from `next.config` or one framework idiom rather than from
application logic. Each is the section 1 or 2 root cause (untrusted input reaching a sink) hidden
behind configuration. Key names below are checked against the Next.js 16 docs; a project on an
older major may spell them differently.

### Image optimizer: `images` in `next.config`

**What to look for:** `images.dangerouslyAllowLocalIP: true`; `images.dangerouslyAllowSVG: true`
without a `contentSecurityPolicy` (or with `contentDispositionType: 'inline'`); `remotePatterns`
with `hostname: '**'`, or a wildcard (`**.example.com`) over a domain where outsiders can create
subdomains or host content; the deprecated `images.domains`.

**Why it's exploitable:** `/_next/image` fetches the `src` URL server-side for anyone who can reach
it, so every allowed pattern is an SSRF surface (section 2). `dangerouslyAllowLocalIP` removes the
private-address guard; the docs warn it "could allow malicious users to access content on your
internal network". A wildcard or attacker-influenced host (user-content subdomain, public bucket,
dangling CNAME) lets the attacker choose what your server requests, which is the shape of
`CVE-2026-94483` (version floors: `secaudit:framework-versions`, "The shared image pipeline").
SVG can carry script, so serving user SVG from your origin is stored XSS unless it is forced to
download and sandboxed. An omitted `protocol`, `port`, `pathname` or `search` in a pattern implies
`**`, so `{ hostname: 'cdn.example.com' }` allows every path and query on that host.

**Fix:** keep `dangerouslyAllowLocalIP` unset (false); list exact hostnames with `protocol` and a
narrow `pathname`; never wildcard a domain that hosts user content; leave `dangerouslyAllowSVG` off
and use the `unoptimized` prop for known first-party SVGs. If SVG optimization is truly needed, set
all three keys. `contentDispositionType` defaults to `attachment` (since 15.0.0), so `'inline'`
is the regression to look for.

```ts
// BAD — any host, any path; private IPs reachable; user SVG served inline with no CSP
images: {
  dangerouslyAllowLocalIP: true,
  dangerouslyAllowSVG: true,
  contentDispositionType: "inline",
  remotePatterns: [{ protocol: "https", hostname: "**" }],
}

// GOOD — one host, one path prefix; defaults for the rest
images: {
  remotePatterns: [{ protocol: "https", hostname: "cdn.example.com", pathname: "/img/**" }],
}

// GOOD (only if user SVG must be optimized) — forced download plus a script-blocking sandbox CSP
images: {
  dangerouslyAllowSVG: true,
  contentDispositionType: "attachment",
  contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
}
```

```bash
# risky image settings, wildcard hosts, and the deprecated domains list
grep -nE "dangerouslyAllowLocalIP: *true|dangerouslyAllowSVG: *true|contentDispositionType: *['\"]inline|hostname: *['\"]\*+['\"]|hostname: *['\"]\*\*?\.|[^a-zA-Z]domains: *\[" next.config.*
# files that allow SVG but never set contentSecurityPolicy
f=$(grep -l "dangerouslyAllowSVG: *true" next.config.*); [ -n "$f" ] && grep -L contentSecurityPolicy $f
```

### JSON-LD: `JSON.stringify` does not make a `<script>` safe

**What to look for:** `<script type="application/ld+json" dangerouslySetInnerHTML={{ __html:
JSON.stringify(data) }} />` where `data` includes a title, name, description or any other
user-controlled field.

**Why it's exploitable:** inside a `<script>` element the HTML parser ends the element at the first
`</script>`, whatever the JSON quoting around it. A product name of `</script><script>alert(1)</script>`
breaks out and runs. The Next.js JSON-LD guide says so itself: `JSON.stringify` "does not sanitize
malicious strings used in XSS injection".

**Fix:** escape `<` in the serialized string (`<` is still valid JSON, so crawlers read the same
value), as the guide's own snippet does, or serialize with a library built for it
(`serialize-javascript`). Put it in one helper so no page forgets.

```tsx
// BAD — a name containing </script> ends the tag early
<script type="application/ld+json"
  dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />

// GOOD
<script type="application/ld+json"
  dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />
```

```bash
# files that emit JSON-LD without any < escape (a file with two scripts needs a manual look)
grep -rl --null "ld+json" --include='*.tsx' --include='*.jsx' --include='*.ts' --include='*.js' --include='*.mdx' --exclude-dir=node_modules --exclude-dir=.next . | xargs -0 -r grep -L 'u003c'
```

### Rewrites: a destination built from the request is an open proxy

**What to look for:** `NextResponse.rewrite(new URL(x))` in middleware / `proxy.ts` where `x` comes
from `searchParams`, a header, a cookie or the path; a `rewrites()` entry whose external
`destination` interpolates a wildcard parameter (`https://api.example.com/:path*`), a `has` capture,
or a template literal built from request-time data.

**Why it's exploitable:** the docs call a rewrite "a URL proxy": the server fetches the destination
and returns it under your origin. A request-chosen destination is SSRF (section 2) plus an open
proxy that serves attacker-chosen content from your domain, and with a wildcard path the caller can
also reach internal-only routes on the same backend. The backend-for-frontend forms (`:path*`,
service-token injection, header forwarding) are in `secaudit:api-surface` §5; host-to-tenant rewrites
are in `secaudit:multi-tenant-isolation` §2.

**Fix:** map a validated key to a fixed origin and build only the path; use exact `source` entries or
constrained parameters (`:id(\\d{1,})`) in `rewrites()`; refuse anything not in the map.

```ts
// BAD — the caller picks the upstream
const target = req.nextUrl.searchParams.get("u")!;
return NextResponse.rewrite(new URL(target));

// GOOD — the caller picks a key from a Map (no `constructor` / `__proto__` lookups); the origin is yours;
// a path starting with `//` would be read as a host by new URL(), so reject it and re-check the origin
const ORIGINS = new Map([["a", "https://a.internal"]]);
const origin = ORIGINS.get(req.nextUrl.searchParams.get("t") ?? "");
const path = req.nextUrl.pathname;
if (!origin || !path.startsWith("/") || path.startsWith("//")) return new NextResponse(null, { status: 404 });
const upstream = new URL(path, origin);
if (upstream.origin !== origin) return new NextResponse(null, { status: 404 });
return NextResponse.rewrite(upstream);
```

```bash
# external destinations with a host parameter or wildcard path, and template-built destinations
grep -nE "destination: *[\`'\"]https?://([^/'\"\`]*:[A-Za-z_]|[^'\"\`]*:[A-Za-z_]+[*+])|destination: *\`\\\$\{" next.config.*
# NextResponse.rewrite fed a request-derived URL (also trace variables built from the request, e.g. nextUrl.clone() with its host or pathname changed)
grep -rl --null "NextResponse\.rewrite" --include='*.ts' --include='*.tsx' --exclude-dir=node_modules --exclude-dir=.next . | xargs -0 -r grep -nE "new URL\((target|url|dest|u|[a-z]+\.nextUrl\.(searchParams|pathname)|[a-z]+\.headers\.get|[a-z]+\.cookies)|NextResponse\.rewrite\(new URL\([a-zA-Z_]+\)\)|NextResponse\.rewrite\(\`https?://\\\$\{|nextUrl\.clone\(\)"
```

### Taint API: an optional net, checked at runtime, not at build

`experimental: { taint: true }` enables React's `experimental_taintObjectReference` and
`experimental_taintUniqueValue` (imported from `react`). A tainted object or value that is passed
into a Client Component makes React throw while rendering, which is the only moment it is checked:
`next build` and the type checker do not flag it, so a path no test renders stays unchecked. The
docs list the limits. Tainting follows the object **reference**, so a copy or spread
(`{ ...user }`) is untainted; a derived value is untainted; and the built-in `process.env` taint
covers the object only, not `process.env.MY_VAR` passed as a string. Enabling it also switches the
app directory to React's experimental channel. The docs say not to rely on it as the only
mechanism: the primary fix is a DTO, which selects the safe fields before data reaches a Client
Component (`secaudit:secrets` covers `NEXT_PUBLIC_` exposure; `secaudit:api-surface` §8 covers
whole-row responses).

```tsx
// BAD — the whole row, password hash and tokens included, becomes client props
const user = await db.user.findFirst({ where: { id } });
return <ProfileCard user={user} />;

// GOOD — a DTO, plus taint as a backstop for the next person who forgets
import { experimental_taintObjectReference } from "react";
const user = await db.user.findFirst({ where: { id } });
experimental_taintObjectReference("Do not pass the full user row to the client", user);
return <ProfileCard name={user.name} avatarUrl={user.avatarUrl} />;
```

```bash
# whole user/session/account/token objects passed as props (read each hit; is the component a Client Component?)
grep -rnE "<[A-Z][A-Za-z]* [^>]*\b(user|session|account|token|profile)=\{[A-Za-z_.]+\}" --include='*.tsx' --include='*.jsx' --exclude-dir=node_modules --exclude-dir=.next .
# is taint enabled, and where is it applied
grep -rnE "taint: *true|experimental_taint" --exclude-dir=node_modules --exclude-dir=.next .
```

## Sources

- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html -- XSS prevention (context-correct escaping)
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html -- DOM-based XSS sinks and fixes
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html -- SSRF allowlisting, IP/DNS validation
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html -- upload validation, storage, re-encoding
- https://community.owasp.org/attacks/Path_Traversal -- path traversal mechanics
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html -- IDOR prevention
- https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/ -- OWASP API #1 (BOLA)
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP -- Content-Security-Policy as defense-in-depth
- https://portswigger.net/web-security -- worked examples (XSS, SSRF, file upload, access control)
- https://nextjs.org/docs/app/api-reference/components/image -- `images` config keys (remotePatterns wildcard rules and omitted fields implying `**`, dangerouslyAllowLocalIP, dangerouslyAllowSVG, contentDispositionType, contentSecurityPolicy), deprecated `domains`, `unoptimized`
- https://nextjs.org/docs/app/guides/json-ld -- JSON-LD: `JSON.stringify` does not sanitize; replace `<` with `\u003c`
- https://nextjs.org/docs/app/api-reference/config/next-config-js/rewrites -- rewrites act as a URL proxy; external destinations; matched params in the destination
- https://nextjs.org/docs/app/api-reference/functions/next-response -- `NextResponse.rewrite()` proxies the given URL
- https://nextjs.org/docs/app/api-reference/config/next-config-js/taint -- `experimental.taint`, taint APIs, caveats (reference-only, runtime throw)
- https://nextjs.org/docs/app/guides/data-security -- Tainting is an additional layer; filter in the DAL first
