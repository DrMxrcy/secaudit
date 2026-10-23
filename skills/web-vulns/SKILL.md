---
name: web-vulns
description: Audits classic web application vulnerabilities that AI assistants generate by omitting the validation or authorization guard - XSS (stored, reflected, DOM-based, including navigation sinks like location.href and router.push, postMessage origin checks, and Sanitizer API / mutation XSS), SSRF (user-supplied URLs, webhooks, image/preview fetchers), file upload and path traversal, and IDOR / broken object-level authorization. Use when handling untrusted input that is rendered as HTML, used to build an outbound request, used as a file path or upload, or used to look up an object by ID. Covers OWASP A01 and A05 (2025 edition; SSRF is folded into A01 as of 2025).
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

Review grep heuristics: raw-HTML render sinks, `innerHTML`, `location.href =` / `router.push(` /
`window.open(` with a non-literal argument, `addEventListener("message"` without an `event.origin`
check, server-side `fetch(`/`axios(` on user input, `path.join(` with request data, and object
lookups `where: { id }` with no user/tenant scope. The DOM-sink greps are in §1.1-§1.3.

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

`safeUrl` fits a link that may point off-site (a profile "website" field). For a *navigation* target
that must stay on your site, use the same-origin check in §1.1. The DOM-navigation, `postMessage`
and Sanitizer API sinks below are the client-side half of XSS; CSP and Trusted Types
(`secaudit:deployment`) are the backstop when one of them is missed.

### 1.1 Navigation sinks: `javascript:` XSS and open redirect

**What to look for:** `location.href =` / `location =`, `location.assign()` / `location.replace()`,
`window.open()`, `router.push()` / `router.replace()` / `navigate()`, a server-side `redirect()`,
`<a href={…}>`, `<Link href={…}>`, `<iframe src={…}>` and `<form action={…}>`, where the value comes
from the query string (`next`, `returnTo`, `redirect`, `callbackUrl`), `location.hash`,
`document.referrer`, a `postMessage` payload, or a stored field (profile website, "view original" link).

**Why it's exploitable:** a `javascript:` URL assigned to `location.href` or placed in an `<a href>`
runs in your origin when navigated or clicked: XSS, with the viewer's session. A user-controlled
`https://evil.example` is an open redirect, usable for phishing under your domain's trust and for
stealing OAuth codes or tokens carried on the next hop. Do not count on the framework to strip
`javascript:`. String checks fail: `startsWith('/')` passes `//evil.example` and `/\evil.example`
(both resolve to another host), and `startsWith('https://app.example.com')` passes
`https://app.example.com.evil.example`.

**Triage rule (read this before reporting):** SAST tools flag every navigation call whose argument
contains a variable and rate it High. A **server-built same-origin path with typed, enum or numeric
segments is not exploitable**: ``router.push(`/orders/${order.id}`)``,
`` `/projects/${project.slug}/settings` `` where the id or slug comes from a typed, server-loaded
record, or a literal `'/dashboard'`. The leading `/` plus a literal first segment fixes scheme and
host; nothing in a later segment can change them. Mark those as false positives. It **is
exploitable** when the user controls any part of the scheme, host or the whole URL:
`location.href = params.get('next')`, `router.push(query.returnTo)`, `window.open(data.url)`,
`` `${user.baseUrl}/home` ``, `<a href={user.website}>`, and the easy-to-miss `` `/${userPath}` ``
(the user supplies the second `/`, giving `//evil.example`).

**Fix:** map a key to a route you own (`{ billing: '/settings/billing' }[key]`), or parse and
compare against your own origin, then use the *parsed* absolute URL. Do not rebuild it from
`u.pathname`: `/.//evil.example` has the right origin yet a pathname of `//evil.example`, which a
later `location.href = pathname` would follow to another host. For links that may leave the site,
allow only `http:` / `https:` / `mailto:` (the `safeUrl` above) and open new windows with
`rel="noopener noreferrer"` / the `noopener` feature. The server-side form (a `redirect` parameter
followed by a 302) is the "Open Redirects" section below. Google's origin-validation guide adds the
`Origin` API (`Origin.from(x).isSameOrigin(...)`) for browsers that have it; `new URL()` plus an
`origin` comparison works everywhere.

```ts
// BAD — every one of these takes the destination from the user
const next = new URLSearchParams(location.search).get("next");
location.href = next!;                                  // javascript:alert(1) -> XSS; https://evil.example -> redirect
router.push(searchParams.get("returnTo")!);
if (next!.startsWith("/")) location.href = next!;       // //evil.example and /\evil.example pass

// GOOD — same-origin only, using the parsed URL; anything else falls back
export function safeInternalUrl(raw: string | null, fallback = "/"): string {
  if (!raw) return fallback;
  try {
    const u = new URL(raw, location.origin);            // javascript: -> origin "null"; //host -> that host
    return u.origin === location.origin ? u.href : fallback;
  } catch { return fallback; }
}
location.href = safeInternalUrl(next);
```

### 1.2 `postMessage`: check the sender, name the receiver

**What to look for:** `addEventListener("message", …)` (or `window.onmessage =`) whose handler does
not compare `event.origin` to an exact trusted value before acting on `event.data`; origin checks
written with `includes()`, `startsWith()`, `endsWith()`, `indexOf()` or a regex; accepting the
string `"null"`; `postMessage(data, "*")` carrying a token, user data or anything else sensitive.

**Why it's exploitable:** any window with a reference to yours (an opener, a parent frame, an iframe
you embed) can post a message, so `event.data` is attacker input. With no origin check, it flows
into `innerHTML`, `eval`, `location` or an API call (DOM XSS, forced actions). Substring and prefix
checks are bypassed by `https://example.com.evil.example` or `https://evil-example.com`, and
sandboxed iframes and `data:` pages all send the origin `"null"`, which two unrelated pages share.
On the sending side the target `"*"` delivers the message to whichever page now occupies that
window, so a navigated or malicious frame receives the token.

**Fix:** compare `event.origin` with `===` against a fixed list of full origins (scheme, host,
port), then validate the shape of `event.data` before use. Pass the exact receiver origin as the
second argument of every send that carries anything non-public. For sandboxed senders (`event.origin`
is `"null"`) pin `event.source` to the expected frame or use a `MessageChannel` port instead of the
origin string.

```ts
// BAD
window.addEventListener("message", (e) => {
  if (!e.origin.includes("example.com")) return;       // example.com.evil.example, evil-example.com
  el.innerHTML = e.data.html;
});
parent.postMessage({ token: session.token }, "*");     // whoever is in `parent` now gets the token

// GOOD
const TRUSTED = new Set(["https://app.example.com"]);
window.addEventListener("message", (e) => {
  if (!TRUSTED.has(e.origin)) return;                  // exact match; "null" is not in the set
  if (typeof e.data?.action !== "string") return;      // validate before use
  handle(e.data);
});
parent.postMessage({ action: "ready" }, "https://app.example.com");
```

### 1.3 Sanitizer API and mutation XSS

**What to look for:** `setHTMLUnsafe()` and `Document.parseHTMLUnsafe()` fed by untrusted input;
sanitized output that is serialized back to a string and re-parsed with `innerHTML`; a string
edited (`.replace`, concatenation) between the sanitizer and the sink.

**Why it's exploitable:** `Element.setHTML()` and `Document.parseHTML()` always strip XSS-unsafe
content. The `*Unsafe` variants are injection sinks: with no `sanitizer` option MDN states that no
sanitizer is used, and a permissive custom config can allow script-bearing elements. Sanitized DOM
that is serialized and re-parsed can come out different the second time (mutation XSS, "mXSS"):
the parser round-trip moves content between HTML, SVG and MathML contexts, so a payload that was
inert in the first parse becomes active in the second. The same applies to editing the sanitized
string before assignment.

**Fix:** use `el.setHTML(untrusted)` (add `{ sanitizer: { elements: […], attributes: […] } }` to
tighten it). To inspect first, `Document.parseHTML()` and move the nodes
(`target.replaceChildren(...doc.body.childNodes)`), never `innerHTML = doc.body.innerHTML`. Where
the API is missing, feature-detect with `"setHTML" in Element.prototype` and fall back to DOMPurify,
sanitizing last, directly before the sink. Treat `setHTMLUnsafe` / `parseHTMLUnsafe` as sinks
exactly like `innerHTML`, to be enforced with Trusted Types (`secaudit:deployment` §2). Library
sanitizer configuration is `secaudit:rich-text-security`.

```ts
// BAD
el.setHTMLUnsafe(userHtml);                              // no sanitizer unless you pass one
box.innerHTML = DOMPurify.sanitize(html).replace(/&nbsp;/g, " ");   // edited after sanitizing
const doc = Document.parseHTML(userHtml);
target.innerHTML = doc.body.innerHTML;                   // serialize + reparse = mXSS surface

// GOOD
el.setHTML(userHtml);
target.replaceChildren(...Document.parseHTML(userHtml).body.childNodes);
```

### Heuristics (grep)

First-pass leads, not verdicts: apply the §1.1 triage rule to each navigation hit. Tested on a
scratch fixture with vulnerable and clean files: the vulnerable set prints every check, the clean
set prints nothing. Lines containing `safe…(`, `allowlist`, `validate`, `sanitize` or
`isSameOrigin` are filtered from the navigation hits, so name your own guard helpers that way.

```bash
G() { grep -rnE --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=dist \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
  --include='*.vue' --include='*.svelte' --include='*.html' "$@"; }
OKNAV='safe[A-Za-z]*\(|allowlist|validate|sanitize|isSameOrigin'

# 7 navigation sinks fed by a non-literal (a literal "/word" prefix is skipped: see the triage rule)
G "(\blocation(\.href)?\s*=\s*|(router|navigate|history)\.(push|replace)\(\s*|\bnavigate\(\s*|location\.(assign|replace)\(\s*|window\.open\(\s*|\bredirect\(\s*)(\`/?\\\$\{|[A-Za-z_\$(])" . | grep -viE "$OKNAV"
G "(href|action|formAction)=\{\s*(\`/?\\\$\{|[A-Za-z_\$])|<iframe[^>]*src=\{|:href=\"[A-Za-z_]" . | grep -viE "$OKNAV"
# where the URL comes from: query-string params and fields that name a destination
G "(get|getAll)\(['\"](next|returnTo|return_to|returnUrl|redirect|redirectTo|redirect_uri|callbackUrl|continue|dest|url|target)['\"]\)|query\.(next|returnTo|redirect|redirectTo|callbackUrl|url)\b" .

# 6 postMessage: a listener with no exact origin comparison in its first 8 lines
G -l "addEventListener\(\s*['\"]message['\"]|\.onmessage\s*=" . | while IFS= read -r f; do
  awk -v f="$f" '
    /addEventListener\([ ]*["\x27]message["\x27]|\.onmessage[ ]*=/ { n=NR; hit[n]=1; seen[n]=0 }
    { for (s in hit) if (NR>=s && NR<=s+8 && $0 ~ /origin[ ]*[!=]==|isSameOrigin|(TRUSTED|ALLOWED|allowed|trusted)[A-Za-z_]*\.(has|includes)\(/) seen[s]=1 }
    END { for (s in hit) if (!seen[s]) print f ":" s ": message listener with no exact origin check" }' "$f"
done
# weak origin checks (substring, prefix, suffix, regex) and wildcard target origins
G "origin\.(includes|startsWith|endsWith|indexOf|match|search)\(|\.test\(\s*[A-Za-z_.]*origin\b" .
G "postMessage\([^;]*,\s*['\"]\*['\"]" .

# 8 Sanitizer API / mXSS: *Unsafe sinks, serialize-then-reparse, string edits after the sanitizer
G "setHTMLUnsafe|parseHTMLUnsafe" .
G "(innerHTML|outerHTML|setHTMLUnsafe)(\s*=|\()\s*[^=;]*\.(innerHTML|outerHTML)\b|serializeToString" .
G "(sanitize|purify|clean)[A-Za-z]*\([^)]*\)\)?\s*(\.(replace|concat|slice|trim|split)\(|\+)" .
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

The response is attacker input too. Any Node HTTP client that auto-decodes responses (built-in
fetch/undici, axios, node-fetch, got, superagent) decodes a `br` response body, whatever `Accept-Encoding` the request sent, so on a Node.js runtime below the
Node2Shell (`CVE-2026-111497`) floors a fetcher pointed at a hostile host hands it the vulnerable
Brotli decoder: the URL and allowlist checks run before the request, but the decoder runs when the
response (or request) body is read or a redirect is followed, before any body-level handling. The allowlist narrows who can answer;
only the runtime upgrade closes it. Floors, EOL lines and the request-body (`Content-Encoding: br`)
side: `secaudit:framework-versions`, *Node.js (the runtime)*.

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
list. The client-side form (`location.href = next`, `router.push(returnTo)`, which also carries
`javascript:` XSS) and its triage rule are §1.1. This also appears in `secaudit:database` (Supabase GoTrue `redirectTo`),
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
- https://github.com/GoogleChrome/modern-web-guidance-src/blob/main/guides/security/security/guide.md -- dangerous DOM sinks, secure postMessage (exact origin, explicit target origin)
- https://github.com/GoogleChrome/modern-web-guidance-src/blob/main/guides/security/validate-origins/guide.md -- exact origin comparison; substring/prefix spoofing; opaque "null" origins
- https://github.com/GoogleChrome/modern-web-guidance-src/blob/main/guides/security/sanitize-untrusted-html/guide.md -- setHTML vs setHTMLUnsafe; move parsed nodes instead of reserializing (mXSS)
- https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage -- postMessage security: check origin, specify targetOrigin
- https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTMLUnsafe -- setHTMLUnsafe is an injection sink; no sanitizer unless passed
- https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTML -- setHTML always removes XSS-unsafe content
- https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API -- Sanitizer API overview
