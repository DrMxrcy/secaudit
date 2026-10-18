---
name: rich-text-security
description: Audits rich-text editors and the HTML they produce — TipTap and ProseMirror (stored editor JSON vs `getHTML()` HTML, why the client-side editor schema is not a sanitizer, sanitize-on-write at the API, render sinks and server-side `generateHTML`/`generateJSON` running on happy-dom, the Link extension's `isAllowedUri`/`protocols` gate, Image `src` and `allowBase64`, paste and drop handlers, custom nodes and marks that emit raw attributes), document import (mammoth .docx→HTML, external image links, unsanitized converter output), and the sanitizer layer itself (rehype-sanitize schemas and plugin order in a unified/remark/rehype pipeline, DOMPurify and sanitize-html configuration and version floors). Use whenever the project has a WYSIWYG or rich-text editor, stores or renders user-authored rich documents, imports .docx/HTML/Markdown into a document, or configures an HTML sanitizer — stored XSS in a shared document runs on your origin for every viewer. Generic XSS basics stay in secaudit:web-vulns; Markdown rendering of LLM output stays in secaudit:ai-integration.
license: MIT
---

# Rich-Text Security (Editors, Document Import, Sanitizers)

A rich-text editor is a stored-XSS feature with a nice toolbar. Its whole job is to let a user
author markup that other users' browsers will later render, and every layer between the keystroke
and that render — the editor schema, the paste handler, the API that saves the document, the
converter that imported a .docx, the sanitizer, the renderer — is a place where an attribute the
user should never control can slip through. The editor's schema makes the UI *feel* like a filter:
paste a `<script>` into TipTap and it vanishes. That filtering ran in the author's browser, which is
the one machine in the system the attacker owns.

The recurring AI-codegen failure mode is wiring the editor up correctly on the client and then
treating whatever the client sends as already clean: `editor.getHTML()` POSTed straight into a
database column, read back into `dangerouslySetInnerHTML`, with a custom node that copies a `style`
or `href` attribute verbatim because "the editor only produces valid documents." Findings here map
to OWASP **A05:2025** (Injection — XSS) and **A01:2025** (Broken Access Control — SSRF when the
server fetches a document's image URLs).

`secaudit:web-vulns` covers XSS as a general problem (sinks, context-correct escaping, URL-scheme
blocking, CSP as defence in depth) — read it first for the basics; this skill does not repeat them.
This skill covers what is specific to rich documents: where the trust boundary actually is for an
editor, the editor framework's own security knobs and advisories, document import, and sanitizer
configuration. Markdown rendering of LLM output is `secaudit:ai-integration`.

## When to Use

- `package.json` lists any of `@tiptap/*`, `prosemirror-*`, `mammoth`, `rehype-sanitize`,
  `rehype-raw`, `dompurify` / `isomorphic-dompurify`, `sanitize-html`, or `happy-dom`.
- The app stores user-authored documents, posts, comments, wiki pages, notes, or email templates
  with formatting, links, or images, and renders them for anyone other than the author.
- Code converts between HTML, Markdown, editor JSON, or .docx in either direction.
- Reviewing an editor's paste/drop handling, a custom TipTap node or mark, or a sanitizer config.

Review grep heuristics (find the surface first). Every grep in this skill excludes `node_modules`;
in a tree with build output also add `--exclude-dir=.next --exclude-dir=dist --exclude-dir=build
--exclude-dir=out`, or minified bundles bury the real hits:

```bash
grep -rnE --include=package.json --exclude-dir=node_modules \
  '"(@tiptap/[a-z-]+|prosemirror-[a-z]+|mammoth|rehype-sanitize|rehype-raw|dompurify|isomorphic-dompurify|sanitize-html|happy-dom)"' .
npm ls prosemirror-view @tiptap/core @tiptap/extension-link happy-dom 2>/dev/null   # resolved versions, incl. transitive
```

## 1. Stored Format and Sanitize-on-Write

**Why it matters:** the server can only enforce what it re-checks. An editor that stores
`editor.getHTML()` makes the database column a raw-HTML column that any client — or `curl` — can
write; an editor that stores `editor.getJSON()` makes it a tree the server can re-parse against a
known schema. Either way the client schema is a UX feature, not a sanitizer: the attacker skips
the editor entirely and POSTs the payload to your save endpoint.

**What to look for:**

- The save route (API handler, Server Action, tRPC/GraphQL mutation) persists `html`, `content`,
  `body`, or `doc` from the request with no server-side sanitize or schema check. A validator of
  `z.string()`, `z.any()`, `z.unknown()`, or `z.record(...)` on that field is the same as no check.
- HTML stored, then "sanitized on render" only in a client component — the API that serves the
  stored HTML to a mobile app, an RSS feed, an email digest, or an export skips it.
- JSON stored without re-validation. Editor JSON is just JSON: an attacker can send unknown node
  types, an `image` with `src: "javascript:..."`, a `link` mark with any `href`, or attributes your
  extensions never declared.
- **Sanitizer drift.** Content sanitized at write time under last year's sanitizer version or a
  looser config is still in the table. A sanitizer upgrade (§9) or a tightened allowlist does not
  reach rows that were written before it unless they are re-sanitized, or unless the render path
  re-derives output from JSON on every read.

```ts
// BAD — the editor schema filtered this in the author's browser; nothing filters it here
export async function PUT(req: Request) {
  const { html } = await req.json();            // editor.getHTML() — or anything curl sends
  await db.doc.update({ where: { id }, data: { html } });
  return new Response(null, { status: 204 });
}
```

```ts
// GOOD — store JSON, and re-derive it on the server from the same extension list the editor uses
import { getSchema } from '@tiptap/core';
import type { Node as PMNode } from '@tiptap/pm/model';
import { serverExtensions } from '@/editor/extensions.server'; // same nodes/marks as the editor, no node views

const schema = getSchema(serverExtensions);
const MAX_BYTES = 512 * 1024;

export async function PUT(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await requireSession(req);     // identity from the server session, never the body
  const raw = await req.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BYTES) return new Response('Too large', { status: 413 });
  let doc: PMNode;
  try {
    doc = schema.nodeFromJSON(JSON.parse(raw));  // unknown node/mark types throw; undeclared attrs are dropped
    doc.check();                                 // content model + every attribute `validate`
    assertSafeUrls(doc);                         // §3 / §4 — attribute *values* still need an allowlist
  } catch {
    return new Response('Invalid document', { status: 400 });
  }
  const { id } = await params;
  await db.doc.update({ where: { id, ownerId: session.userId }, data: { body: doc.toJSON() } });
  return new Response(null, { status: 204 });
}

function assertSafeUrls(doc: PMNode) {
  doc.descendants((node) => {
    if (node.type.name === 'image' && !isOwnAsset(node.attrs.src)) throw new Error('image src');
    for (const mark of node.marks) {
      if (mark.type.name === 'link' && !isSafeHref(mark.attrs.href)) throw new Error('link href');
    }
  });
}
```

`schema.nodeFromJSON` + `check()` rejects structure the schema does not allow, but every
*declared* attribute is still an arbitrary value unless the extension declares a `validate` for it
(TipTap attributes accept `validate`, passed through to the ProseMirror attribute spec; attribute
`validate` itself arrived in prosemirror-model 1.22.0, so older resolved versions ignore it) —
hence the explicit URL pass. `href` and `src` are not the only ones: Link's `class`, `target`,
`rel`, and `title`, and Image's `alt`, `title`, `width`, and `height` all survive `nodeFromJSON` as
whatever string the client sent. A hostile `class` under utility CSS (`fixed inset-0 z-50 ...`) turns
a link into a full-page click-jacking overlay or a fake login prompt without any script; a hostile
`target` or `rel` undoes your link policy. Pin each one with a `validate` (fixed set, number, or
pattern), or strip and re-default it on the server before storing.

If the project must store HTML, sanitize it on the server at write time with an allowlist
sanitizer (§8, §9) **and** sanitize or re-derive it again at render time, so drift and any path
that bypassed the write check are both covered.

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'getHTML\(\)' --include='*.ts' --include='*.tsx' --include='*.vue' --include='*.svelte' .
grep -rnE --exclude-dir=node_modules '(html|content|body|doc)[A-Za-z]*: *z\.(string|any|unknown|record)\(' --include='*.ts' .
# save routes that touch rich content but never sanitize or re-parse it
grep -rlE --exclude-dir=node_modules 'getHTML|getJSON|JSONContent|bodyHtml|contentHtml' --include='*.ts' --include='*.tsx' . \
  | xargs grep -LE 'sanitize|DOMPurify|nodeFromJSON|rehype-sanitize|sanitizeDoc' 2>/dev/null
```

## 2. Render Sinks

**Why it matters:** stored rich content is rendered for every viewer, so the render path decides
whether a single bad row is a stored XSS. Rendering a validated JSON tree to framework elements
escapes text by construction; rendering an HTML string through a raw-HTML sink trusts every byte of
it. Server-side rendering adds a second risk: the HTML utility runs a DOM emulator on your server.

**What to look for:**

- Stored HTML (or `generateHTML(...)` output) into React's `dangerouslySetInnerHTML`, Vue `v-html`,
  Svelte `{@html}`, `element.innerHTML =`, or `insertAdjacentHTML`. `generateHTML` output is only as
  safe as the JSON you fed it (§1) and every extension's `renderHTML` (§6) — it is not a sanitizer.
- `generateHTML` / `generateJSON` imported from `@tiptap/html` on the server. The docs describe it
  as the server-capable variant ("On the server, a virtual DOM is used to generate the HTML"); the
  virtual DOM is **happy-dom**, a peer dependency since `@tiptap/html` 3.0.1 (3.0.0 and the 2.x
  line used zeed-dom), so *your* lockfile picks its version. `generateJSON(attackerHtml, ...)` on the server hands attacker markup to that emulator.
- The happy-dom version. At least five advisories apply to a server parsing untrusted HTML:
  CVE-2024-51757 (GHSA-96g7-g7g9-jxw8, server-side code executed by a `<script>` tag) fixed
  15.10.2; CVE-2025-61927 (GHSA-37j7-fg3j-429f, VM-context escape to RCE when JavaScript evaluation
  is on, which was the default) fixed 20.0.0; CVE-2025-62410 (GHSA-qpm2-6cq5-7pq5, the
  `--disallow-code-generation-from-strings` mitigation is insufficient to isolate untrusted script)
  fixed 20.0.2; CVE-2026-33943 (GHSA-6q6h-j7hj-3r64, ES-module export names interpolated into
  executable code) fixed 20.8.8; CVE-2026-34226 (GHSA-w4gp-fjgq-3q4g, `fetch` with
  `credentials: "include"` sends page-origin cookies to the request target) fixed 20.8.9.
- The `@tiptap/html` version. Releases before 3.17.1 construct the happy-dom `Window` with default
  settings; from 3.17.1 it passes `disableJavaScriptEvaluation: true` and
  `disableJavaScriptFileLoading: true` explicitly. Early 3.x releases declare a `happy-dom` peer of
  `^18.0.1`, so an untouched lockfile on an early 3.x install can still resolve a happy-dom that
  evaluates script by default — which is the CVE-2025-61927 precondition.
- Direct `new Window()` from happy-dom (or jsdom with `runScripts`) used to "clean" or parse user
  HTML on the server.

Floor: `happy-dom@20.8.9` with a current `@tiptap/html`, or no DOM emulator on the server at all.

```tsx
// BAD — raw HTML from the database into the page; one bad row is stored XSS for every reader
export function DocView({ doc }: { doc: { html: string } }) {
  return <article dangerouslySetInnerHTML={{ __html: doc.html }} />;
}

// BAD — generateHTML is a serializer, not a sanitizer; on the server it also runs happy-dom
import { generateHTML } from '@tiptap/html';
export function DocHtml({ row }: { row: { body: JSONContent } }) {
  const html = generateHTML(row.body, extensions);  // row.body never re-validated (§1)
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
```

```tsx
// GOOD — validated JSON rendered to React elements: text is escaped by React, no DOM emulator,
// and each extension's renderHTML (including Link's href gate, §3) still runs
import { renderToReactElement } from '@tiptap/static-renderer/pm/react';
import { serverExtensions } from '@/editor/extensions.server';

export function DocView({ body }: { body: JSONContent }) {   // body was checked on write (§1)
  return <article>{renderToReactElement({ content: body, extensions: serverExtensions })}</article>;
}
```

The static renderer (`@tiptap/static-renderer`, also `renderToHTMLString` from
`@tiptap/static-renderer/pm/html-string`) builds output without a browser or DOM, escapes text and
attribute values, and calls each extension's `renderHTML`. It does **not** vet attribute *names*: a
custom `renderHTML` that emits `onerror` or `style` (§6) is rendered as written — in the HTML-string
variant an `on*` attribute is live markup, and in the React variant a `style` string becomes a live
inline style. Fix the extension, not the renderer.

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'dangerouslySetInnerHTML|v-html|\{@html|\.innerHTML *=|insertAdjacentHTML' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.vue' --include='*.svelte' .
grep -rnE --exclude-dir=node_modules "from ['\"]@tiptap/html|generate(HTML|JSON)\(" --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules "from ['\"](happy-dom|jsdom)['\"]|new (Window|JSDOM)\(" --include='*.ts' --include='*.tsx' --include='*.js' .
```

## 3. TipTap Link: `isAllowedUri` Is the Gate

**Why it matters:** a link mark's `href` is the most direct script vector in a rich document — a
`javascript:` URL in an `<a>` runs on click, on your origin. TipTap's Link extension has exactly one
security control for it, `isAllowedUri`, and it is easy to disable while "fixing" a link that
would not save.

**How the gate works (`@tiptap/extension-link`, 3.x source):** `isAllowedUri(url, ctx)` is checked
in `parseHTML` (an `<a>` whose href fails is not parsed as a link), in `renderHTML` (a failing href
is rendered as `href=""`), and in the `setLink` / `toggleLink` commands. The default validator
allows `http`, `https`, `ftp`, `ftps`, `mailto`, `tel`, `callto`, `sms`, `cid`, `xmpp`, scheme-less
(relative) URLs, plus whatever you add in `protocols`; it strips Unicode whitespace before matching.

**What to look for:**

- `isAllowedUri` that returns `true`, or that ignores `ctx.defaultValidate` without its own scheme
  check (`isAllowedUri: (url) => url.length > 0`).
- `protocols` extended with a scheme that can execute or smuggle content (`javascript`, `data`,
  `vbscript`, `file`). `protocols` *adds* to the default list; it cannot remove `ftp`/`tel`/etc. —
  if the app wants only `https`/`mailto`, write an `isAllowedUri` that says so.
- `validate` or `shouldAutoLink` treated as the security check. `validate` is **deprecated** in
  favour of `shouldAutoLink` (the extension logs a rename warning). `shouldAutoLink` only decides
  whether typed or pasted URL text is *auto*-linked; it never runs for `setLink`, parsed HTML, or
  stored JSON.
- A custom renderer (your own React mapping, an email template, a Markdown exporter) that reads
  `mark.attrs.href` directly. The gate lives in the extension's `renderHTML`; code that bypasses it
  bypasses the gate, and stored JSON can carry any `href` (§1).
- The extension version. CVE-2025-14284 (GHSA-vhrc-hgrq-x75r): `setLink` / `toggleLink` accepted a
  `javascript:` href in `@tiptap/extension-link` before 2.10.4; fixed 2.10.4. Any 3.x release
  includes it.

```ts
// BAD — "links to our internal tool weren't saving", so the gate was switched off
import Link from '@tiptap/extension-link';

Link.configure({
  protocols: ['javascript'],                 // never — this is a script URL allowlist
  isAllowedUri: () => true,                  // parseHTML, renderHTML and setLink now accept anything
  shouldAutoLink: (url) => url.startsWith('https://'), // autolink only — not a security check
});
```

```ts
// GOOD — an explicit allowlist that composes with the default validator
import Link from '@tiptap/extension-link';

const ALLOWED = new Set(['https:', 'http:', 'mailto:']);
export function isSafeHref(href: unknown): boolean {
  if (typeof href !== 'string') return false;
  try {
    // Dummy base so relative links parse; only the protocol is read. The URL parser strips the
    // tabs/newlines/control characters that "java\tscript:" relies on.
    return ALLOWED.has(new URL(href, 'https://example.com').protocol);
  } catch {
    return false;
  }
}

Link.configure({
  openOnClick: false,
  isAllowedUri: (url, ctx) => ctx.defaultValidate(url) && isSafeHref(url),
  HTMLAttributes: { rel: 'noopener noreferrer nofollow ugc' },
});
```

Use the same `isSafeHref` in the server-side check (§1) and in any custom renderer, so the three
places that judge an `href` cannot disagree.

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'isAllowedUri *: *\([^)]*\) *=> *true|isAllowedUri *: *\(\) *=>' --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules "protocols *: *\[[^]]*(javascript|data|vbscript|file)" --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules -A12 'Link\.(configure|extend)\(|link *: *\{' --include='*.ts' --include='*.tsx' . \
  | grep -E 'validate|shouldAutoLink|isAllowedUri|protocols'
grep -rnE --exclude-dir=node_modules 'attrs\??\.href' --include='*.ts' --include='*.tsx' .   # renderers reading href directly
```

## 4. Image `src`

**Why it matters:** an image node's `src` is fetched by every viewer's browser the moment the
document renders — no click needed. An arbitrary `src` is a read receipt (tracking pixel revealing
each viewer's IP and open time), a mixed-content or hotlinked asset, a vector for oversized
`data:` payloads, and — if any server process ever fetches or renders document images (thumbnails,
PDF export, link previews, email digests) — an SSRF primitive aimed at your internal network.

**How the extension behaves (`@tiptap/extension-image`, 3.x source):** `allowBase64` (default
`false`) only changes the `parseHTML` rule — with it off, `<img src="data:...">` in parsed HTML is
skipped. Nothing in the extension checks the protocol or host of `src`, and `setImage`, stored
JSON, and Markdown input are not gated by `allowBase64` at all. `inline` only changes whether
images sit inside paragraphs.

**What to look for:**

- `allowBase64: true` — `data:` images bloat stored rows, sidestep your upload pipeline's type and
  size checks, and carry SVG-in-data-URI risks when something later renders them out of context.
- No `src` allowlist anywhere: the editor, the server check (§1), and the renderer all accept any
  `https://` host, `http://`, or `data:`.
- Server code that fetches `src` values from a stored document (`fetch(node.attrs.src)`, image
  proxies, `sharp` on a downloaded buffer, headless-browser PDF export with network access) — apply
  `secaudit:web-vulns` SSRF controls, or better, never fetch: resolve your own asset ids instead.
- Upload handlers that insert whatever URL the upload endpoint echoes back without checking it is
  your asset origin.

```ts
// BAD — base64 accepted, any host accepted, and the server later fetches it for a PDF export
import Image from '@tiptap/extension-image';

Image.configure({ allowBase64: true });

export async function exportPdf(doc: JSONContent, pdf: PdfWriter) {
  for (const src of imageSrcs(doc)) pdf.addImage(await (await fetch(src)).arrayBuffer()); // SSRF
}
```

```ts
// GOOD — only your own uploaded-asset origin loads, in the editor and on the server
import Image from '@tiptap/extension-image';

const ASSET_ORIGIN = 'https://assets.myapp.com';  // where your upload route stores objects
const ASSET_PATH = '/u/';

// Judge the *parsed* URL, never the raw string: `https://assets.myapp.com/u/%2e%2e/private/x.png`
// passes a startsWith() prefix check but the URL parser normalizes it to `/private/x.png`.
export function isOwnAsset(src: unknown): src is string {
  if (typeof src !== 'string') return false;
  let u: URL;
  try {
    u = new URL(src);                             // absolute only — no base, so '/u/x.png' is rejected
  } catch {
    return false;
  }
  return (
    u.origin === ASSET_ORIGIN &&                  // scheme + host + port, case-normalized
    u.pathname.startsWith(ASSET_PATH) &&          // normalized path: dot segments already resolved
    !/%2f|%5c/i.test(u.pathname) &&               // encoded separators a CDN might decode later
    !u.username && !u.password && !u.search && !u.hash
  );
}

const SafeImage = Image.extend({
  parseHTML() {
    // pasted/parsed <img> from any other origin is dropped instead of fetched
    return [{ tag: 'img[src]', getAttrs: (el) => (isOwnAsset((el as HTMLElement).getAttribute('src')) ? null : false) }];
  },
}).configure({ allowBase64: false });
```

Pair `isOwnAsset` with the server check in §1 (stored JSON skips `parseHTML`), and have export jobs
read the object from storage by key rather than fetching the URL. Serving those assets safely —
object-key ownership, content type, `Content-Disposition` — is `secaudit:object-storage-security`.

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'allowBase64 *: *true' --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules 'Image\.(configure|extend)\(' --include='*.ts' --include='*.tsx' .   # then: is there a src check?
grep -rnE --exclude-dir=node_modules 'fetch\([^)]*\.src\b|attrs\??\.src' --include='*.ts' .                 # server fetching document images
grep -rnE --exclude-dir=node_modules 'puppeteer|playwright|page\.setContent|wkhtmltopdf' --include='*.ts' --include='*.js' .
```

## 5. The Paste and Drop Path

**Why it matters:** paste is the one input path where a victim imports attacker HTML into their
own session — copied from a malicious page, a shared doc, or an email. ProseMirror parses pasted
HTML with the editor schema, so the schema's `parseHTML` rules and the Link/Image gates (§3, §4)
apply — but any custom paste handler that builds content itself can skip all of them, and
ProseMirror's own paste code has had an XSS.

**ProseMirror hooks (`EditorProps`, prosemirror.net reference):** `transformPastedHTML(html, view)`
transforms the raw pasted HTML string before it is parsed; `handlePaste(view, event, slice)`
overrides paste entirely (`slice` is the already-parsed content, `event` exposes the raw clipboard);
`transformPasted(slice, view, plain)` transforms pasted *or dropped* content before it is applied;
`handleDrop` overrides drop. In TipTap these go in `editorProps`.

**What to look for:**

- A `handlePaste` that reads `clipboardData.getData('text/html')` and inserts it via
  `insertContent(html)`, `setContent`, or `innerHTML` without running the same allowlist used for
  stored content. One allowlist function, called from paste, import (§7), and the save route (§1).
- A `transformPastedHTML` that only rewrites styles (Google Docs/Word cleanup) and is mistaken for
  sanitization; it must return HTML the schema will still filter, not be the filter.
- A "native paste" bypass keyed on a marker the attacker controls — for example skipping the
  allowlist when the HTML `includes('data-pm-slice')` (ProseMirror's own clipboard marker) or a
  custom `data-from-our-app` attribute. Any page can put that attribute in clipboard HTML. If you
  keep a native path for internal copy/paste, it must still end in the schema's parse rules (never
  `innerHTML`), with the §3/§4 gates installed.
- `handleDrop` uploading dropped files: the inserted `src` must be the URL your upload route
  returned and verified (§4), not the file name or a `blob:`/`data:` URL that gets persisted.
- The prosemirror-view version. CVE-2026-104847 (GHSA-c8x8-7fp4-3x9w): pasting attacker-provided
  HTML into any ProseMirror-based editor could run attacker JavaScript in the page; fixed 1.42.3 in
  prosemirror-view, and the advisory lists no workaround. TipTap pulls it in transitively through
  `@tiptap/pm` with a caret range, so refreshing the lockfile is usually enough — confirm with
  `npm ls prosemirror-view`. Floor: `prosemirror-view@1.42.3`.

```ts
// BAD — pasted HTML inserted as-is; "our own clipboard" detected by a marker anyone can forge
const editor = useEditor({
  extensions,
  editorProps: {
    handlePaste: (view, event) => {
      const html = event.clipboardData?.getData('text/html');
      if (!html || html.includes('data-pm-slice')) return false; // forged marker → native path
      editor?.commands.insertContent(html);  // custom nodes' parseHTML (§6) decide what survives
      return true;
    },
  },
});
```

```ts
// GOOD — every pasted HTML string goes through the same server-grade allowlist, then the schema
import { useEditor } from '@tiptap/react';
import { Slice } from '@tiptap/pm/model';
import { htmlToSafeDoc } from '@/editor/sanitize';   // allowlist sanitizer (§8/§9) → JSON, URLs checked (§3/§4)

const editor = useEditor({
  extensions,
  editorProps: {
    handlePaste: (view, event) => {
      const data = event.clipboardData;
      if (!data || data.files.length > 0) return false; // file pastes fall through to your upload path
      const html = data.getData('text/html');
      if (!html) return false;                 // plain text: ProseMirror's text path, no markup
      const doc = view.state.schema.nodeFromJSON(htmlToSafeDoc(html));
      view.dispatch(view.state.tr.replaceSelection(Slice.maxOpen(doc.content)).scrollIntoView());
      return true;
    },
  },
});
```

Returning `true` for every clipboard that carries `text/html` also swallows pastes that carry files
(a copied image often brings an HTML wrapper too), so the files check comes first and lets those
pastes reach your upload handler (§4), which inserts only the URL it verified.

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'handlePaste|transformPastedHTML|transformPasted\b|handleDrop' --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules "getData\(['\"]text/html['\"]\)" --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules 'data-pm-slice' --include='*.ts' --include='*.tsx' .   # marker-based "trusted paste" bypass
npm ls prosemirror-view 2>/dev/null
```

## 6. Custom Nodes and Marks

**Why it matters:** built-in extensions ship with their gates; custom ones ship with whatever the
author wrote in an afternoon. A custom node's `addAttributes` decides which attributes survive
parsing, and its `renderHTML` decides which become live DOM attributes — copy `style`, `href`,
`src`, or anything starting with `on` from the stored attributes into the output and the node is a
stored-XSS gadget that every renderer (§2) will faithfully reproduce.

**What to look for:**

- `renderHTML` returning an attribute object built from attribute values with no allowlist: a
  `style` string (CSS overlay/phishing even without script), an `href`/`src` with no scheme check,
  or spreading a whole attribute object (`{ ...node.attrs }`, `HTMLAttributes` from JSON) so any key —
  `onerror`, `srcdoc`, `formaction` — reaches the DOM.
- `parseHTML` / attribute `parseHTML` returning raw `getAttribute('style' | 'href' | 'src' | 'on*')`
  — pasted or imported HTML (§5, §7) then stores it. Prefer parsing into a constrained value
  (`kind` from a fixed enum, a number, a validated URL) and declaring `validate` on the attribute.
- `addGlobalAttributes` that adds `style` or `class` to `'*'` or to many types from parsed HTML.
- A node view (`addNodeView`, `ReactNodeViewRenderer`) that renders an attribute through
  `innerHTML` or `dangerouslySetInnerHTML` — node views bypass `renderHTML` in the editor.
- `mergeAttributes` fed attribute objects that came from JSON (imported documents, CMS/API/tenant
  config, AI output). GHSA-cp6q-959q-f8rh (`@tiptap/core`): `mergeAttributes()` assigned an own
  `__proto__` key with ordinary bracket assignment, giving the merged object an attacker-chosen
  prototype that `Object.keys` cannot see; ProseMirror's `DOMSerializer` enumerates with `for...in`,
  so inherited `src`/`onerror` values became real DOM attributes and the handler ran. Introduced in
  2.0.0-alpha.0; OSV lists 3.30.4 as the only fixed version. The 2.x line also carries the guard:
  the `v2-latest` release 2.27.3 (2026-09-04) defines an own `__proto__` key as a plain data
  property in `mergeAttributes`, which 2.27.2 does not — verified in the published package, ahead of
  the OSV record. A 2.x editor can take 2.27.3 or move to 3.30.4 or later; scanners keyed on OSV will
  still flag 2.27.3 until the record is updated. The advisory notes the standard fixed schemas drop unknown attributes, so exposure
  needs an untrusted object reaching `mergeAttributes` or a dynamic/custom schema that preserves it.
- Markdown attribute parsing. GHSA-j95f-988m-3j2f (`@tiptap/core`): quadratic ReDoS in the
  Pandoc-style block-attribute and inline-shortcode parsers behind `createBlockMarkdownSpec`,
  `createAtomBlockMarkdownSpec`, and `createInlineMarkdownSpec`; affects 3.7.0 up to the fix in
  3.30.5, so the 2.x line is not exposed. A single crafted Markdown document (tens of KB) costs seconds of CPU per parse — a
  denial-of-service on any server that parses user Markdown into a TipTap document.
- Floor for both on 3.x: `@tiptap/core@3.30.5`.

```ts
// BAD — attributes copied verbatim from parsed HTML and stored JSON into the DOM
import { Node, mergeAttributes } from '@tiptap/core';

export const Callout = Node.create({
  name: 'callout',
  group: 'block',
  content: 'block+',
  addAttributes: () => ({
    style: { default: null, parseHTML: (el) => el.getAttribute('style') },   // any CSS, from any paste
    href: { default: null, parseHTML: (el) => el.getAttribute('data-href') }, // no scheme check
    extra: { default: {} },                                                     // arbitrary object
  }),
  parseHTML: () => [{ tag: 'aside[data-callout]' }],
  renderHTML: ({ node, HTMLAttributes }) =>
    ['aside', mergeAttributes(HTMLAttributes, node.attrs.extra, { 'data-callout': '' }), 0],
});
```

```ts
// GOOD — constrained values in, a fixed attribute shape out
import { Node, mergeAttributes } from '@tiptap/core';
import { isSafeHref } from '@/editor/urls';        // §3

const KINDS = ['note', 'tip', 'warning'] as const;
type Kind = (typeof KINDS)[number];
const asKind = (v: unknown): Kind => (KINDS.includes(v as Kind) ? (v as Kind) : 'note');

export const Callout = Node.create({
  name: 'callout',
  group: 'block',
  content: 'block+',
  addAttributes: () => ({
    kind: {
      default: 'note',
      validate: (v: unknown) => { if (!KINDS.includes(v as Kind)) throw new RangeError('kind'); },
      parseHTML: (el) => asKind(el.getAttribute('data-kind')),
      renderHTML: (a) => ({ 'data-kind': asKind(a.kind) }),       // a class/data value from a fixed set
    },
    href: {
      default: null,
      parseHTML: (el) => { const h = el.getAttribute('data-href'); return isSafeHref(h) ? h : null; },
      renderHTML: (a) => (isSafeHref(a.href) ? { 'data-href': a.href } : {}),
    },
  }),
  parseHTML: () => [{ tag: 'aside[data-callout]' }],
  renderHTML: ({ HTMLAttributes }) => ['aside', mergeAttributes(HTMLAttributes, { 'data-callout': '' }), 0],
});
```

Grep heuristics:

```bash
grep -rlnE --exclude-dir=node_modules '(Node|Mark|Extension)\.create\(|addAttributes|addGlobalAttributes' --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules "getAttribute\(['\"](style|href|src|on[a-z]+)['\"]\)" --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules "['\"]?style['\"]? *: *[A-Za-z_.]*attrs|\.\.\.(node\.)?attrs\b" --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules 'mergeAttributes\(' --include='*.ts' --include='*.tsx' .     # then: can any argument come from JSON?
grep -rnE --exclude-dir=node_modules 'create(AtomBlock|Block|Inline)MarkdownSpec' --include='*.ts' --include='*.tsx' .
grep -rnE --exclude-dir=node_modules 'addNodeView|ReactNodeViewRenderer|VueNodeViewRenderer' --include='*.ts' --include='*.tsx' .  # node views bypass renderHTML
```

<!-- sections 7-11: step 2 -->
