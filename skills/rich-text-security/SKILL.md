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

## 7. Document Import: mammoth (.docx → HTML)

**Why it matters:** a .docx is a zip of XML written by whoever sent it, and mammoth's own README
says it "performs no sanitisation of the source document." Import runs on your server, so a crafted
document can attack the server (file read, resource exhaustion) as well as every later reader
(the HTML it emits is attacker-shaped).

**What mammoth does with hostile input** (verified against mammoth 1.10.0 and 1.13.0 with a
crafted .docx):

- **Hyperlinks pass through verbatim.** A relationship target of `javascript:alert(document.domain)`
  comes out as `<a href="javascript:alert(document.domain)">` in every version — the README lists
  this case explicitly.
- **External images read local files.** CVE-2025-11849 (GHSA-rmjr-87wv-gf87): an image that uses
  `r:link` (an external reference) instead of `r:embed` makes mammoth resolve the URI to a path,
  read it, and inline it as a base64 `data:` URI in the output — arbitrary file read on the
  converting server, returned to the uploader, or a hang/memory blow-up via `/dev/zero` or
  `/dev/random`. Versions from 0.3.25 are in range; fixed 1.11.0, which adds `externalFileAccess`
  (default `false`). On 1.13.0 the same document yields an error message ("external file access is
  disabled") instead of the file. Setting `externalFileAccess: true` restores the old behaviour.
- **Images become `data:` URIs by default.** The default `convertImage` (`mammoth.images.dataUri`)
  inlines every embedded picture, so a 20 MB image becomes a 27 MB attribute in a stored row. If
  the HTML then goes through TipTap's Image extension with `allowBase64: false` the pictures vanish
  — and "fixing" that by flipping `allowBase64: true` reopens §4.
- **Pathological documents.** The README warns it is "likely possible to craft a source document
  that causes high CPU or memory usage" and suggests a separate thread with a timeout. A zip bomb
  (tiny upload, gigabytes inflated) adds the classic decompression DoS on top.

**What to look for:** a `mammoth` version below 1.11.0; `externalFileAccess: true` anywhere;
`convertToHtml` output stored or rendered without the §8/§9 sanitizer; no `convertImage`, so
`data:` URIs are stored; no upload size cap, no inflated-size/entry-count check, and conversion on
the request thread with no timeout.

Floor: `mammoth@1.11.0`.

```ts
// BAD — external files on, output stored as-is, conversion on the request thread
import mammoth from 'mammoth';

export async function POST(req: Request) {
  const buffer = Buffer.from(await req.arrayBuffer());              // no size cap
  const { value: html } = await mammoth.convertToHtml({ buffer }, { externalFileAccess: true });
  await db.doc.create({ data: { html } });                          // javascript: links, data: images, maybe /etc/passwd
  return Response.json({ ok: true });
}
```

```ts
// GOOD — bounded input, no external files, images re-stored on your origin, output sanitized
import mammoth from 'mammoth';
import { htmlToSafeDoc } from '@/editor/sanitize';   // §8 pipeline → validated editor JSON (§1)
import { storeImage } from '@/storage';              // returns a URL that passes isOwnAsset (§4)

const MAX_DOCX_BYTES = 10 * 1024 * 1024;
const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);

export async function importDocx(buffer: Buffer) {   // run this inside a worker with a timeout (below)
  if (buffer.byteLength > MAX_DOCX_BYTES) throw new Error('too large');
  // Also bound the zip before mammoth parses it: total inflated bytes and entry count (zip bomb).
  // This is the real zip-bomb control — the worker's resourceLimits cap only the V8 heap, not
  // off-heap Buffers an inflating archive allocates.
  const { value } = await mammoth.convertToHtml({ buffer }, {
    externalFileAccess: false,                       // the 1.11.0+ default — stated so a refactor can't flip it
    convertImage: mammoth.images.imgElement(async (image) => {
      if (!IMAGE_TYPES.has(image.contentType)) return { src: '' };   // dropped by the sanitizer / isOwnAsset
      return { src: await storeImage(await image.readAsBuffer(), image.contentType) };
    }),
  });
  return htmlToSafeDoc(value);                       // mammoth output is unsanitized: always sanitize
}
```

```ts
// GOOD — CPU/memory bound: the conversion dies with its worker, not with your server
import { Worker } from 'node:worker_threads';

export function importInWorker(buffer: Buffer, ms = 15_000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./import-docx.worker.js', import.meta.url), {
      workerData: buffer,
      resourceLimits: { maxOldGenerationSizeMb: 512 },
    });
    const timer = setTimeout(() => { void worker.terminate(); reject(new Error('import timed out')); }, ms);
    worker.once('message', (doc) => { clearTimeout(timer); resolve(doc); });
    worker.once('error', (err) => { clearTimeout(timer); reject(err); });
  });
}
```

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules "from ['\"]mammoth['\"]|require\(['\"]mammoth['\"]\)" --include='*.ts' --include='*.js' .
grep -rnE --exclude-dir=node_modules 'externalFileAccess *: *true' --include='*.ts' --include='*.js' .
grep -rlE --exclude-dir=node_modules 'convertToHtml\(' --include='*.ts' --include='*.js' . \
  | xargs grep -LE 'sanitize|DOMPurify|rehype-sanitize|htmlToSafeDoc' 2>/dev/null   # converters with no sanitizer in the file
grep -rnE --exclude-dir=node_modules 'convertImage|images\.dataUri' --include='*.ts' --include='*.js' .
npm ls mammoth 2>/dev/null
```

## 8. The unified / remark / rehype Pipeline

**Why it matters:** `rehype-sanitize` (a wrapper around `hast-util-sanitize`) is safe with its
defaults — and the README is blunt about the rest: "improper use of `rehype-sanitize` can open you
up to a cross-site scripting (XSS) attack. Use `rehype-sanitize` after the last unsafe thing:
everything after `rehype-sanitize` could be unsafe." Both halves fail in practice: the schema gets
widened until "the formatting works," and plugins get appended after the sanitizer.

**Schema misconfiguration** (each one below was run through rehype-sanitize 6.0.0 to confirm the
payload survives):

- `attributes['*']` extended with `'style'` — `<a style="position:fixed;inset:0">` survives, a
  full-page overlay with no script. Adding `'className'` to `'*'` is the same class of problem
  under utility CSS; prefer per-tag regex allowlists such as `code: [['className', /^language-/]]`.
- `protocols.href` / `protocols.src` extended with `'javascript'` or `'data'` — `javascript:` links
  survive from both raw HTML and Markdown link syntax.
- `clobberPrefix: ''` (or a trimmed `clobber` list) while `id` / `name` are allowed — the default
  prefixes them with `user-content-`; without it `<img name="config">` defines `document.config`
  and user content can shadow globals your scripts read (DOM clobbering). The rehype-sanitize
  README's own example is heading ids.
- `tagNames` extended with `iframe`, `object`, `embed`, `form`, `svg`/`math` subtrees, `style`, or
  `script` — or `strip` emptied so `script` contents survive as text.
- `allowComments` / `allowDoctypes` turned on for "fidelity" — rarely needed, never for user input.

**Plugin order:**

- `rehype-raw` must come **before** `rehype-sanitize`. In the reverse order the sanitizer drops
  the unparsed raw nodes and the embedded HTML silently disappears — safe, but broken, and the
  usual "fix" is the real finding: deleting the sanitizer, or rendering without it via
  `remark-rehype` + `rehype-stringify` both set to `allowDangerousHtml: true`, which ships the raw
  HTML (`<script>`, `onerror`, `javascript:`) untouched. Any pipeline with `allowDangerousHtml` on
  the stringify step and no sanitizer after `rehype-raw` is a finding.
- Nothing that adds elements, attributes, or URLs runs **after** `rehype-sanitize`: heading-id and
  autolink-heading plugins, syntax highlighters, link rewriters, custom "embed" plugins. A test
  plugin that set `onmouseover` after the sanitizer shipped it to the output.
- remark directives (`remark-directive`: `:text`, `::leaf`, `:::container`). A handler that maps a
  directive to `data.hName` / `data.hProperties = node.attributes` copies attacker-chosen
  attributes (`style`, `onclick`, `href="javascript:..."`) onto an element. Harmless only if the
  sanitizer runs after it; map known directive names to fixed elements and pick attributes from an
  allowlist anyway.
- mdast-util-to-hast version. CVE-2025-66400 (GHSA-4fh9-h7wg-q85m): a fenced-code info string with
  character references (`` ```js&#x20;xss ``) produced unprefixed extra classes
  (`class="language-js xss"`) that pick up your page's CSS and JS hooks; 13.0.0 is in range and it
  was fixed 13.2.1. It arrives transitively through `remark-rehype`, so confirm with
  `npm ls mdast-util-to-hast`. Floor: `mdast-util-to-hast@13.2.1`.

Markdown rendered from LLM output (`react-markdown` with `rehype-raw`, chat UIs) is the same
pipeline with a different author; `secaudit:ai-integration` covers that case.

```ts
// BAD — schema widened, plugins after the sanitizer
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkRehype from 'remark-rehype';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize, { defaultSchema } from 'rehype-sanitize';
import rehypeSlug from 'rehype-slug';
import rehypeStringify from 'rehype-stringify';

const loose = {
  ...defaultSchema,
  clobberPrefix: '',                                          // ids/names now clobber globals
  attributes: { ...defaultSchema.attributes, '*': [...(defaultSchema.attributes?.['*'] ?? []), 'className', 'style'] },
  protocols: { ...defaultSchema.protocols, href: [...(defaultSchema.protocols?.href ?? []), 'javascript'] },
};

export const render = (md: string) => String(unified()
  .use(remarkParse)
  .use(remarkRehype, { allowDangerousHtml: true })
  .use(rehypeSanitize, loose)                                 // widened: javascript: links survive
  .use(rehypeRaw)                                             // wrong order: raw HTML already dropped, so it
                                                              //   "doesn't work" — next someone deletes the sanitizer
  .use(rehypeSlug)                                            // adds unprefixed ids after sanitize (clobbering)
  .use(rehypeStringify)
  .processSync(md));
```

```ts
// GOOD — narrow schema, raw before sanitize, everything that adds markup before sanitize
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkRehype from 'remark-rehype';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize, { defaultSchema, type Options as SanitizeSchema } from 'rehype-sanitize';
import rehypeSlug from 'rehype-slug';
import rehypeStringify from 'rehype-stringify';

const schema: SanitizeSchema = {
  ...defaultSchema,                                           // keeps clobber, clobberPrefix, strip: ['script']
  tagNames: ['p', 'br', 'h1', 'h2', 'h3', 'h4', 'strong', 'em', 'del', 'code', 'pre', 'blockquote',
    'ul', 'ol', 'li', 'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr'],
  attributes: {
    a: ['href', 'title'], img: ['src', 'alt', 'title'], ol: ['start'], th: ['align'], td: ['align'],
    h1: ['id'], h2: ['id'], h3: ['id'], h4: ['id'],           // rehype-slug ids, prefixed by clobberPrefix
    code: [['className', /^language-[a-z0-9-]+$/]],
  },
  protocols: { href: ['https', 'mailto'], src: ['https'] },
};

export const render = (md: string) => String(unified()
  .use(remarkParse)
  .use(remarkRehype, { allowDangerousHtml: true })
  .use(rehypeRaw)                                             // parse embedded HTML into real nodes...
  .use(rehypeSlug)                                            // ...run everything that adds markup...
  .use(rehypeSanitize, schema)                                // ...then sanitize, last
  .use(rehypeStringify)                                       // no allowDangerousHtml on output
  .processSync(md));
```

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'allowDangerousHtml|rehype-?[Rr]aw|skipHtml *: *false' --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rnE --exclude-dir=node_modules '\.use\((rehypeRaw|rehypeSanitize|rehypeStringify|remarkRehype|rehype[A-Z][A-Za-z]*)' --include='*.ts' --include='*.tsx' --include='*.js' .   # read the order per file
grep -rnE --exclude-dir=node_modules 'rehypePlugins' --include='*.ts' --include='*.tsx' --include='*.js' .   # react-markdown: read the array order
grep -rnE --exclude-dir=node_modules "clobberPrefix *: *['\"]['\"]|clobber *: *\[\]" --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rnE --exclude-dir=node_modules -A10 'defaultSchema' --include='*.ts' --include='*.tsx' --include='*.js' . \
  | grep -E "'style'|\"style\"|className|javascript|'data'|\"data\"|iframe|allowComments"
grep -rnE --exclude-dir=node_modules 'containerDirective|leafDirective|textDirective|hProperties' --include='*.ts' --include='*.tsx' --include='*.js' .
npm ls mdast-util-to-hast 2>/dev/null
```

## 9. Alternative Sanitizers: DOMPurify and sanitize-html

**Why it matters:** both are good libraries whose security depends on staying current and on not
being configured open. Each has shipped a steady run of bypass fixes, and each exposes options
whose whole purpose is to let more through.

**DOMPurify** (`dompurify`, `isomorphic-dompurify`):

- Version. CVE-2026-109344 (GHSA-p98j-92pf-mc4p): an `afterSanitize*` hook that removes nodes in
  `IN_PLACE` mode left event handlers armed on the detached subtree; 3.4.13 is in range; fixed
  3.4.16. CVE-2026-109345 (GHSA-6688-9rhm-gjv2): `IN_PLACE` returned a force-removed rawtext root
  whose text reparses as markup; fixed 3.4.16. Earlier 3.4.x releases carry more: OSV lists six
  open advisories against 3.4.7 alone. Floor: `dompurify@3.4.16`.
- `IN_PLACE` on attacker-supplied DOM. GHSA-x4vx-rjvf-j5p4 (CVE-2026-65901): `IN_PLACE` trusted an
  attacker-controlled `nodeName`, so a real `<script>` could be kept. OSV records 3.4.6 as the last
  affected version (3.4.7 and later are outside the range) and names no fixed release. Three of the advisories above are `IN_PLACE`-only:
  sanitize **strings** and insert the result, rather than sanitizing a live tree you were handed.
- `setConfig` is global and sticky. The README: "once it is set, all extra configuration
  parameters passed to `DOMPurify.sanitize` are ignored." One module calling
  `DOMPurify.setConfig({ ADD_TAGS: ['iframe'] })` on the shared instance overrides the strict
  per-call config of every other caller in the process — confirmed: a later call passing
  `ALLOWED_TAGS: ['a']` still returned `<img>` and `<iframe>`.
- Widening options: `ADD_TAGS`, `ADD_ATTR` (`ADD_ATTR: ['onerror']` keeps the handler),
  `ALLOWED_URI_REGEXP` loosened, `ALLOW_UNKNOWN_PROTOCOLS`, `ADD_DATA_URI_TAGS`,
  `CUSTOM_ELEMENT_HANDLING` with permissive patterns, `ALLOW_ARIA_ATTR`/`ALLOW_DATA_ATTR` relied on
  by code that later reads `data-*` as a URL.
- Hooks that *add* or *copy* after the checks. An `afterSanitizeAttributes` hook that sets `href`
  from `data-href` writes `javascript:` after DOMPurify's URI check ran — confirmed. Hooks that only
  *remove* (drop a `src` that fails `isOwnAsset`, §4) are fine; hooks that add are a bypass.
- `data:` URIs on `img`, `audio`, `video`, `source`, `image`, `track` are allowed by default
  regardless of `ALLOWED_URI_REGEXP` (the `DATA_URI_TAGS` default). If images must come from your
  asset origin, enforce that after sanitizing (removal hook or the §1 check).
- `isomorphic-dompurify` on the server is DOMPurify plus **jsdom** (4.6.0 depends on
  `jsdom ^30.1.3`); older 2.x releases depend on `jsdom ^23.0.0` and `dompurify ^3.0.6`. The caret
  range means your lockfile decides both versions — run `npm ls dompurify jsdom`. Never configure
  that jsdom with `runScripts`.

**sanitize-html** (`sanitize-html`):

- Version. CVE-2026-53606 (GHSA-vccv-cmxp-4j9h): incomplete scheme validation let `javascript:`
  through `action`, `formaction`, `data`, `poster`, and `background`; 1.18.0 is in range; fixed
  2.17.5. CVE-2026-63670 (GHSA-jxwj-j7wr-gfrw): mutation XSS / `allowedTags` bypass via a literal
  `</textarea/>` solidus close; fixed 2.17.6. CVE-2026-84371 (GHSA-g8qq-57p8-ggw5): stored XSS via
  an SVG SMIL URI-list scheme-policy bypass; 1.9.0 is in range; fixed 2.17.7. Floor:
  `sanitize-html@2.17.7`.
- `allowedTags: false` / `allowedAttributes: false` mean **allow everything** — confirmed: with
  both, `<img onerror>` and `<iframe srcdoc>` survive.
- `allowVulnerableTags: true` silences the warning for `style`/`script` in `allowedTags`;
  `allowedSchemes` / `allowedSchemesByTag` extended with `javascript` or `data`;
  `allowedSchemesAppliedToAttributes` trimmed; `allowProtocolRelative` left on when only your
  origin should load; `allowedStyles` with broad regexes; `transformTags` that add attributes
  (transforms run inside the sanitizer, but an attribute they set from input text is attacker data).
- `parser: { lowerCaseAttributeNames: false }` or other parser options changed to "preserve" input
  — exactly the parser-differential surface mutation XSS lives in.

```ts
// BAD — one shared instance, global config widened, an attribute-copying hook
import DOMPurify from 'isomorphic-dompurify';

DOMPurify.setConfig({ ADD_TAGS: ['iframe'], ADD_ATTR: ['allow', 'onerror'] }); // now every caller's config is ignored
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.hasAttribute('data-href')) node.setAttribute('href', node.getAttribute('data-href')!); // after the URI check
});
export const clean = (html: string) => DOMPurify.sanitize(html, { ALLOWED_TAGS: ['p', 'a'] });   // ignored
```

```ts
// GOOD — a private instance, an explicit allowlist per call, a hook that only removes
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { isOwnAsset } from '@/editor/urls';          // §4

const purify = createDOMPurify(new JSDOM('').window as unknown as Window & typeof globalThis);
purify.addHook('afterSanitizeAttributes', (node) => {
  if (node.hasAttribute('src') && !isOwnAsset(node.getAttribute('src'))) node.removeAttribute('src');
});

const CONFIG = {
  ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'h2', 'h3', 'img'],
  ALLOWED_ATTR: ['href', 'src', 'alt', 'title'],
  ALLOWED_URI_REGEXP: /^(?:https:|mailto:|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,  // https, mailto, relative
};
export const clean = (html: string): string => purify.sanitize(html, CONFIG);   // strings in, strings out — no IN_PLACE
```

```ts
// GOOD — sanitize-html with explicit lists and per-tag schemes
import sanitizeHtml from 'sanitize-html';

export const clean = (html: string): string => sanitizeHtml(html, {
  allowedTags: ['p', 'br', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'h2', 'h3', 'img'],
  allowedAttributes: { a: ['href', 'title'], img: ['src', 'alt', 'title'] },
  allowedSchemes: ['https', 'mailto'],
  allowedSchemesByTag: { img: ['https'] },          // no data: images
  allowProtocolRelative: false,
});
```

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'IN_PLACE|\.setConfig\(|\.addHook\(|ADD_TAGS|ADD_ATTR|ADD_DATA_URI_TAGS|ALLOW_UNKNOWN_PROTOCOLS|ALLOWED_URI_REGEXP|CUSTOM_ELEMENT_HANDLING' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rnE --exclude-dir=node_modules 'allowedTags *: *false|allowedAttributes *: *false|allowVulnerableTags|allowedSchemes|allowProtocolRelative|allowedStyles|transformTags' \
  --include='*.ts' --include='*.tsx' --include='*.js' .
grep -rnE --exclude-dir=node_modules "runScripts *: *['\"]" --include='*.ts' --include='*.js' .
npm ls dompurify isomorphic-dompurify jsdom sanitize-html 2>/dev/null
```

## 10. Blast Radius: Where Stored Rich Content Runs

**Why it matters:** every bypass in §1–§9 ends the same way — attacker markup rendered on your
application's origin, with the viewer's session. In a shared or public document that is every
reader; in a multi-tenant product it is every tenant's admins who open the shared template, the
support agent viewing a customer's page, or the platform owner previewing a tenant site. The
sanitizer is the primary control; this section is what limits the damage when it misses.

**What to look for:**

- No Content-Security-Policy, or one with `'unsafe-inline'` in `script-src`, on the pages that
  render user documents. A strict nonce- or hash-based `script-src` turns an injected
  `onerror=` or `javascript:` link into a CSP violation report instead of code execution. Header
  setup and nonce wiring are `secaudit:deployment`.
- User documents rendered on the same origin as the admin console, billing, or API — the injected
  script can call those with the viewer's cookies. Where the product allows it, serve user-authored
  pages from a separate origin (a dedicated user-content domain, or per-tenant subdomains on a
  registrable domain listed on the Public Suffix List so cookies cannot be shared), or render
  untrusted HTML inside a `sandbox`ed `<iframe>` without `allow-same-origin`.
- Previews and admin views that render tenant- or user-authored HTML on the platform's main
  origin "just for the preview." Cross-tenant stored XSS: an author in tenant A writes the
  payload, a privileged user in tenant B (or a platform admin) executes it on an origin where they
  hold more privilege than the author. Treat any surface where one tenant's content reaches
  another tenant's users as the high-severity case, and check that tenant scoping on the document
  *read* path is server-side (`secaudit:web-vulns` IDOR, `secaudit:privilege-escalation`).
- `<iframe srcdoc>` built from user HTML without `sandbox`, or with
  `sandbox="allow-scripts allow-same-origin"` — a `srcdoc` frame shares the page's origin, and MDN
  warns that this pair then lets the embedded document remove the sandbox attribute.
- Sensitive tokens readable by script on the content origin (`localStorage` session tokens, a
  non-`HttpOnly` session cookie) — XSS on that origin becomes account takeover instead of
  in-page defacement.

```tsx
// BAD — tenant-authored HTML previewed on the platform admin origin, no sandbox
export function TenantPagePreview({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;  // runs with the platform admin's session
}
```

```tsx
// GOOD — sanitized, then isolated: an opaque-origin frame with scripts off
import { clean } from '@/editor/sanitize';          // §8 / §9

export function TenantPagePreview({ html }: { html: string }) {
  return (
    <iframe
      title="Page preview"
      sandbox=""                                     // no allow-scripts, no allow-same-origin: opaque origin
      srcDoc={clean(html)}
      referrerPolicy="no-referrer"
    />
  );
}
```

Grep heuristics:

```bash
grep -rnE --exclude-dir=node_modules 'Content-Security-Policy|contentSecurityPolicy|script-src' --include='*.ts' --include='*.js' --include='*.mjs' --include='*.json' .
grep -rnE --exclude-dir=node_modules "unsafe-inline|unsafe-eval" --include='*.ts' --include='*.js' --include='*.mjs' --include='*.json' .
grep -rnE --exclude-dir=node_modules 'srcdoc|srcDoc|sandbox=' --include='*.ts' --include='*.tsx' --include='*.vue' --include='*.svelte' .
grep -rnE --exclude-dir=node_modules 'allow-scripts[^"]*allow-same-origin|allow-same-origin[^"]*allow-scripts' --include='*.tsx' --include='*.vue' --include='*.html' .
```

## Rich-Text Footgun Checklist

- §1 The save route stores `editor.getHTML()` (or any client HTML) without a server-side allowlist
  sanitizer, or stores editor JSON without re-parsing it against the schema.
- §1 Document attributes beyond `href`/`src` (`class`, `target`, `rel`, `title`, `width`) accepted
  as free strings instead of pinned with `validate` or stripped on the server.
- §1 Stored HTML sanitized only under an old sanitizer version or config, with no re-sanitize or
  re-render from JSON on read.
- §2 Stored or `generateHTML` output rendered through `dangerouslySetInnerHTML` / `v-html` /
  `{@html}` / `innerHTML` without a sanitizer at render time.
- §2 Server-side `@tiptap/html` with happy-dom below 20.8.9, `@tiptap/html` before 3.17.1, or a
  hand-built happy-dom/jsdom `Window` that evaluates scripts.
- §3 Link `isAllowedUri` returning `true`, `protocols` extended with `javascript`/`data`, or
  `shouldAutoLink`/`validate` mistaken for the security gate.
- §3 A custom renderer or exporter reading `mark.attrs.href` without the shared `isSafeHref`.
- §4 `allowBase64: true`, no image `src` origin allowlist, or a server job that fetches document
  image URLs.
- §5 A paste handler that inserts clipboard HTML without the shared allowlist, or skips it on a
  forgeable marker like `data-pm-slice`; prosemirror-view below 1.42.3.
- §6 A custom node or mark copying `style`/`href`/`src`/`on*` or a whole attribute object into
  `renderHTML`, or a node view writing an attribute via `innerHTML`.
- §6 `mergeAttributes` fed JSON-derived objects on a `@tiptap/core` without the `__proto__` guard;
  `@tiptap/core` 3.7.0–3.30.4 parsing untrusted Markdown attributes.
- §7 mammoth below 1.11.0, `externalFileAccess: true`, mammoth output not sanitized, default
  `data:` URI images stored, or conversion with no size cap, zip check, worker, or timeout.
- §8 rehype-sanitize schema widened with `style`/`className` on `'*'`, `javascript`/`data`
  protocols, `clobberPrefix: ''`, or dangerous tags; mdast-util-to-hast below 13.2.1.
- §8 `rehype-raw` after `rehype-sanitize`, `allowDangerousHtml` output with no sanitizer after
  `rehype-raw`, or any plugin that adds markup running after the sanitizer; directive attributes
  copied to elements.
- §9 dompurify below 3.4.16 or sanitize-html below 2.17.7; `IN_PLACE` on attacker-supplied DOM.
- §9 DOMPurify `setConfig` on a shared instance, widening `ADD_*` options, or a hook that adds or
  copies attributes; sanitize-html with `allowedTags: false` / `allowedAttributes: false`.
- §10 No strict CSP on pages that render user documents, user content on the admin/API origin,
  tenant content previewed on the platform origin, or `sandbox="allow-scripts allow-same-origin"`.

## Cross-References

- `secaudit:web-vulns` — XSS fundamentals, URL-scheme blocking, SSRF controls for any server
  fetch of a document URL (§4), and IDOR on the document read path (§10).
- `secaudit:ai-integration` — Markdown rendering of LLM output, the same §8 pipeline with a
  model as the author.
- `secaudit:deployment` — Content-Security-Policy and the other response headers §10 relies on.
- `secaudit:object-storage-security` — the uploaded-asset origin §4 restricts images to: key
  ownership, content type, and safe serving.
- `secaudit:framework-versions` / `secaudit:supply-chain` — keeping the floors in this skill
  current, including transitive packages (`prosemirror-view`, `mdast-util-to-hast`, `jsdom`).
- `secaudit:rate-limiting` — import and render endpoints (§7) as CPU-expensive surfaces.

## Sources

- https://tiptap.dev/docs/editor/extensions/marks/link -- `isAllowedUri`, `protocols`, `shouldAutoLink`, `validate` deprecated
- https://tiptap.dev/docs/editor/extensions/nodes/image -- `allowBase64` (default false), `inline`
- https://tiptap.dev/docs/editor/api/utilities/html -- `generateHTML`/`generateJSON` from `@tiptap/core` (browser) vs `@tiptap/html` (server, virtual DOM)
- https://tiptap.dev/docs/editor/api/utilities/static-renderer -- `renderToReactElement`, `renderToHTMLString`, no DOM required
- https://tiptap.dev/docs/editor/core-concepts/schema -- schema derived from extensions; what the editor will parse
- https://tiptap.dev/docs/editor/core-concepts/persistence -- storing editor JSON vs HTML
- https://tiptap.dev/docs/editor/extensions/custom-extensions/create-new/node -- `addAttributes`, `parseHTML`, `renderHTML`
- https://tiptap.dev/docs/editor/extensions/custom-extensions/create-new/mark -- custom marks
- https://tiptap.dev/docs/editor/markdown -- TipTap Markdown support (the §6 Markdown attribute parsers)
- https://prosemirror.net/docs/ref/ -- `handlePaste`, `transformPastedHTML`, `transformPasted`, `handleDrop`; attribute `validate`; `Node.check`
- https://github.com/mwilliamson/mammoth.js -- Security section: no sanitisation, `javascript:` links, `externalFileAccess`, CPU/memory DoS; image converters
- https://github.com/rehypejs/rehype-sanitize -- "use rehype-sanitize after the last unsafe thing"; DOM clobbering example
- https://github.com/syntax-tree/hast-util-sanitize -- schema fields: `attributes`, `clobber`, `clobberPrefix`, `protocols`, `strip`, `tagNames`, `allowComments`
- https://github.com/syntax-tree/mdast-util-to-hast -- the mdast→hast step behind `remark-rehype`
- https://github.com/remarkjs/remark-rehype -- `allowDangerousHtml`
- https://github.com/rehypejs/rehype-raw -- parsing raw HTML nodes into hast
- https://github.com/remarkjs/remark-directive -- `:text`, `::leaf`, `:::container` directives
- https://github.com/cure53/DOMPurify -- configuration, `setConfig` semantics, hooks, `IN_PLACE` notes
- https://github.com/kkomelin/isomorphic-dompurify -- server-side DOMPurify on jsdom
- https://github.com/apostrophecms/sanitize-html -- `allowedTags`, `allowedAttributes`, `allowedSchemes`, `allowedSchemesByTag`, `allowVulnerableTags`
- https://github.com/advisories/GHSA-vhrc-hgrq-x75r -- @tiptap/extension-link `javascript:` via setLink/toggleLink (CVE-2025-14284)
- https://github.com/advisories/GHSA-c8x8-7fp4-3x9w -- prosemirror-view paste XSS (CVE-2026-104847)
- https://github.com/advisories/GHSA-cp6q-959q-f8rh -- @tiptap/core `mergeAttributes` `__proto__`
- https://github.com/advisories/GHSA-j95f-988m-3j2f -- @tiptap/core Markdown attribute ReDoS
- https://github.com/advisories/GHSA-96g7-g7g9-jxw8 -- happy-dom server-side `<script>` execution (CVE-2024-51757)
- https://github.com/advisories/GHSA-37j7-fg3j-429f -- happy-dom VM context escape (CVE-2025-61927)
- https://github.com/advisories/GHSA-qpm2-6cq5-7pq5 -- happy-dom `--disallow-code-generation-from-strings` insufficient (CVE-2025-62410)
- https://github.com/advisories/GHSA-6q6h-j7hj-3r64 -- happy-dom ES-module export-name injection (CVE-2026-33943)
- https://github.com/advisories/GHSA-w4gp-fjgq-3q4g -- happy-dom fetch credentials cookie leak (CVE-2026-34226)
- https://github.com/advisories/GHSA-rmjr-87wv-gf87 -- mammoth external image file read (CVE-2025-11849)
- https://github.com/advisories/GHSA-4fh9-h7wg-q85m -- mdast-util-to-hast unprefixed `class` (CVE-2025-66400)
- https://github.com/advisories/GHSA-p98j-92pf-mc4p -- DOMPurify `IN_PLACE` hook-detached subtree (CVE-2026-109344)
- https://github.com/advisories/GHSA-6688-9rhm-gjv2 -- DOMPurify `IN_PLACE` rawtext root (CVE-2026-109345)
- https://github.com/advisories/GHSA-x4vx-rjvf-j5p4 -- DOMPurify `IN_PLACE` attacker-controlled `nodeName` (CVE-2026-65901)
- https://github.com/advisories/GHSA-vccv-cmxp-4j9h -- sanitize-html `javascript:` via action/formaction/data/poster/background (CVE-2026-53606)
- https://github.com/advisories/GHSA-jxwj-j7wr-gfrw -- sanitize-html `</textarea/>` mutation XSS (CVE-2026-63670)
- https://github.com/advisories/GHSA-g8qq-57p8-ggw5 -- sanitize-html SVG SMIL URI-list bypass (CVE-2026-84371)
- https://github.com/ChALkeR/notes/blob/master/Improper-markup-sanitization.md -- the unsanitized-class class of bug behind CVE-2025-66400
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html -- XSS prevention; HTML sanitization guidance
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html -- why unprefixed `id`/`name` in user content matters
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html -- strict CSP as the §10 backstop
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy -- CSP directives
- https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe -- `sandbox` and `srcdoc`; why `allow-scripts` + `allow-same-origin` defeats the sandbox
- https://developer.mozilla.org/en-US/docs/Web/API/URL/URL -- URL parsing used by `isSafeHref` / `isOwnAsset`
- https://top10.owasp.org/2025/A05_2025-Injection/ -- A05:2025, where the XSS findings land
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ -- A01:2025, where image-fetch SSRF and cross-tenant reads land
