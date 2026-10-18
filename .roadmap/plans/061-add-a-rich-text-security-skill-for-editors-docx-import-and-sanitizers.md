---
id: 61
title: Add a rich-text-security skill for editors, docx import and sanitizers
type: feature
version: 3.12.0
status: active
created: 2026-10-17
---

# Plan 61: Add a rich-text-security skill for editors, docx import and sanitizers
> Type: feature · Target: v3.12.0

## 🎯 Target Scope & Boundaries
- **Core objective:** new `skills/rich-text-security/SKILL.md` auditing rich-text editors (TipTap/ProseMirror), document import (mammoth docx→HTML) and the unified/remark/rehype sanitize pipeline. Same house style as other skills (frontmatter name/description/license, numbered sections, BAD/GOOD snippets, grep heuristics, checklist, Sources).
- **Sections (with verified facts, OSV queried 2026-10-17):**
  1. Stored format & sanitize-on-write: editor JSON vs `getHTML()` HTML; the client editor schema is not a sanitizer (attacker POSTs HTML directly); sanitize server-side at the API on write, and again/escape on read if HTML is rendered; sanitizer drift across versions.
  2. Render sinks: `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, server-side `generateHTML`/`generateJSON` from `@tiptap/html` which uses happy-dom (happy-dom CVE-2024-51757 server-side `<script>` exec fixed 15.10.2; CVE-2025-61927 VM escape→RCE fixed 20.0.0; CVE-2026-34226 fixed 20.8.9). Prefer rendering JSON to React elements / `@tiptap/static-renderer`.
  3. TipTap Link: `isAllowedUri` returning true / extra `protocols`; `validate` is deprecated → `shouldAutoLink` (autolink only — not a security gate); GHSA-vhrc-hgrq-x75r / CVE-2025-14284 `javascript:` via setLink/toggleLink fixed @tiptap/extension-link 2.10.4.
  4. Image `src`: `allowBase64: true`, no protocol/host check, tracking pixels / mixed content, SSRF if the server fetches/renders images.
  5. Paste path: `handlePaste` / `transformPastedHTML` must route pasted HTML through the same allowlist; prosemirror-view GHSA-c8x8-7fp4-3x9w / CVE-2026-104847 paste XSS fixed 1.42.3.
  6. Custom nodes/marks: `addAttributes`/`renderHTML` emitting raw `style`/`on*`/`href` from attrs; @tiptap/core GHSA-cp6q-959q-f8rh `mergeAttributes` `__proto__` → XSS fixed 3.30.4; GHSA-j95f-988m-3j2f Markdown-attr ReDoS fixed 3.30.5.
  7. mammoth/docx import: GHSA-rmjr-87wv-gf87 / CVE-2025-11849 external `r:link` image reads arbitrary files (or /dev/zero DoS) and inlines as data URI, fixed 1.11.0 which adds `externalFileAccess` (default false) — flag `<1.11.0` or `externalFileAccess: true`; mammoth output is NOT sanitized (links with `javascript:`); default `convertImage` inlines data URIs; CPU/zip-bomb DoS → size cap + worker + timeout.
  8. unified pipeline: rehype-sanitize schema misconfig (`'*': ['className','style']`, allowing `style`, adding `javascript`/`data` to `protocols`, `clobberPrefix: ''` while `id`/`name` allowed → DOM clobbering); plugin order — sanitize after `rehype-raw` / `allowDangerousHtml`, and nothing that adds attributes runs after sanitize; mdast-util-to-hast GHSA-4fh9-h7wg-q85m / CVE-2025-66400 unprefixed `class` via character references fixed 13.2.1; remark directives (`:text`, `::leaf`, `:::container`) mapped to elements/attributes from directive attrs.
  9. Alternative sanitizers: DOMPurify floor 3.4.16 (CVE-2026-109344/109345); GHSA-x4vx-rjvf-j5p4 (IN_PLACE `nodeName`) has no fix → don't use IN_PLACE; hooks/ADD_TAGS/setConfig bypass class; sanitize-html floor 2.17.7 (CVE-2026-53606 action/formaction `javascript:` 2.17.5, CVE-2026-63670 2.17.6, CVE-2026-84371 SVG SMIL 2.17.7). Re-verify each on OSV before writing.
  10. Blast radius: stored XSS in shared/public/multi-tenant docs runs on the app origin → pair with strict CSP (deployment) and per-tenant origins where possible.
  11. Checklist + Sources.
- **Out of scope:** markdown-for-LLM output (ai-integration keeps it; add cross-link), generic XSS (web-vulns keeps it; add pointer).

## 🏗️ Architectural Blueprint
- **Files to create:** skills/rich-text-security/SKILL.md
- **Files to modify:** skills/web-vulns/SKILL.md (one pointer line in XSS section), skills/ai-integration/SKILL.md (cross-link near rehypeRaw ~L240-259), skills/framework-versions/SKILL.md (floors: mammoth 1.11.0, @tiptap/core 3.30.5, @tiptap/extension-link 2.10.4, prosemirror-view 1.42.3, mdast-util-to-hast 13.2.1, happy-dom 20.8.9, dompurify 3.4.16, sanitize-html 2.17.7), skills/audit/SKILL.md (tier dispatch trigger: tiptap/prosemirror/mammoth/rehype-sanitize/dompurify/sanitize-html in deps; OWASP map A05), README.md skill table, .claude-plugin/plugin.json keywords, SOURCES.md.

## ✅ Acceptance
- **Passes when:** the skill covers all 11 sections with concrete grep heuristics; every advisory ID/fixed version matches OSV at build time; audit dispatches it on those deps; README/plugin.json list it.
- **Passes when:** `python3 scripts/check-freshness.py` is clean.
- **Fails if:** generic XSS content is duplicated from web-vulns instead of linked, or any version claim disagrees with OSV.

## 🚶 Step-by-Step Checklist
- [x] Step 1: Write rich-text-security SKILL.md sections 1-6 (format, sinks, Link, Image, paste, custom nodes) -> target: skills/rich-text-security/SKILL.md
  > evidence: freshness --only fixclaims/cves/links/versions: All current (manifest drift expected until step 3); 24 grep heuristics tested BSD+GNU; GOOD snippets tsc --strict vs TipTap 3.32.0; spec MET; quality CONFIRMED after one fix loop (2.27.3 guard, isOwnAsset %2e%2e bypass, attr allowlist, 5 happy-dom advisories) (2026-10-17)
- [ ] Step 2: Write sections 7-11 (mammoth, unified pipeline, alt sanitizers, blast radius, checklist, sources) -> target: skills/rich-text-security/SKILL.md
- [ ] Step 3: Register: audit dispatch + OWASP map, README, plugin.json, cross-links, framework-versions floors, SOURCES; freshness green -> target: skills/audit/SKILL.md, README.md, .claude-plugin/plugin.json, skills/web-vulns/SKILL.md, skills/ai-integration/SKILL.md, skills/framework-versions/SKILL.md, SOURCES.md
