# Dynamic Verification Probes

Concrete recipes for confirming or refuting findings against a running app with the **Playwright
MCP**. Tools referenced by their short names: `browser_navigate`, `browser_evaluate`,
`browser_network_requests`, `browser_snapshot`, `browser_console_messages`, `browser_type`,
`browser_click`. (Your environment may namespace them, e.g. `…__browser_navigate`.)

**Before running any probe, clear the authorization gate in `SKILL.md`.** All recipes below are
read-only. Report each result as **Confirmed** / **Refuted** / **Inconclusive** with evidence.

---

## 1. Security headers — confirms `secaudit:deployment`

WSTG-CONF-07 (HSTS) and configuration testing. A missing header is only real if the *live*
response omits it.

1. `browser_navigate` to the target page.
2. **Primary method — read the network-layer response headers**, not JS. Use
   `browser_network_requests` to find the main document response and inspect its response headers.
   The network layer surfaces the real headers; JS-side `fetch(...).headers` does **not** — the
   browser hides most response headers from script (`content-security-policy`,
   `strict-transport-security`, and `x-frame-options` are typically **not** readable via
   `headers.entries()`), so a same-origin `fetch` will falsely report them "missing". Only use a
   `fetch`-based read as a last resort, and never conclude a header is absent from `fetch` alone.
3. Inspect the response headers for:
   - `content-security-policy` — present and not trivially unsafe (`unsafe-inline`/`*`)?
   - `strict-transport-security` — present (only meaningful over HTTPS)?
   - `x-frame-options` or a CSP `frame-ancestors` — clickjacking protection?
   - `x-content-type-options: nosniff`?

**Confirmed** if a header the static finding flagged is absent from the network-layer response.
**Refuted** if present. A `curl -sI https://TARGET` is a reliable out-of-band cross-check.

---

## 2. CORS misconfiguration — confirms `secaudit:deployment` / `secaudit:web-vulns`

WSTG-CLNT-07. Tests whether the API reflects an arbitrary origin and allows credentials — which
would let any website read authenticated responses.

1. `browser_navigate` to an **unrelated** origin you control or a neutral one (so the browser
   sends a foreign `Origin` header).
2. `browser_evaluate` a cross-origin credentialed request to the target API:
   ```js
   () => fetch("https://TARGET/api/whoami", { credentials: "include" })
     .then(r => r.text()).then(t => ({ ok: true, body: t.slice(0, 200) }))
     .catch(e => ({ ok: false, error: String(e) }))
   ```
3. A resolving cross-origin fetch is **necessary but not sufficient**: a wildcard `ACAO: *`
   *without* credentials also resolves but is far less dangerous. What confirms the exploitable
   case is **origin reflection with credentials allowed**. Confirm that authoritatively with an
   out-of-band header check (shell, not Playwright):
   `curl -sI -H "Origin: https://evil.example" https://TARGET/api/... | grep -i access-control`
   → **Confirmed** when `Access-Control-Allow-Origin: https://evil.example` appears together with
   `Access-Control-Allow-Credentials: true`. **Refuted** if the origin is not reflected or
   credentials are not allowed.

---

## 3. Routes reachable without authentication — confirms `secaudit:auth` / `secaudit:privilege-escalation`

WSTG-ATHZ. A protected page or API must not return data to an unauthenticated caller.

1. Start from a clean, logged-out state (no session cookie). If needed, `browser_navigate` to a
   logout URL or use a fresh browser context.
2. `browser_navigate` to the protected route (e.g. `/admin`, `/dashboard`) and `browser_snapshot`
   — does it render the protected content, or redirect to login / show 401/403?
3. For an API, `browser_evaluate`:
   ```js
   () => fetch("https://TARGET/api/admin/users", { credentials: "omit" })
     .then(r => ({ status: r.status }))
   ```
4. Check the status via `browser_network_requests` too.

**Confirmed** if protected data renders or the API returns `200` with data while logged out.
**Refuted** if it redirects to login or returns `401`/`403`.

---

## 4. IDOR / broken object-level authorization — confirms `secaudit:web-vulns` / `secaudit:privilege-escalation`

WSTG-ATHZ-04. Needs **two test accounts you own** (gate step 4). Confirms access is possible; do
not exfiltrate real data.

1. Log in as **account B**: `browser_navigate` to the login page, `browser_type` credentials,
   `browser_click` submit. Note an object id that belongs to B (e.g. `/orders/1002`).
2. Log out, log in as **account A** (a different, low-value test account you own).
3. As A, request B's object — `browser_navigate` to `/orders/1002`, or `browser_evaluate`:
   ```js
   () => fetch("https://TARGET/api/orders/1002", { credentials: "include" })
     .then(r => ({ status: r.status, leak: r.status === 200 }))
   ```
4. **Confirmed** if A receives B's object (`200` + B's data) → object-level authorization is
   missing. **Refuted** if `403`/`404`. Record only that access was possible, not the contents.

---

## 5. Reflected XSS — confirms `secaudit:web-vulns`

WSTG-INPV-01. Verifies a static XSS finding actually executes, using a harmless marker (no real
payload).

1. `browser_navigate` to the flagged URL with a unique marker in the parameter, e.g.
   `https://TARGET/search?q=<img src=x onerror="window.__xssMarker=1">`.
2. In the **same navigation** (a fresh `browser_navigate` resets `window`, so don't reload before
   reading), `browser_evaluate`:
   ```js
   () => ({ executed: window.__xssMarker === 1 })
   ```
   and check `browser_console_messages` for the load error the marker triggers.
3. Also `browser_snapshot` / inspect the DOM to see whether the raw payload appears unescaped.

**Confirmed** if `executed` is true (the injected handler ran) or the payload is present unescaped
in an executable context. **Refuted** if the framework escaped it (marker not set, payload shown
as inert text). Use a benign marker only — never a real data-stealing payload.

---

## Reporting

Roll every verdict back into the audit output. A **Confirmed** finding keeps its severity and
gains reproduction evidence; a **Refuted** finding is dropped or downgraded with the observed
compensating control; an **Inconclusive** one stays "Needs verification" with the missing
precondition named.
