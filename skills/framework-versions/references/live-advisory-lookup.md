# Live Advisory Lookup

The hardcoded CVE lists in `framework-versions` and `supply-chain` are a *starting point*, not
the source of truth. A CVE disclosed after those skills were last edited will not be in them.
This procedure looks up **live** vulnerability data for the exact package name+version pairs the
target project actually uses, so newly disclosed issues are still caught.

None of this adds network calls to the audited project. It is guidance the auditing agent runs
against public advisory sources at audit time.

## Tool preference order

Use the first available; fall back down the list.

1. **`osv-scanner`** (CLI) — if installed, the fastest whole-project pass. Reads the lockfile
   and reports vulns per package. `osv-scanner scan source --lockfile package-lock.json` (or point it at
   the repo root). Install: `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`
   or `brew install osv-scanner`.
2. **OSV.dev HTTP API** — no install, no API key, no documented rate limit. Best when the CLI is
   absent. Covers npm, PyPI, crates.io, Go, and more. See the worked example below.
3. **`npm audit --json`** — when a `package-lock.json` / `npm-shrinkwrap.json` is present. Built
   into npm, resolves the whole transitive tree. Parse `.vulnerabilities` (each entry has
   `severity`, `via`, `range`, `fixAvailable`). Use `--audit-level=high` to focus. (`pnpm audit
   --json` / `yarn npm audit --json` are the equivalents for those managers.)
4. **GitHub Security Advisory DB** — the web UI at `https://github.com/advisories` or the GraphQL
   `securityVulnerabilities` API (needs a token) for prose detail and affected/fixed ranges.
5. **firecrawl / WebSearch** — fallback for reading advisory *prose* when a machine ID isn't
   enough: confirm exact affected/fixed version ranges, exploitation status (CISA KEV), and the
   canonical CVE id when a scanner returns only a GHSA. Search e.g. `"<package> <version> CVE"`
   or fetch the NVD / GitHub advisory page directly.

## OSV.dev worked example

**Triage many packages at once** with `POST https://api.osv.dev/v1/querybatch`. It returns only
the vulnerability **ids** per query (fast, small) — use it to find *which* packages have any vuln:

```bash
curl -s -d @- "https://api.osv.dev/v1/querybatch" <<'EOF'
{
  "queries": [
    { "package": { "ecosystem": "npm", "name": "next" },  "version": "15.1.0" },
    { "package": { "ecosystem": "npm", "name": "react" }, "version": "19.0.0" }
  ]
}
EOF
```

Response — one `results` entry per query, in order; `vulns` is absent when the version is clean:

```json
{ "results": [
  { "vulns": [ { "id": "GHSA-xxxx-xxxx-xxxx", "modified": "2025-..." } ] },
  {}
] }
```

**Then fetch full detail** for each hit. Either `GET https://api.osv.dev/v1/vulns/<id>` or a
single `POST https://api.osv.dev/v1/query` (same body as one querybatch entry) returns the full
OSV object, including:

- `aliases` — the CVE id(s) for a GHSA (or vice versa). Report the CVE when one exists.
- `severity` — CVSS vector/score.
- `affected[].ranges` and `affected[].versions` — the exact affected range and the **fixed**
  version (the `fixed` event in a range). This is what the developer needs to upgrade to.
- `database_specific.cwe_ids`, `references` — links to the advisory.

Rules for the request body: use `version` **or** a versioned `purl`, never both (400 otherwise).
The npm ecosystem string is exactly `npm`; PyPI is `PyPI`; crates.io is `crates.io`; Go is `Go`.

## Mapping results to severity

- Any vuln with a CVSS **Critical/High** score, or listed in **CISA KEV** (actively exploited),
  → report as **Critical**. Confirm KEV status via the advisory prose (step 5 fallback) since OSV
  doesn't always carry it.
- Other confirmed vulns affecting the installed version → **High**.
- Always report the **fixed version** to upgrade to, taken from the `affected[].ranges` `fixed`
  event — not a guess.
- If a source disagrees with the hardcoded example list in the skill, **the live result wins**;
  note the discrepancy so the skill's example can be refreshed later.

## Ranking: EPSS (exploitation probability)

After you have the CVE list, batch it through EPSS to get the upgrade order right. Free, no key.

```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2025-55182,CVE-2025-29927,CVE-2024-29041" \
  | python3 -c "import json,sys;[print(f\"{r['cve']:<18} epss={r['epss']} pct={r['percentile']}\") for r in json.load(sys.stdin)['data']]"
```

```
CVE-2025-55182     epss=0.998020000 pct=0.999560000
CVE-2025-29927     epss=0.992030000 pct=0.999320000
CVE-2024-29041     epss=0.007860000 pct=0.533500000
```

A CVE absent from the response has no score yet (usually very recent) — treat that as unknown,
not as low. EPSS is a rolling 30-day forecast, so re-derive it every audit.

## Runtime end-of-life

No advisory database covers this: OSV indexes packages, not runtimes (`ecosystem: "Node.js"`
returns HTTP 400). An EOL runtime gets no patches at all.

```bash
curl -s https://endoflife.date/api/nodejs.json \
  | python3 -c "
import json,sys,datetime
today=datetime.date.today().isoformat()
for r in json.load(sys.stdin):
    eol=r.get('eol')
    if isinstance(eol,str):
        print(f\"{r['cycle']:<6} eol={eol}  {'EOL' if eol<today else 'supported'}\")
"
```

Products available include `nodejs`, `python`, `django`, `postgresql`, `php`, `ruby`, `laravel`,
`dotnet`. Check the language runtime *and* the framework — a supported framework on an EOL
runtime is still unpatched underneath.

## Sources

- https://google.github.io/osv.dev/api/ — OSV.dev API overview (endpoints, no key, ecosystems)
- https://google.github.io/osv.dev/post-v1-querybatch/ — querybatch request/response shape
- https://github.com/google/osv-scanner — osv-scanner CLI
- https://docs.npmjs.com/cli/commands/npm-audit/ — `npm audit` and its `--json` output
- https://github.com/advisories — GitHub Security Advisory Database
- https://nvd.nist.gov/developers/vulnerabilities — NVD CVE API (live CVE detail lookup)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — CISA KEV (actively exploited)
- https://api.first.org/data/v1/epss — EPSS exploitation-probability API (FIRST.org, no key)
- https://www.first.org/epss/ — EPSS model and how to read the score
- https://endoflife.date/ — runtime and framework end-of-life dates (no key)
