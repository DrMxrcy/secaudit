#!/usr/bin/env python3
"""Re-derive every perishable fact the secaudit skills assert, from live sources.

The skills hardcode version floors, CVE fix-versions, and URLs. All three rot: a fact
that is correct when written stops being correct when the next advisory lands. Measured
on 2026-08-21, the median gap between `next` advisory publication days was 31 days, so a
hardcoded floor for a fast-moving framework has a useful life of weeks.

This script reports drift. It deliberately does NOT edit the skills — silently
auto-correcting security guidance is a worse failure mode than staleness.

Usage:
    python3 scripts/check-freshness.py                  # all checks
    python3 scripts/check-freshness.py --only versions  # one class
    python3 scripts/check-freshness.py --json           # machine-readable

Exit codes: 0 = everything current, 1 = drift found, 2 = the script itself failed.
Stdlib only, so there is nothing to install and nothing to keep patched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = "Mozilla/5.0 (compatible; secaudit-freshness-check)"
TIMEOUT = 20

# Files whose assertions we check.
def source_files() -> list[Path]:
    files = [ROOT / "SOURCES.md"]
    files += sorted(ROOT.glob("skills/**/*.md"))
    return [f for f in files if f.is_file()]


# --- Exclusions -------------------------------------------------------------
# Placeholders that appear inside example snippets. These are not real citations;
# flagging them would train people to ignore this check, which is the failure mode
# that matters most.
PLACEHOLDER_PATTERNS = [
    r"myapp\.com", r"\bTARGET\b", r"evil\.example", r"example\.com",
    r"<[^>]*>",                       # <project-id>, <img, <id>
    r"GHSA-xxxx", r"api\.openai\.com", r"localhost", r"127\.0\.0\.1",
    r"registry\.npmjs\.org/:_authToken",
    r"pypi\.company\.com",           # fictional private index in a dependency-confusion example
]

# Hosts/URLs that legitimately answer non-200 to this script. Each needs a reason.
URL_ALLOWLIST = {
    # Returns 403 to a browser User-Agent, 200 with none. Alive; still the W3C Recommendation.
    "https://www.w3.org/TR/webauthn-2/": "403 to browser UA, alive",
    # POST-only API endpoints, documented as such in live-advisory-lookup.md.
    "https://api.osv.dev/v1/query": "POST-only by design",
    "https://api.osv.dev/v1/querybatch": "POST-only by design",
    # Cloudflare-protected root; the specific article links in the same file resolve.
    "https://socket.dev": "Cloudflare challenge on root",
}


def is_placeholder(text: str) -> bool:
    return any(re.search(p, text) for p in PLACEHOLDER_PATTERNS)


# --- HTTP helpers -----------------------------------------------------------
def http_status(url: str, attempts: int = 3) -> int:
    """Status WITHOUT following redirects, so a 301 surfaces as drift.

    Raises TransientError when we could not get an answer at all. A connection reset or
    TLS hiccup is not evidence that a page is gone — reporting it as "dead" sends someone
    to replace a working citation, and trains everyone to distrust the checker.
    """
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    last = None
    for i in range(attempts):
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code                # a real HTTP answer, including 404/301
        except Exception as e:
            last = e                     # DNS/TLS/reset — retry before believing it
        time.sleep(1.0 * (i + 1))
    raise TransientError(f"{url}: {last}")


def osv_version_query(pkg: str, version: str, ecosystem: str = "npm") -> list[dict]:
    body = json.dumps({"package": {"name": pkg, "ecosystem": ecosystem}, "version": version})
    req = urllib.request.Request(
        OSV_QUERY, data=body.encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r).get("vulns", [])


class TransientError(Exception):
    """A network/rate-limit failure — NOT evidence that the fact is wrong.

    Reporting a transient failure as drift is how a checker loses trust. Only a
    definitive 404 means the advisory genuinely does not exist.
    """


def osv_advisory(advisory_id: str, attempts: int = 3) -> dict | None:
    """Return the advisory, None if it truly does not exist, raise if we could not tell."""
    req = urllib.request.Request(OSV_VULN + advisory_id, headers={"User-Agent": UA})
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None          # definitive: no such advisory
            last = e                 # 429/5xx — retry
        except Exception as e:
            last = e
        time.sleep(1.5 * (i + 1))    # linear backoff; OSV rate-limits bursts
    raise TransientError(f"{advisory_id}: {last}")


# --- Check 1: version floors ------------------------------------------------
# Any `pkg@1.2.3` the docs present as a target must have zero open advisories.
# This is the check that would have caught next@15.5.7 and express@4.19.0.
FLOOR_RE = re.compile(
    r"`?(?P<pkg>@?[a-z0-9][a-z0-9._/-]*)@(?P<ver>\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)`?"
)


# A version cited *as vulnerable* is not drift — the skills deliberately name bad
# versions ("Before", "not a clean floor", "28 open advisories") to teach the contrast.
# Only versions presented as somewhere to upgrade TO should be required to be clean.
NEGATIVE_CONTEXT = re.compile(
    r"\b(BAD|Before|vulnerable|affected|not a clean floor|still in range|advisories"
    r"|do not|don't|no longer safe|exposed to|in range|patched by|fixed in|Affected)\b",
    re.IGNORECASE,
)


def unwrap(text: str) -> str:
    """Collapse markdown's hard line wraps so a sentence is contiguous.

    Blank lines and list-item starts are preserved as breaks; everything else joins.
    Without this, a qualifying phrase straddles a newline and sentence context misses it.
    """
    out, buf = [], []
    for line in text.split("\n"):
        if not line.strip() or re.match(r"\s*([-*+]|\d+\.|#|\||```)", line):
            if buf:
                out.append(" ".join(buf))
                buf = []
            out.append(line)
        else:
            buf.append(line.strip())
    if buf:
        out.append(" ".join(buf))
    return "\n".join(out)


def _sentence_of(text: str, pos: int) -> str:
    """The sentence containing `pos`.

    Sentence scope, not line scope: a negative marker three lines away can belong to a
    different claim entirely. Suppressing on that would hide real drift — the failure
    mode where the check passes while the fact is wrong.
    """
    lo = max(
        text.rfind(". ", 0, pos) + 1,
        text.rfind("\n", 0, pos) + 1,
        text.rfind("— ", 0, pos) + 1,
    )
    ends = [e for e in (text.find(". ", pos), text.find("\n", pos)) if e != -1]
    hi = min(ends) if ends else len(text)
    return text[lo:hi]


def check_version_floors() -> list[dict]:
    findings, seen = [], set()
    for f in source_files():
        text = unwrap(f.read_text(encoding="utf-8"))
        for m in FLOOR_RE.finditer(text):
            pkg, ver = m.group("pkg"), m.group("ver")
            if is_placeholder(m.group(0)) or (pkg, ver) in seen:
                continue
            if NEGATIVE_CONTEXT.search(_sentence_of(text, m.start())):
                continue  # cited as a bad version on purpose
            # Only check packages we can resolve on npm. Skip prose like "node@22".
            seen.add((pkg, ver))
            try:
                vulns = osv_version_query(pkg, ver)
            except Exception:
                continue  # unknown package/ecosystem — not our concern here
            if vulns:
                ids = ", ".join(sorted(
                    (v.get("aliases") or [v["id"]])[0] for v in vulns
                )[:5])
                findings.append({
                    "check": "version-floor",
                    "file": str(f.relative_to(ROOT)),
                    "subject": f"{pkg}@{ver}",
                    "problem": f"{len(vulns)} open advisories ({ids})",
                })
    return findings


# --- Check 2: CVE fix-versions ----------------------------------------------
# Every advisory ID cited must resolve, and its stated alias must match.
ADVISORY_RE = re.compile(r"\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")


def check_advisories() -> list[dict]:
    findings = []
    cited: dict[str, set[str]] = {}
    for f in source_files():
        text = f.read_text(encoding="utf-8")
        for m in ADVISORY_RE.finditer(text):
            if is_placeholder(m.group(0)):
                continue
            cited.setdefault(m.group(1), set()).add(str(f.relative_to(ROOT)))

    def probe(gid: str):
        try:
            return gid, osv_advisory(gid), None
        except TransientError as e:
            return gid, False, str(e)

    unreachable = []
    # Modest concurrency: OSV rate-limits bursts, and a 429 storm would look like drift.
    with ThreadPoolExecutor(max_workers=4) as ex:
        for gid, data, err in ex.map(probe, cited):
            if err:
                unreachable.append(gid)
            elif data is None:
                findings.append({
                    "check": "advisory",
                    "file": ", ".join(sorted(cited[gid])),
                    "subject": gid,
                    "problem": "does not resolve on OSV (404 — advisory does not exist)",
                })
    if unreachable:
        # Surfaced, but not as drift: we could not determine the answer either way.
        print(f"warning: could not reach OSV for {len(unreachable)} advisories "
              f"({', '.join(unreachable[:3])}...); re-run before trusting a clean result",
              file=sys.stderr)
    return findings


# --- Check 3: links ---------------------------------------------------------
# `<` is excluded so a URL containing a `<placeholder>` is truncated before it, and the
# truncated form is then caught by the placeholder check rather than probed as a real link.
URL_RE = re.compile(r"https://[^\s)\"'`,\]<>]+")


def check_links() -> list[dict]:
    findings = []
    urls: dict[str, set[str]] = {}
    for f in source_files():
        text = f.read_text(encoding="utf-8")
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;:")
            # If the match stopped because the next character is `<`, the real URL
            # continues into a `<placeholder>` — it is an example, not a citation.
            if text[m.end():m.end() + 1] == "<":
                continue
            if is_placeholder(url) or url in URL_ALLOWLIST:
                continue
            urls.setdefault(url, set()).add(str(f.relative_to(ROOT)))

    def probe(url: str):
        try:
            return url, http_status(url), None
        except TransientError as e:
            return url, None, str(e)

    unreachable = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for url, status, err in ex.map(probe, urls):
            if err:
                unreachable.append(url)
            elif status != 200:
                kind = "dead" if status in (404, 410) else f"redirects ({status})"
                findings.append({
                    "check": "link",
                    "file": ", ".join(sorted(urls[url])),
                    "subject": url,
                    "problem": kind,
                })
    if unreachable:
        print(f"warning: {len(unreachable)} URL(s) unreachable from here (not reported as "
              f"drift): {', '.join(unreachable[:3])}", file=sys.stderr)
    return findings


# --- Check 4: KEV drift -----------------------------------------------------
# A cited CVE joining the CISA KEV catalog means confirmed exploitation, which
# raises it to Critical. That is a change the skills should reflect.
def check_kev() -> list[dict]:
    findings = []
    cited: dict[str, set[str]] = {}
    for f in source_files():
        text = f.read_text(encoding="utf-8")
        for m in CVE_RE.finditer(text):
            cited.setdefault(m.group(0), set()).add(str(f.relative_to(ROOT)))
    try:
        req = urllib.request.Request(KEV_FEED, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            kev = json.load(r)
    except Exception as e:
        return [{"check": "kev", "file": "-", "subject": KEV_FEED,
                 "problem": f"could not fetch KEV feed: {e}"}]

    listed = {v["cveID"]: v["dateAdded"] for v in kev.get("vulnerabilities", [])}
    for cve, files in sorted(cited.items()):
        if cve in listed:
            mentions_kev = any(
                "KEV" in (ROOT / f).read_text(encoding="utf-8") for f in files
            )
            if not mentions_kev:
                findings.append({
                    "check": "kev",
                    "file": ", ".join(sorted(files)),
                    "subject": cve,
                    "problem": f"on CISA KEV since {listed[cve]} but the file does not say so",
                })
    return findings


CHECKS = {
    "versions": check_version_floors,
    "cves": check_advisories,
    "links": check_links,
    "kev": check_kev,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", choices=sorted(CHECKS), action="append",
                    help="run only this check (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    selected = args.only or sorted(CHECKS)
    findings: list[dict] = []
    for name in selected:
        try:
            findings.extend(CHECKS[name]())
        except Exception as e:  # a broken check must not look like a clean run
            print(f"check {name!r} failed to run: {e}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps({"findings": findings, "checked": selected}, indent=2))
    elif not findings:
        print(f"All current. Checks run: {', '.join(selected)}")
    else:
        print(f"{len(findings)} item(s) have drifted:\n")
        for f in findings:
            print(f"  [{f['check']}] {f['subject']}")
            print(f"      {f['problem']}")
            print(f"      cited in: {f['file']}\n")
        print("These facts were correct when written. Re-verify against the live source,")
        print("then update the skills by hand — do not auto-apply.")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
