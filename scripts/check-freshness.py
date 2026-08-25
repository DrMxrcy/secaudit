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
import datetime
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
    # Kept for documentation; the global 403 rule below now covers this class generally.
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
            # 429 and 5xx are the server having a problem, not the page having moved.
            # Retry, and if it never answers cleanly treat it as unreachable rather than
            # drift — a 503 is not evidence that a citation is wrong.
            if e.code == 429 or 500 <= e.code < 600:
                last = e
            else:
                return e.code            # a real answer about the resource: 200/301/403/404
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


_ADVISORY_CACHE: dict[str, dict | None] = {}


def osv_advisory(advisory_id: str, attempts: int = 3) -> dict | None:
    """Return the advisory, None if it truly does not exist, raise if we could not tell.

    Cached per process: the same advisory is cited from several files, and the fix-claim
    check follows aliases, so without this a single run refetches the same records many
    times and takes minutes instead of seconds.
    """
    if advisory_id in _ADVISORY_CACHE:
        return _ADVISORY_CACHE[advisory_id]
    req = urllib.request.Request(OSV_VULN + advisory_id, headers={"User-Agent": UA})
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = json.load(r)
            _ADVISORY_CACHE[advisory_id] = data
            return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _ADVISORY_CACHE[advisory_id] = None   # definitive: no such advisory
                return None
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


# A version cited *as vulnerable* is not drift — the skills deliberately name bad versions
# to teach the contrast. But suppression must key on an EXPLICIT disclaimer, never on a word
# that appears in both the good and the bad case.
#
# "fixed in X" and "patched by X" are deliberately NOT here. They read as recommendations, so
# they must be verified. Suppressing them once hid an Astro entry recommending a version with
# 17 open advisories: the suppression that prevented a false positive created a false negative,
# which is strictly worse — it turns "nobody checked" into "the check passed".
NEGATIVE_CONTEXT = re.compile(
    r"(\bBAD\b|\bBefore\b|\bvulnerable\b|\baffected\b|not a clean floor|still in range"
    r"|open advisories|do not stop there|not versions that are safe|no longer safe"
    r"|\bexposed to\b|\bin range\b|is \*not\* a|are \*not\*)",
    re.IGNORECASE,
)


def unwrap(text: str) -> str:
    """Collapse markdown's hard line wraps so a sentence is contiguous.

    Blank lines and list-item starts are preserved as breaks; everything else joins.
    Without this, a qualifying phrase straddles a newline and sentence context misses it.
    """
    out, buf = [], []

    def flush():
        if buf:
            out.append(" ".join(buf))
            buf.clear()

    for line in text.split("\n"):
        stripped = line.strip()
        # Hard breaks: a blank line, a heading, a table row, or a fence ends the paragraph.
        if not stripped or re.match(r"\s*(#|\||```)", line):
            flush()
            out.append(line)
        # A list marker STARTS a new buffer rather than being emitted alone, so the item's
        # wrapped continuation lines join it. Note the marker patterns require a following
        # space: without it, a version like "4.16.18" reads as an ordered-list marker and the
        # line carrying it gets split away from the "fixed" that qualifies it.
        elif re.match(r"\s*([-*+]\s|\d+\.\s)", line):
            flush()
            buf.append(stripped)
        else:
            buf.append(stripped)
    flush()
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

# --- Check 2b: bare "fixed in X" versions -----------------------------------
# Most version claims in the skills are bare numbers in prose ("fixed 4.16.18 / 5.0.8"),
# not `pkg@1.2.3`, so the floor check above never sees them. That blind spot hid an Astro
# entry recommending a version with 17 open advisories.
#
# Package identity comes from the CVE cited on the same line: ask OSV which packages that
# advisory affects, then check the bare versions against those packages. Using the advisory
# as the source of identity avoids guessing a package name out of prose.
BARE_VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+(?:-[a-z0-9.]+)?\b")
# Version numbers contain dots, so the clause cannot terminate on the first ".".
# Stop at a sentence end (". " or end of line) instead.
FIX_CLAIM_RE = re.compile(r"\b(fixed|patched)\b(?:[^.]|\.(?=\d))*", re.IGNORECASE)


def _packages_for(cve: str) -> set[str]:
    """npm packages an advisory affects.

    A CVE-keyed OSV record often carries an `affected` entry with no `package` field — the
    package data lives on the GHSA alias. Follow the alias rather than giving up, or this
    check silently finds nothing (which is how the Astro entry stayed wrong).
    """
    for ident in (cve,):
        adv = osv_advisory(ident)
        if not adv:
            continue
        pkgs = {a["package"]["name"] for a in adv.get("affected", [])
                if a.get("package", {}).get("ecosystem") == "npm"}
        if pkgs:
            return pkgs
        for alias in adv.get("aliases", []):
            if alias.startswith("GHSA-"):
                sub = osv_advisory(alias)
                if sub:
                    pkgs = {a["package"]["name"] for a in sub.get("affected", [])
                            if a.get("package", {}).get("ecosystem") == "npm"}
                    if pkgs:
                        return pkgs
    return set()


def _before_not(clause: str) -> str:
    """Drop the trailing counter-example in "fixed in X, not Y".

    The skills deliberately name the wrong version right after the right one ("fixed 4.19.2,
    not 4.19.0") to make the correction memorable. Everything after "not" is the version
    being warned against, so verifying it would report the lesson itself as the defect.
    """
    return re.split(r"\bnot\b", clause, maxsplit=1)[0]


def check_fix_claims() -> list[dict]:
    """Verify that a version named as a CVE's fix actually fixes it.

    Two different defects hide in a "fixed in X" claim, and they need different handling:

    1. **X does not fix that CVE at all.** This is a hard failure — it is the Express
       "fixed 4.19.0" defect (the real fix was 4.19.2), which shipped for months.
    2. **X fixes that CVE but has since accrued later advisories.** This is normal and true
       of essentially every CVE entry over time, so failing on it would make the check
       useless noise. It is reported as a WARNING, and only matters when the entry reads as
       upgrade advice without naming a current clean floor.
    """
    claims = []
    for f in source_files():
        text = unwrap(f.read_text(encoding="utf-8"))
        for line in text.split("\n"):
            if not FIX_CLAIM_RE.search(line):
                continue
            cves = CVE_RE.findall(line)
            # Suppression is scoped to the fix CLAUSE, not the whole line. A good entry
            # discusses its own caveats ("4.19.2 is not a clean floor: ..."), and matching
            # those against the line would exempt the very entries that explain themselves
            # best — leaving the actual "fixed in X" claim unchecked.
            versions = set()
            for m in FIX_CLAIM_RE.finditer(line):
                clause = _before_not(m.group(0))
                if NEGATIVE_CONTEXT.search(clause):
                    continue
                versions.update(BARE_VERSION_RE.findall(clause))
            if cves and versions:
                claims.append((str(f.relative_to(ROOT)), cves[0], tuple(sorted(versions))))

    cves = sorted({c for _, c, _ in claims})
    advisories: dict[str, dict | None] = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        for cve, adv in zip(cves, ex.map(lambda c: _safe(_resolve_advisory, c), cves)):
            advisories[cve] = adv

    findings, warnings = [], []
    for path, cve, versions in claims:
        adv = advisories.get(cve)
        if not adv:
            continue
        # Only SEMVER/ECOSYSTEM ranges. A CVE record also carries GIT ranges whose "fixed"
        # values are commit hashes, which would make every semver claim look wrong.
        fixed = {e["fixed"] for a in adv.get("affected", [])
                 for r in a.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")
                 for e in r["events"] if "fixed" in e}
        if not fixed:
            continue
        for ver in versions:
            if ver not in fixed:
                findings.append({
                    "check": "fix-claim",
                    "file": path,
                    "subject": f"{ver} named as the fix for {cve}",
                    "problem": ("that version is not in the advisory's fixed list; "
                                f"actual: {', '.join(sorted(fixed)[:6])}"),
                })
            else:
                warnings.append(f"{cve}: {ver} fixes it but may carry later advisories ({path})")

    # Deliberately NOT reported. Every CVE entry accrues later advisories over time, so this
    # would print on every clean run — an action item nobody will work through 24 times, which
    # is how a checker's output becomes wallpaper. The hard check above catches the real defect
    # (a version that does not fix its stated CVE); the "is this a clean floor today" question
    # is the `versions` check's job, on versions actually offered as upgrade targets.
    return findings


def _resolve_advisory(cve: str) -> dict | None:
    """The advisory record that actually carries package/version data.

    A CVE-keyed OSV record often has an `affected` entry with no `package` field; the data
    lives on the GHSA alias. Follow the alias rather than giving up, or this check silently
    finds nothing — which is how the Astro entry stayed wrong through two releases.
    """
    adv = osv_advisory(cve)
    if not adv:
        return None
    def has_semver(rec):
        return any(r.get("type") in ("SEMVER", "ECOSYSTEM")
                   for a in rec.get("affected", []) for r in a.get("ranges", []))
    has_ranges = has_semver(adv)
    if has_ranges:
        return adv
    for alias in adv.get("aliases", []):
        if alias.startswith("GHSA-"):
            sub = osv_advisory(alias)
            if sub and has_semver(sub):
                return sub
    return None


def _safe(fn, *args, default=None):
    """Run fn; treat any failure as 'could not determine', never as a finding."""
    try:
        return fn(*args)
    except Exception:
        return default

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
            elif status == 403:
                # 403 never means "moved" or "gone" — it means this client was refused.
                # WAFs block datacenter IPs, so links that are 200 from a laptop are 403
                # from a CI runner. Reporting that as drift would fail the monthly job every
                # time and teach everyone to ignore it.
                unreachable.append(f"{url} (403 — likely bot/WAF block, not drift)")
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


# --- Check 5: runtime end-of-life -------------------------------------------
# OSV indexes packages, not runtimes, so the version checks above cannot see that a
# recommended Node/Python/Postgres major has gone EOL. An EOL runtime gets no patches
# at all, which outranks any single CVE — and there is no advisory to catch it.
EOL_API = "https://endoflife.date/api/{}.json"

# Runtimes the skills give version advice about, mapped to their endoflife.date product.
EOL_PRODUCTS = {
    "node": "nodejs", "nodejs": "nodejs", "python": "python",
    "django": "django", "postgres": "postgresql", "postgresql": "postgresql",
    "php": "php", "ruby": "ruby", "laravel": "laravel",
}
# "Node 22", "Python 3.9", "Postgres 16" — a major (optionally minor) after the name.
RUNTIME_VER_RE = re.compile(
    r"\b(?P<name>" + "|".join(sorted(EOL_PRODUCTS, key=len, reverse=True)) + r")"
    r"[\s@v]+(?P<ver>\d+(?:\.\d+)?)\b", re.IGNORECASE)


def _eol_cycles(product: str) -> dict[str, str]:
    req = urllib.request.Request(EOL_API.format(product), headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return {str(c["cycle"]): c.get("eol") for c in json.load(r)}


def check_eol() -> list[dict]:
    findings = []
    today = datetime.date.today().isoformat()
    cache: dict[str, dict[str, str]] = {}
    for f in source_files():
        text = unwrap(f.read_text(encoding="utf-8"))
        for line in text.split("\n"):
            # Only lines that read as a recommendation. A line explaining that something is
            # EOL is the correct advice, not drift.
            if not re.search(r"\b(use|upgrade|require|minimum|at least|target)\b", line, re.I):
                continue
            if NEGATIVE_CONTEXT.search(line) or re.search(r"\bEOL\b|end.of.life", line, re.I):
                continue
            for m in RUNTIME_VER_RE.finditer(line):
                name, ver = m.group("name").lower(), m.group("ver")
                product = EOL_PRODUCTS[name]
                if product not in cache:
                    try:
                        cache[product] = _eol_cycles(product)
                    except Exception:
                        cache[product] = {}
                eol = cache[product].get(ver)
                if isinstance(eol, str) and eol < today:
                    findings.append({
                        "check": "eol",
                        "file": str(f.relative_to(ROOT)),
                        "subject": f"{m.group('name')} {ver}",
                        "problem": f"reached end of life on {eol} — receives no security patches",
                    })
    return findings


# --- Check 6: manifest consistency ------------------------------------------
# Not a network check, but the same failure shape: facts that were true when written
# and quietly stopped being true. marketplace.json sat at 3.1.0 for six releases with a
# stale description and 7 of 30 keywords — and that is the copy users see when installing.
def check_manifests() -> list[dict]:
    findings = []

    def add(file, subject, problem):
        findings.append({"check": "manifest", "file": file,
                         "subject": subject, "problem": problem})

    try:
        plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
    except Exception as e:
        return [{"check": "manifest", "file": ".claude-plugin/plugin.json",
                 "subject": "plugin.json", "problem": f"unreadable: {e}"}]

    # marketplace.json must agree with plugin.json on what is being shipped
    mpath = ROOT / ".claude-plugin/marketplace.json"
    if mpath.exists():
        try:
            entry = json.loads(mpath.read_text())["plugins"][0]
            for key in ("version", "description", "keywords"):
                if entry.get(key) != plugin.get(key):
                    add(".claude-plugin/marketplace.json", key,
                        f"disagrees with plugin.json (marketplace={entry.get(key)!r:.60})")
        except Exception as e:
            add(".claude-plugin/marketplace.json", "marketplace.json", f"unreadable: {e}")

    # every skill on disk must be discoverable: named in README and dispatched by audit
    on_disk = {d.name for d in (ROOT / "skills").iterdir() if (d / "SKILL.md").is_file()}
    readme = (ROOT / "README.md").read_text()
    audit = (ROOT / "skills/audit/SKILL.md").read_text()
    for name in sorted(on_disk):
        if f"secaudit:{name}" not in readme:
            add("README.md", name, "skill exists on disk but is not listed in the README table")
        if name != "audit" and f"secaudit:{name}" not in audit:
            add("skills/audit/SKILL.md", name,
                "skill exists but the orchestrator never dispatches it — it will never run")

    # and a skill's frontmatter name must match its directory, or it will not load
    for name in sorted(on_disk):
        text = (ROOT / "skills" / name / "SKILL.md").read_text()
        m = re.search(r"(?m)^name:\s*(\S+)\s*$", text)
        if not m:
            add(f"skills/{name}/SKILL.md", name, "no `name:` in frontmatter")
        elif m.group(1) != name:
            add(f"skills/{name}/SKILL.md", name,
                f"frontmatter name is {m.group(1)!r} but the directory is {name!r}")
    return findings


CHECKS = {
    "manifests": check_manifests,
    "versions": check_version_floors,
    "fixclaims": check_fix_claims,
    "cves": check_advisories,
    "links": check_links,
    "kev": check_kev,
    "eol": check_eol,
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
