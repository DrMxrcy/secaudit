#!/usr/bin/env python3
"""Find new live security incidents for the stacks the secaudit skills cover.

check-freshness.py re-verifies facts the skills already cite. It cannot notice an
advisory the skills have never heard of — and the ones that matter most are often the
ones OSV does not index at all: language runtimes (PHP core, Node.js) and vendor-only
advisories that land days before any database ingests them.

pwn.watch tracks those as incidents with affected/fixed versions and source links. This
polls its per-tag feeds and emits only what is new since the last run, as sanitised,
structured JSON for the advisory-watch workflow to turn into issues.

pwn.watch is a tracker, not the vendor: every incident is emitted with its vendor
sources, and those are what a fix must cite.

Usage:
    python3 scripts/watch-advisories.py                          # last 7 days, all tags
    python3 scripts/watch-advisories.py --state .pwnwatch-state.json
    python3 scripts/watch-advisories.py --tags php,node --since 2026-10-01
    python3 scripts/watch-advisories.py --out advisories.json

The state file holds each tag's ETag (sent back as If-None-Match, so an unchanged feed
costs a 304) and the newest updatedAt processed. Run it at most hourly — the feeds are
edge-cached for 60s and the publisher asks for no more.

Exit codes: 0 = ran (new incidents or not), 2 = the script itself failed.
Stdlib only, so there is nothing to install and nothing to keep patched.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://pwn.watch"
UA = "secaudit-advisory-watch (+https://github.com/DrMxrcy/secaudit)"
TIMEOUT = 30

# Stacks the skills cover. A tag here with no matching skill produces issues nobody can
# act on, so keep this in step with skills/.
DEFAULT_TAGS = (
    "node", "npm", "php", "python", "pypi", "docker", "github-actions",
    "nextjs", "react", "supply-chain",
)
CATEGORIES = {"patch", "supply-chain"}

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,150}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
ENUMS = {
    "severity": {"critical", "high", "medium", "low", "unknown"},
    "patchStatus": {"patched", "partial", "unpatched", "unknown"},
    "category": {"patch", "breach", "supply-chain"},
}


class Unreachable(Exception):
    """Could not get an answer. NOT the same as 'nothing new'."""


def _get(url: str, etag: str | None = None, attempts: int = 3) -> tuple[int, dict | None, str | None]:
    """GET JSON. Returns (status, body, etag); status 304 means unchanged and body is None."""
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.status, json.load(r), r.headers.get("ETag")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, None, etag
            if e.code == 429 or 500 <= e.code < 600:
                last = e
            else:
                raise Unreachable(f"{url}: HTTP {e.code}")
        except Exception as e:
            last = e
        time.sleep(1.5 * (i + 1))
    raise Unreachable(f"{url}: {_err_text(last)}")


def _err_text(e) -> str:
    """An exception's text (it can carry a server's HTTP reason phrase) as short printable ASCII."""
    t = re.sub(r"\s+", " ", re.sub(r"[^\x20-\x7e]", "?", str(e))).replace("`", "'").strip()
    return t if len(t) <= 300 else t[:297] + "..."


# --- Sanitisation -------------------------------------------------------------
# Everything below ends up in a public GitHub issue that an AI agent may later be assigned
# to. Feed text is untrusted. Free-form prose (summary, agentBrief, timeline bodies) is
# never passed through at all; the short fields that are passed through are reduced to
# printable ASCII (after folding dashes and quotes), so nothing invisible (Unicode tag characters, zero-width or bidi
# controls) can carry text a human reviewer cannot see. Backticks are stripped so the
# workflow can render every string inside a code span, where @mentions and links do not
# fire. Any field that had to be altered marks the incident `clean: false`, and an unclean
# incident is never offered to Copilot.

# Characters plausible in a product name or a version range. Anything else is dropped.
TEXT_RE = re.compile(r"[^A-Za-z0-9 .,:;=!^~+\-/()@'\"%&?<>*]")
# Typographic punctuation that is common in vendor text and safe to fold to ASCII.
# Every Unicode hyphen and the minus sign fold to '-' BEFORE TEXT_RE runs: dropping them would
# glue "4.0.0\u20114.17.20" into the meaningless "4.0.04.17.20" instead of a range.
FOLD = str.maketrans({"\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
                      "\u2015": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'",
                      "\u201c": '"', "\u201d": '"', "\u2264": "<=", "\u2265": ">=", "\u2026": "..."})

# Hosts a fix may cite as the vendor source. pwn.watch can list any https URL; an
# unknown host is shown as unverified and keeps the incident away from Copilot, because
# Copilot is told the vendor source outranks the issue.
TRUSTED_HOSTS = {
    "nvd.nist.gov", "www.cve.org", "cve.org", "osv.dev", "www.cisa.gov", "cisa.gov",
    "nodejs.org", "www.php.net", "php.net", "www.python.org", "python.org", "pypi.org",
    "www.npmjs.com", "npmjs.com", "nextjs.org", "react.dev", "vercel.com",
    "docs.docker.com", "github.blog", "go.dev", "pkg.go.dev",
}


def clean_text(value, limit: int = 200) -> tuple[str, bool]:
    """Return (text, unaltered). unaltered is False if anything was dropped or truncated."""
    if not isinstance(value, str):
        return "", value is None
    s = unicodedata.normalize("NFKC", value).translate(FOLD)
    s = re.sub(r"\s+", " ", s).strip()
    cleaned = re.sub(r"\s+", " ", TEXT_RE.sub("", s)).strip()
    ok = cleaned == s
    if len(cleaned) > limit:
        cleaned, ok = cleaned[: limit - 3].rstrip() + "...", False
    return cleaned, ok


def clean_url(value) -> dict | None:
    if not isinstance(value, str) or len(value) > 500:
        return None
    try:
        u = urllib.parse.urlsplit(value.strip())
        host = (u.hostname or "").lower()
    except ValueError:
        return None
    if (u.scheme != "https" or not host or u.username or u.password or u.port
            or any(c in value for c in " <>`\"'()[]\\")
            or any(ord(c) < 33 or ord(c) > 126 for c in value.strip())):
        return None
    if host == "github.com":
        trusted = "/advisories/" in u.path or "/security/advisories/" in u.path
    else:
        trusted = host in TRUSTED_HOSTS
    return {"url": urllib.parse.urlunsplit(u), "host": host, "trusted": trusted}


def clean_enum(field: str, value) -> str:
    return value if isinstance(value, str) and value in ENUMS[field] else "unknown"


def sanitise(inc: dict, detail: dict | None) -> dict | None:
    slug = inc.get("slug")
    if not isinstance(slug, str) or not SLUG_RE.match(slug):
        return None
    altered: set[str] = set()   # fields whose text was changed, cut short or dropped

    def text(value, limit, field):
        t, ok = clean_text(value, limit)
        if not ok:
            altered.add(field)
        return t

    def texts(values, limit, field, n=12):
        if not isinstance(values, list):
            if values is not None:
                altered.add(field)
            return []
        if len(values) > n:
            altered.add(field)
        out = [text(v, limit, field) for v in values[:n]]
        return list(dict.fromkeys(v for v in out if v))

    def ids(values, pattern, n=20):
        if not isinstance(values, list):
            return []
        return list(dict.fromkeys(v for v in values[:n] if isinstance(v, str) and pattern.match(v)))

    raw_sources = (detail or {}).get("sources")
    sources = []
    for s in raw_sources if isinstance(raw_sources, list) else []:
        c = clean_url(s.get("url") if isinstance(s, dict) else s)
        if c and c["url"] not in [x["url"] for x in sources]:
            sources.append(c)
    sources = sources[:8]

    item = {
        "slug": slug,
        "title": text(inc.get("title"), 140, "title") or slug,
        "product": text(inc.get("product"), 120, "product"),
        "category": clean_enum("category", inc.get("category")),
        "severity": clean_enum("severity", inc.get("severity")),
        "patchStatus": clean_enum("patchStatus", inc.get("patchStatus")),
        "cves": ids(inc.get("cveIds"), CVE_RE),
        "tags": ids(inc.get("tags"), TAG_RE),
        "affected": texts(inc.get("affectedVersions"), 200, "affected"),
        "fixed": texts(inc.get("fixedVersions"), 120, "fixed"),
        "sources": sources,
        "updatedAt": norm_time(inc.get("updatedAt")) or "",
        "tracker": f"{BASE}/i/{slug}",
    }
    clean = not altered
    item["clean"] = clean
    # Which fields were altered or truncated (an added key; `clean` keeps its meaning).
    item["altered"] = sorted(altered)
    # Offered to Copilot only when it is an actionable patch, nothing had to be altered,
    # and at least one source is a host a fix can actually cite.
    item["copilotOk"] = (
        clean and item["category"] == "patch" and item["severity"] in ("critical", "high")
        and any(s["trusted"] for s in sources)
    )
    return item


# --- Polling --------------------------------------------------------------------

def norm_time(value) -> str | None:
    """Normalise an ISO timestamp or date to YYYY-MM-DDTHH:MM:SSZ so string order is time order."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_state(path: Path | None) -> dict:
    if path and path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
    return {}


def poll(tags: list[str], since: str, state: dict) -> tuple[list[dict], list[str], int]:
    """Returns (incidents, warnings, number of tag feeds that could not be fetched)."""
    etags = state.get("etags")
    if not isinstance(etags, dict):
        etags = state["etags"] = {}
    seen: dict[str, dict] = {}
    warnings = []
    feed_failures = 0
    for tag in tags:
        prior = etags.get(tag) if isinstance(etags.get(tag), str) else None
        try:
            status, body, etag = _get(f"{BASE}/t/{tag}.json", prior)
        except Unreachable as e:
            warnings.append(str(e))
            feed_failures += 1
            continue
        if status == 304 or not isinstance(body, dict):
            continue
        incidents = body.get("incidents")
        for inc in incidents if isinstance(incidents, list) else []:
            # One malformed item must not stop the run: skip it.
            if not isinstance(inc, dict):
                continue
            slug, category = inc.get("slug"), inc.get("category")
            if not isinstance(slug, str) or not SLUG_RE.match(slug):
                continue
            if inc.get("status") != "live" or not isinstance(category, str) or category not in CATEGORIES:
                continue
            updated = norm_time(inc.get("updatedAt"))
            if not updated or updated <= since:
                continue
            seen.setdefault(slug, inc)
        # Only remember the ETag once the body has been processed.
        if etag:
            etags[tag] = etag

    out = []
    for slug, inc in seen.items():
        detail = None
        try:
            _, detail, _ = _get(f"{BASE}/i/{slug}.json")
            if isinstance(detail, dict) and isinstance(detail.get("incident"), dict):
                detail = detail["incident"]
        except Unreachable as e:
            warnings.append(f"{e} (emitted without vendor sources)")
        try:
            item = sanitise(inc, detail if isinstance(detail, dict) else None)
        except Exception as e:  # a malformed incident is skipped, not fatal
            warnings.append(f"{slug}: skipped malformed incident ({type(e).__name__})")
            continue
        if item:
            out.append(item)
    out.sort(key=lambda x: x["updatedAt"], reverse=True)
    return out, warnings, feed_failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tags", help="comma-separated pwn.watch tags (default: the stacks the skills cover)")
    ap.add_argument("--since", help="ISO date/time; default: state cursor, else 7 days ago")
    ap.add_argument("--state", type=Path, help="state file for ETags and the cursor (read and updated)")
    ap.add_argument("--out", type=Path, help="write the JSON result here instead of stdout")
    args = ap.parse_args()

    tags = [t.strip() for t in (args.tags.split(",") if args.tags else DEFAULT_TAGS) if t.strip()]
    bad = [t for t in tags if not TAG_RE.match(t)]
    if bad:
        print(f"invalid tag(s): {', '.join(bad)}", file=sys.stderr)
        return 2

    state = load_state(args.state)
    now = datetime.datetime.now(datetime.timezone.utc)
    cursor = norm_time(state.get("cursor"))
    if args.since:
        since = norm_time(args.since)
        if not since:
            print(f"invalid --since: {args.since}", file=sys.stderr)
            return 2
    elif cursor:
        # Re-read a 48 h overlap behind the cursor. Feeds are edge-cached and fetched one
        # by one, so a newer item seen on one tag must not hide an older one on another.
        # Re-emitting is harmless: the workflow dedupes by slug and fingerprint.
        since = norm_time((datetime.datetime.fromisoformat(cursor.replace("Z", "+00:00"))
                           - datetime.timedelta(hours=48)).isoformat())
    else:
        since = (now - datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        items, warnings, feed_failures = poll(tags, since, state)
    except Exception as e:  # anything unexpected is a script failure, never "nothing new"
        print(f"watch-advisories failed: {e}", file=sys.stderr)
        return 2
    if feed_failures == len(tags):
        # Every feed unreachable: report failure rather than an empty all-clear.
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        return 2

    # Advance the cursor only when every feed answered; otherwise the failed tags' items
    # would fall behind it for good.
    if items and not feed_failures:
        state["cursor"] = max(cursor or since, items[0]["updatedAt"])
    result = {"since": since, "tags": tags, "count": len(items), "warnings": warnings, "advisories": items}
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(text + "\n")
    else:
        print(text)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if args.state:
        args.state.write_text(json.dumps(state, indent=2) + "\n")
    print(f"{len(items)} new or updated incident(s) since {since}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
