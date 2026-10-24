#!/usr/bin/env python3
"""Continuously monitor an app's dependencies, ranked by what is actually being exploited.

This is a PRIORITISATION layer, not another scanner. Dependabot and osv-scanner already
tell you which dependencies have advisories; neither tells you which of them matters
today:

  * Dependabot opens a PR per advisory. Forty open PRs is not a priority order.
  * osv-scanner reports advisories but carries no EPSS, so a CVSS-Critical open redirect
    at 0.8% exploitation probability looks identical to a pre-auth RCE at 99.8%.
  * Neither knows the runtime is end-of-life, because no advisory database indexes
    runtimes.

So it applies the same rule secaudit's audit severity model uses — CISA KEV, then EPSS,
then CVSS, with an EOL runtime critical on its own — continuously, instead of only when
someone remembers to run an audit.

Usage:
    python3 scripts/monitor-deps.py                     # scan cwd
    python3 scripts/monitor-deps.py --path ../myapp
    python3 scripts/monitor-deps.py --min-epss 0.1      # only likely-exploited
    python3 scripts/monitor-deps.py --fail-on kev       # exit non-zero only on KEV
    python3 scripts/monitor-deps.py --json
    python3 scripts/monitor-deps.py --pwnwatch          # also match live pwn.watch incidents

--pwnwatch adds what OSV cannot see: language runtimes (PHP, Node.js, Bun, Python) and
vendor-only advisories that land days before OSV ingests them. It reads the pwn.watch tag
feeds for the ecosystems found under --path, with an ETag cache in a user cache directory
(see docs/monitoring.md). Schedule it hourly at most. A pwn.watch outage is reported as
UNCHECKED for that source and never changes the exit code on its own.

Exit codes: 0 = nothing above threshold, 1 = something is, 2 = the script itself failed.
Stdlib only — nothing to install, nothing to keep patched.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_API = "https://endoflife.date/api/{}.json"
UA = "Mozilla/5.0 (compatible; secaudit-monitor)"
TIMEOUT = 30


class Unreachable(Exception):
    """Could not get an answer. NOT the same as 'no vulnerabilities'.

    A monitor that fails open is worse than no monitor: it reports 'all clear' from a
    network blip and nobody looks again for a week.
    """


def _post(url: str, payload: dict, attempts: int = 3) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json", "User-Agent": UA})
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429 or 500 <= e.code < 600:
                last = e
            else:
                raise Unreachable(f"{url}: HTTP {e.code}")
        except Exception as e:
            last = e
        time.sleep(1.5 * (i + 1))
    raise Unreachable(f"{url}: {last}")


def _get(url: str, attempts: int = 3) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429 or 500 <= e.code < 600:
                last = e
            else:
                raise Unreachable(f"{url}: HTTP {e.code}")
        except Exception as e:
            last = e
        time.sleep(1.5 * (i + 1))
    raise Unreachable(f"{url}: {last}")


# --- Dependency discovery ----------------------------------------------------
# Only formats that parse cleanly from stdlib. Bespoke lockfile formats are DETECTED
# and reported as unchecked rather than half-parsed: a partial parse that reports
# "no findings" is exactly the false-clean this tool exists to prevent.
UNSUPPORTED = {
    "yarn.lock": "yarn.lock uses a bespoke format",
    "pnpm-lock.yaml": "pnpm-lock.yaml is YAML and needs a parser this script deliberately avoids",
    "Gemfile.lock": "Gemfile.lock is not supported",
    "composer.lock": "composer.lock is not supported",
    "go.sum": "go.sum is not supported",
}


def deps_from_package_lock(path: Path) -> list[tuple[str, str, str]]:
    """npm lockfile v2/v3. Returns (ecosystem, name, version)."""
    data = json.loads(path.read_text())
    out = []
    for key, meta in (data.get("packages") or {}).items():
        if not key or not isinstance(meta, dict):
            continue                      # "" is the root project itself
        name = meta.get("name") or key.split("node_modules/")[-1]
        version = meta.get("version")
        if name and version and not meta.get("link"):
            out.append(("npm", name, version))
    if not out:                           # lockfileVersion 1 uses "dependencies"
        def walk(d):
            for name, meta in (d or {}).items():
                v = meta.get("version")
                if v:
                    out.append(("npm", name, v))
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def deps_from_uv_lock(path: Path) -> list[tuple[str, str, str]]:
    data = tomllib.loads(path.read_text())
    return [("PyPI", p["name"], p["version"])
            for p in data.get("package", []) if p.get("name") and p.get("version")]


def deps_from_requirements(path: Path) -> list[tuple[str, str, str]]:
    """Only `==` pins are checkable. A floating range has no single version to query."""
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            out.append(("PyPI", m.group(1), m.group(2)))
    return out


PARSERS = {
    "package-lock.json": deps_from_package_lock,
    "uv.lock": deps_from_uv_lock,
    "requirements.txt": deps_from_requirements,
}


def discover(root: Path) -> tuple[list[tuple[str, str, str]], list[str]]:
    deps, unchecked = [], []
    for name, parser in PARSERS.items():
        for f in sorted(root.rglob(name)):
            if "node_modules" in f.parts:
                continue
            try:
                found = parser(f)
                deps.extend(found)
            except Exception as e:
                unchecked.append(f"{f.relative_to(root)}: could not parse ({e})")
    for name, why in UNSUPPORTED.items():
        for f in sorted(root.rglob(name)):
            if "node_modules" in f.parts:
                continue
            unchecked.append(f"{f.relative_to(root)}: {why} — run `osv-scanner scan source` here")
    # de-duplicate; a monorepo lists the same package many times
    return sorted(set(deps)), unchecked


# --- Runtime end-of-life -----------------------------------------------------
def runtime_eol(root: Path) -> list[dict]:
    """No advisory database indexes runtimes, so nothing else reports this."""
    found = []
    today = datetime.date.today().isoformat()

    declared: list[tuple[str, str]] = []
    pkg = root / "package.json"
    if pkg.exists():
        try:
            engines = json.loads(pkg.read_text()).get("engines", {})
            if "node" in engines:
                m = re.search(r"(\d+)", str(engines["node"]))
                if m:
                    declared.append(("nodejs", m.group(1)))
        except Exception:
            pass
    pyver = root / ".python-version"
    if pyver.exists():
        m = re.search(r"(\d+\.\d+)", pyver.read_text())
        if m:
            declared.append(("python", m.group(1)))

    for product, cycle in declared:
        try:
            cycles = {str(c["cycle"]): c.get("eol") for c in _get(EOL_API.format(product))}
        except Unreachable:
            continue
        eol = cycles.get(cycle)
        if isinstance(eol, str) and eol < today:
            found.append({"product": product, "cycle": cycle, "eol": eol})
    return found


# --- Enrichment --------------------------------------------------------------
def scan(deps: list[tuple[str, str, str]]) -> dict[str, dict]:
    """OSV batch -> {cve: {packages, ids}}. Batched 500 at a time per the API."""
    hits: dict[str, dict] = {}
    for i in range(0, len(deps), 500):
        chunk = deps[i:i + 500]
        queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]
        res = _post(OSV_BATCH, {"queries": queries})
        for (eco, name, ver), r in zip(chunk, res.get("results", [])):
            for v in r.get("vulns", []):
                vid = v["id"]
                hits.setdefault(vid, {"id": vid, "packages": set(), "cve": None})
                hits[vid]["packages"].add(f"{name}@{ver}")
    # resolve CVE aliases so EPSS and KEV can be joined on them
    for vid, h in hits.items():
        if vid.startswith("CVE-"):
            h["cve"] = vid
    return hits


def add_cves(hits: dict[str, dict]) -> None:
    for vid, h in hits.items():
        if h["cve"]:
            continue
        try:
            adv = _get(OSV_VULN + vid)
        except Unreachable:
            continue
        for a in adv.get("aliases", []) or []:
            if a.startswith("CVE-"):
                h["cve"] = a
                break


def add_epss(hits: dict[str, dict]) -> None:
    cves = sorted({h["cve"] for h in hits.values() if h["cve"]})
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        try:
            data = _get(EPSS_API.format(",".join(chunk)))
        except Unreachable:
            continue
        scores = {r["cve"]: float(r["epss"]) for r in data.get("data", [])}
        for h in hits.values():
            if h["cve"] in scores:
                h["epss"] = scores[h["cve"]]


def add_kev(hits: dict[str, dict]) -> None:
    try:
        kev = _get(KEV_FEED)
    except Unreachable:
        return
    listed = {v["cveID"]: v["dateAdded"] for v in kev.get("vulnerabilities", [])}
    for h in hits.values():
        if h["cve"] in listed:
            h["kev"] = listed[h["cve"]]


# --- pwn.watch live incidents (opt-in: --pwnwatch) ----------------------------
# OSV indexes packages, not runtimes, and ingests vendor-only advisories days after they
# land. pwn.watch tracks both as incidents with free-text affected/fixed versions. It is a
# TRACKER, not the vendor: every hit is reported with its vendor sources, and those are
# what a fix must cite.
#
# The HTTP client, the sanitiser and the trusted vendor-host list live in
# watch-advisories.py and are loaded from there, not copied: feed text is untrusted and
# there must be exactly one place that cleans it. Matching runs on the sanitised text.
#
# affectedVersions is prose, read with a STRICT grammar. A clause yields a verdict only when
# every token in it is consumed by a known pattern ("< X", ">= X, < Y", "before X", "X to Y",
# "X or later", "between X and Y", "X.x before Y", a bare version list...). One leftover word,
# number or operator makes the whole incident "check manually" for that package. The matcher
# never reports clean from text it could not read completely: "not-affected" is issued only by
# _pw_conclude, and only when the sanitiser left the text unaltered, every affected line was
# read or attributed to something else the script recognises, and nothing was left unread.

PWN_UA = "secaudit-monitor-deps (+https://github.com/DrMxrcy/secaudit)"
PWN_SKIP_DIRS = {"node_modules", "vendor", ".git", ".venv", "venv", "__pycache__"}
PWN_FILE_TAGS = {
    "package-lock.json": ("node", "npm"), "package.json": ("node", "npm"),
    "yarn.lock": ("node", "npm"), "pnpm-lock.yaml": ("node", "npm"),
    ".nvmrc": ("node",), ".node-version": ("node",),
    "uv.lock": ("python", "pypi"), "requirements.txt": ("python", "pypi"),
    "pyproject.toml": ("python", "pypi"), ".python-version": ("python",),
    "composer.json": ("php",), "composer.lock": ("php",), ".php-version": ("php",),
    "Gemfile.lock": ("ruby",), "go.sum": ("go",),
}
PWN_COMPOSE = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
PWN_RUNTIME_TAG = {"php": "php", "node": "node", "bun": "node", "python": "python"}
PWN_RUNTIME_NAME = {"php": "PHP", "node": "Node.js", "bun": "Bun", "python": "Python"}
PWN_RUNTIME_LABEL = {"php": r"PHP", "node": r"Node(?:\.js)?", "bun": r"Bun", "python": r"C?Python"}
PWN_RUNTIME_ANY = {k: re.compile(rf"(?<![\w./@-]){v}(?![\w/-])", re.I) for k, v in PWN_RUNTIME_LABEL.items()}
PWN_RUNTIME_START = {k: re.compile(rf"\s*{v}(?![\w/-])", re.I) for k, v in PWN_RUNTIME_LABEL.items()}
# How many version components name a supported release line.
PWN_LINE_PARTS = {"php": 2, "python": 2, "node": 1, "bun": 2}
# Official images: only their tags are read as runtime versions.
PWN_IMAGES = {"php": "php", "node": "node", "python": "python", "oven/bun": "bun"}
# Any other image whose last path component is one of these (a mirror, bitnami/node, ...)
# carries that runtime at a version its tag does not reliably state: reported as check.
PWN_IMAGE_TAILS = {"php": "php", "node": "node", "python": "python", "bun": "bun"}
PWN_TOOL_VERSIONS = {"nodejs": "node", "node": "node", "php": "php", "python": "python", "bun": "bun"}
# Official-image tag suffixes that name a variant, not a different version.
_PW_TAG_VARIANT = re.compile(r"cli|fpm|apache|zts|alpine[\d.]*|bookworm|bullseye|buster|stretch|trixie|slim|debian|"
                             r"distroless|jammy|noble|focal|windowsservercore|nanoserver|ltsc\d{4}|\d{4}|musl|glibc",
                             re.I)
# Words that may lead a runtime clause without naming some other product.
PWN_GENERIC = {"eol", "end-of-life", "lines", "line", "branches", "branch", "versions",
               "version", "all", "releases", "release", "supported", "unsupported", "older",
               "earlier", "and", "the", "from", "affected", "series"}
# Package names that are also everyday words: matched only in "name <version>" position.
PWN_COMMON = {"is", "the", "and", "or", "to", "in", "on", "of", "for", "before", "after",
              "see", "all", "any", "with", "from", "via", "up", "not", "it", "as", "by", "at",
              "be", "go", "node", "npm", "next", "core", "latest", "new", "fix", "patch"}
PWN_FIELDS = ("slug", "title", "product", "status", "category", "severity", "patchStatus",
              "cveIds", "tags", "affectedVersions", "fixedVersions", "updatedAt")
PWN_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
PWN_VERDICT = {"affected": 0, "check": 1, "not-affected": 2}
PWN_REPORT_CAP = 25
PWN_MANUAL_CAP = 10
PWN_FEED_CAP = 300
PWN_DETAIL_FAILS = 2
PWN_STATE_VERSION = 1
# An ETag is a quoted printable-ASCII token. Anything else in the state file is dropped.
_PW_ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]{0,200}"')

_PRE = r"(?:-(?:alpha|beta|rc|pre|preview|canary|next|dev|nightly|snapshot)[0-9A-Za-z.]*|(?:a|b|rc)\d+|\.post\d+|\.dev\d+)"
_VERD = rf"(?:v?\d+(?:\.\d+)+(?:\.[xX*])?{_PRE}?|v?\d+\.[xX*])"       # standalone: needs a dot


def _vparse(text: str):
    """'v16.4.0' -> ((16, 4, 0), pre, partial). None when it is not a version we can order."""
    if not isinstance(text, str):
        return None
    t = text.strip().split("+")[0].lstrip("vV")
    m = re.fullmatch(r"(\d+(?:\.\d+)*)(\.[xX*])?(?:[-.]?([A-Za-z][0-9A-Za-z.-]*))?", t)
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    return nums, m.group(3) or "", bool(m.group(2)) or len(nums) < 3


# Pre-release labels in order. Anything else (canary, next, nightly, ...) has no defined order.
_PW_PRE_RANK = {"a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "pre": 3, "preview": 3}
_PW_FINAL = ((2,), (0,), (1,))


def _vphase(pre: str) -> tuple:
    """The (pre, post, dev) part of a sort key, in PEP 440 order:
    X.devN < X.aN.devM < X.aN < X.aN.postM < X.bN < X.rcN < X < X.postN.devM < X.postN.

    Numbers compare as numbers (rc9 < rc10) and spelling does not matter ('-rc.1', 'rc1' and
    'RC1' are equal). A label with no defined order gets pre-release rank 0, which
    _v_ambiguous treats as unordered.
    """
    s = (pre or "").lower()
    if not s:
        return _PW_FINAL
    groups: list = []
    for part in re.findall(r"[a-z]+|\d+", s):
        if part.isdigit():
            if not groups:
                groups.append(["", []])
            groups[-1][1].append(int(part))
        else:
            groups.append([part, []])
    known = not re.search(r"[^a-z0-9._-]", s)
    pre_t = post_t = dev_t = None
    for word, nums in groups:
        n = tuple(nums) or (0,)
        if word in _PW_PRE_RANK and pre_t is None and post_t is None and dev_t is None:
            pre_t = (1, _PW_PRE_RANK[word]) + n
        elif word in ("post", "rev", "r") and post_t is None and dev_t is None:
            post_t = (1,) + n
        elif word == "dev" and dev_t is None:
            dev_t = (0,) + n
        else:
            known = False
    if not known:
        return ((1, 0) + (tuple(groups[0][1]) if groups and groups[0][1] else (0,)), (0,), (1,))
    a = pre_t if pre_t else ((0,) if dev_t and not post_t else (2,))
    return (a, post_t or (0,), dev_t or (1,))


def _vkey(nums: tuple, pre: str = "") -> tuple:
    """Sort key: six numeric parts, then _vphase (pre-releases below the release, .postN above)."""
    return (tuple(nums) + (0,) * 6)[:6] + (_vphase(pre),)


def _v_ambiguous(k: tuple, bound) -> bool:
    """Is installed key k unreliably ordered against a range bound or fixed version?

    Only when k is a pre/post/dev release of the very version the bound names: whether
    '8.3.x', '<= 1.0.0' or 'fixed in 3.13.0' covers 8.3.0rc1 or 1.0.0.post1 differs between
    npm, PEP 440 and vendor prose, and a label like 'canary' has no order at all.
    """
    if bound is None or k[:6] != bound[:6] or k[6] == _PW_FINAL:
        return False

    def ordered(phase):
        return not (phase[0][0] == 1 and phase[0][1] == 0)
    return bound[6] == _PW_FINAL or not (ordered(k[6]) and ordered(bound[6]))


def _bump(nums: tuple) -> tuple:
    return tuple(nums[:-1]) + (nums[-1] + 1,)


# --- pwn.watch: the strict range grammar --------------------------------------------
# A range is (lo, lo_incl, hi, hi_incl, soft) over _vkey keys; None is unbounded. A soft
# range (caret/tilde) proves "affected" from inside it but never "not affected" from outside.
_PW_IDS = re.compile(r"\b(?:CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3})\b", re.I)
_PW_VLIST = r"v?\d[\w.+-]*(?:\s*(?:,|/|\band\b)\s*v?\d[\w.+-]*)*"
_PW_FIXED_PAREN = re.compile(rf"\s*(?:fixed|patched|resolved)\b(?:\s+(?:in|on|at|by|with))?\s*:?\s*{_PW_VLIST}\s*", re.I)
_PW_FIXED = re.compile(rf"(?<!\bnot\s)[,;]?\s*\b(?:fixed|patched|resolved)\b(?:\s+(?:in|on|at|by|with))?\s*:?\s*"
                       rf"{_PW_VLIST}(?=\s*(?:$|[;,]))", re.I)
# The sanitiser already folds these; direct callers get the same reading.
_PW_FOLD = str.maketrans({"\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
                          "\u2015": "-", "\u2212": "-", "\u2264": "<=", "\u2265": ">="})
# Parentheticals are dropped only from an allow-list: a bare ecosystem/runtime label, a
# "(fixed X / Y)" note on an affected line, or a vulnerability label that carries an advisory
# id and no digit, modifier or widening word. Anything else, "(including canary releases)",
# "(Windows only)", "(and the legacy branch)", is kept as [..], which nothing parses: check.
_PW_PAREN_OK = {"php", "npm", "pypi", "node", "node.js", "nodejs", "python", "cpython", "bun", "composer",
                "packagist", "pip", "yarn", "pnpm"}
_PW_PAREN_WIDEN = re.compile(r"\b(?:includ\w*|and|also|plus|all|any|every|each|canary|nightly|legacy|branch(?:es)?|"
                             r"lines?|series|releases?|versions?|builds?|pre-?releases?|alpha|beta|rc|lts|other|"
                             r"too|well|older|newer|previous|earlier|later|or)\b", re.I)
_PW_MODIFIERS = re.compile(r"\b(?:later|newer|older|earlier|above|below|higher|lower|greater|less|prior|before|"
                           r"after|since|until|till|onwards?|upwards?|through|thru|up|except|excluding|excluded|"
                           r"not|only|unaffected|inclusive|exclusive)\b", re.I)
_PW_TOKEN = re.compile(r"""
    (?P<ver>v?\d+(?:\.\d+)*(?:\.[x*])?
        (?:-(?:alpha|beta|rc|pre|preview|canary|next|dev|nightly|snapshot)[0-9a-z.]*|(?:a|b|rc)\d+|\.post\d+|\.dev\d+)?
        (?:\+[0-9a-z][0-9a-z.]*)?)(?![0-9a-z])
  | (?P<op>>=|<=|==|!=|=>|=<|~>|->|\.\.|>|<|=|\^|~)
  | (?P<punct>[,;/&+:-])
  | (?P<word>[a-z](?:[a-z-]*[a-z])?)
  | (?P<ws>\s+)
  | (?P<other>.)
""", re.X)
_PW_LEAD = {"all", "any", "every", "versions", "version", "releases", "release", "everything",
            "including", "branch", "branches", "line", "lines", "series"}
_PW_TRAIL = {"versions", "version", "releases", "release", "line", "branch", "series", "inclusive", "only"}
_PW_SEPS = [(",", "and"), (",", "or"), (",", "plus"), (",", "also"), (";", "and"), (";", "or"),
            ("and", "also"), (",",), (";",), ("/",), ("&",), ("and",), ("or",), ("plus",), ("also",)]
_PW_UPPER = [(("up", "to", "and", "including"), True), (("up", "to", "but", "not", "including"), False),
             (("up", "to", "but", "excluding"), False), (("up", "to"), True), (("up", "until"), False),
             (("before",), False), (("prior", "to"), False), (("below",), False), (("earlier", "than"), False),
             (("older", "than"), False), (("less", "than"), False), (("lower", "than"), False),
             (("under",), False), (("until",), False), (("till",), False), (("pre", "-"), False),
             (("through",), True), (("thru",), True), (("at", "most"), True)]
_PW_LOWER = [(("starting", "from"), True), (("starting", "with"), True), (("starting", "at"), True),
             (("as", "of"), True), (("at", "least"), True), (("since",), True), (("from",), True),
             (("after",), False), (("greater", "than"), False), (("newer", "than"), False),
             (("higher", "than"), False), (("later", "than"), False)]
_PW_OLDER = {"earlier", "older", "below", "lower", "prior", "before"}
_PW_NEWER = {"later", "newer", "above", "higher", "greater", "up", "upward", "upwards"}
_PW_ONWARD = {"onwards", "onward", "upwards", "upward"}
_PW_SPAN = {"-", "to", "through", "thru", "..", "->"}


def _pw_clean_line(text: str, fixed_phrases: bool = True) -> str:
    """Drop advisory ids, allow-listed parentheticals and (on affected text) 'fixed in X'.

    Every other parenthetical is kept as [..], which the grammar cannot read, so whoever reads
    it says check. Idempotent. fixed_phrases=False is for fixedVersions text, where 'fixed in'
    is the content rather than a note.
    """
    s = _PW_IDS.sub(" \x01 ", text.translate(_PW_FOLD))

    def paren(m):
        inner = m.group(1)
        rest = re.sub(r"\s+", " ", inner.replace("\x01", " ")).strip()
        if not rest.strip(" ,;/&"):
            return " "                                # "()", "(CVE-2026-1)", "(CVE-a, CVE-b)"
        if fixed_phrases and _PW_FIXED_PAREN.fullmatch(rest):
            return " "                                # "(fixed 1.0.10 / 1.1.1 / 1.2.1)"
        if rest.lower() in _PW_PAREN_OK:
            return " "                                # "(npm)", "(PHP)"
        if ("\x01" in inner and not re.search(r"\d", rest) and not _PW_MODIFIERS.search(rest)
                and not _PW_PAREN_WIDEN.search(rest)):
            return " "                                # "(Image Optimization SVG RCE, CVE-2026-96889)"
        return f" [{rest}] "
    prev = None
    while prev != s:
        prev, s = s, re.sub(r"\(([^()]*)\)", paren, s)
    s = s.replace("\x01", " ")
    if fixed_phrases:
        s = _PW_FIXED.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()


def _r_lo(v, incl: bool):
    nums, pre = v[2][0], v[2][1]
    if not incl and v[4]:                             # "> 2.x" starts above every 2.x
        return _vkey(_bump(nums)), True
    return _vkey(nums, pre), incl


def _r_hi(v, incl: bool):
    nums, pre, partial = v[2]
    if incl and partial:                              # "through 8.5" means every 8.5.x
        return _vkey(_bump(nums)), False
    return _vkey(nums, pre), incl


def _r_exact(v):
    nums, pre, partial = v[2]
    if partial:                                       # "1.2.x" / "1.2": the whole line
        return (_vkey(nums), True, _vkey(_bump(nums)), False, False)
    k = _vkey(nums, pre)
    return (k, True, k, True, False)


def _r_soft(op: str, v):
    nums = v[2][0]
    if op == "^":                                     # ^1.2.3 <2.0.0, ^0.2.3 <0.3.0, ^0.0.3 <0.0.4
        i = next((i for i, n in enumerate(nums) if n), len(nums) - 1)
        hi = tuple(nums[:i]) + (nums[i] + 1,)
    elif op == "~":                                   # ~1.2.3 <1.3.0, ~1 <2.0.0
        hi = _bump(nums[:2])
    else:                                             # ~> 1.2 <2.0, ~> 1.2.3 <1.3
        hi = _bump(nums[:-1]) if len(nums) > 1 else _bump(nums)
    return (_vkey(nums, v[2][1]), True, _vkey(hi), False, True)


def _pw_core(t: list, i: int) -> list:
    """Every way one range construct can be read starting at token i: [(ranges, end)]."""
    n, out = len(t), []
    if i >= n:
        return out

    def ver(k, dotted=False):
        return t[k] if k < n and t[k][0] == "ver" and (t[k][3] or not dotted) else None

    def words(k, seq):
        ok = k + len(seq) <= n and all(t[k + m][1] == w and t[k + m][0] != "ver" for m, w in enumerate(seq))
        return k + len(seq) if ok else None

    kind, text = t[i][0], t[i][1]
    if kind == "op":
        v = ver(i + 1)
        if not v:
            return out
        if text in (">=", "=>", ">"):
            lo = _r_lo(v, text != ">")
            for j in (i + 3, i + 2):                  # ">= X, < Y" / ">= X and < Y" / ">= X < Y"
                if j == i + 3 and not (i + 2 < n and t[i + 2][1] in (",", "and")):
                    continue
                w = ver(j + 1)
                if j < n and t[j][0] == "op" and t[j][1] in ("<", "<=", "=<") and w:
                    hi = _r_hi(w, t[j][1] != "<")
                    if lo[0] < hi[0] or (lo[0] == hi[0] and lo[1] and hi[1]):
                        out.append(([(lo[0], lo[1], hi[0], hi[1], False)], j + 2))
            out.append(([(lo[0], lo[1], None, False, False)], i + 2))
        elif text in ("<", "<=", "=<"):
            hi = _r_hi(v, text != "<")
            out.append(([(None, False, hi[0], hi[1], False)], i + 2))
        elif text in ("=", "=="):
            out.append(([_r_exact(v)], i + 2))
        elif text in ("^", "~", "~>"):
            out.append(([_r_soft(text, v)], i + 2))
        return out
    if kind == "word":
        for seq, incl in _PW_UPPER:
            j = words(i, seq)
            if j is not None and ver(j):
                hi = _r_hi(ver(j), incl)
                out.append(([(None, False, hi[0], hi[1], False)], j + 1))
        for seq, incl in _PW_LOWER:
            j = words(i, seq)
            if j is not None and ver(j):
                lo = _r_lo(ver(j), incl)
                out.append(([(lo[0], lo[1], None, False, False)], j + 1))
        conns = {"from": {"to": True, "through": True, "thru": True, "-": True, "until": False, "before": False},
                 "between": {"and": True}}.get(text)
        a, b = ver(i + 1, True), ver(i + 3, True)
        if conns and a and b and t[i + 2][1] in conns:
            lo, hi = _r_lo(a, True), _r_hi(b, conns[t[i + 2][1]])
            if lo[0] <= hi[0]:
                out.append(([(lo[0], True, hi[0], hi[1], False)], i + 4))
        return out
    line = ver(i)
    if line and line[2][2]:                           # "4.x before 4.19.2", "8.3 before 8.3.36", "14 before 14.1.1"
        for seq, incl in ((("before",), False), (("<",), False), (("<=",), True), (("prior", "to"), False)):
            j = words(i + 1, seq)
            w = ver(j) if j is not None else None
            if w and (line[4] or tuple(w[2][0][:len(line[2][0])]) == line[2][0]):
                lo, hi = _r_lo(line, True), _r_hi(w, incl)
                if lo[0] < hi[0]:
                    out.append(([(lo[0], True, hi[0], hi[1], False)], j + 1))
    v = ver(i, True)
    if not v:
        return out
    out.append(([_r_exact(v)], i + 1))
    if i + 1 < n and t[i + 1][1] in _PW_SPAN and t[i + 1][0] != "ver":
        j, incl = i + 2, True
        if t[i + 1][1] in ("to", "through", "thru") and j < n and t[j][1] == "before":
            j, incl = j + 1, False
        w = ver(j, True)
        if w:
            lo, hi = _r_lo(v, True), _r_hi(w, incl)
            if lo[0] <= hi[0]:
                out.append(([(lo[0], True, hi[0], hi[1], False)], j + 1))
    j = i + 1
    if j < n and t[j][1] in ("and", "or"):
        j2 = j + 1 + (1 if j + 1 < n and t[j + 1][1] == "all" else 0)
        if j2 < n and t[j2][0] == "word" and t[j2][1] in _PW_OLDER:
            hi = _r_hi(v, True)
            out.append(([(None, False, hi[0], hi[1], False)], j2 + 1))
        if j2 < n and t[j2][0] == "word" and t[j2][1] in _PW_NEWER:
            lo = _r_lo(v, True)
            out.append(([(lo[0], True, None, False, False)], j2 + 1))
    if j < n and (t[j][1] == "+" or (t[j][0] == "word" and t[j][1] in _PW_ONWARD)):
        lo = _r_lo(v, True)
        out.append(([(lo[0], True, None, False, False)], j + 1))
    return out


def _pw_clause(t: list, i: int) -> list:
    """Readings of one clause (optional filler words around a construct), longest first."""
    out, starts, j = [], [i], i
    while j < len(t) and t[j][0] == "word" and t[j][1] in _PW_LEAD:
        j += 1
        starts.append(j)
    for s in starts:
        for ranges, e in _pw_core(t, s):
            out.append((ranges, e))
            while e < len(t) and t[e][0] == "word" and t[e][1] in _PW_TRAIL:
                e += 1
                out.append((ranges, e))
    out.sort(key=lambda o: -o[1])
    return out


def _pw_tokens(text: str) -> list | None:
    toks = []
    for m in _PW_TOKEN.finditer(text.lower()):
        kind, txt = m.lastgroup, m.group(0)
        if kind == "ws":
            continue
        if kind == "other":
            return None
        if kind == "ver":
            p = _vparse(txt)
            if not p:
                return None
            core = txt.split("+")[0]
            toks.append(("ver", txt, p, "." in core, bool(re.match(r"v?\d+(?:\.\d+)*\.[x*]", core))))
        else:
            toks.append((kind, txt, None, False, False))
    return toks


def _pw_ranges(text: str):
    """Parse an affected-range phrase into [(lo, lo_incl, hi, hi_incl, soft)].

    Returns None unless EVERY token was consumed: CLAUSE (SEP CLAUSE)*, where SEP is a comma,
    semicolon, slash, '&', 'and', 'or' or 'plus'. A version list with nothing else in it is
    the only form of exact match.
    """
    if not isinstance(text, str):
        return None
    s = _pw_clean_line(text).strip(" ,;:/&")
    s = re.sub(r"^@(?=v?\d|[<>=^~])", "", s)          # name@1.2.3, name@<1.2.3
    s = re.sub(r"(?:\s*(?:[,;/&]|\band\b|\bor\b|\bplus\b))+$", "", s, flags=re.I).strip()
    t = _pw_tokens(s)
    if not t:
        return None
    memo: dict[int, list | None] = {}

    def parse(i):
        if i not in memo:
            memo[i] = None
            for ranges, e in _pw_clause(t, i):
                if e == len(t):
                    memo[i] = ranges
                    break
                for sep in _PW_SEPS:
                    if e + len(sep) < len(t) and all(t[e + m][1] == w and t[e + m][0] != "ver"
                                                     for m, w in enumerate(sep)):
                        rest = parse(e + len(sep))
                        if rest is not None:
                            memo[i] = ranges + rest
                            break
                if memo[i] is not None:
                    break
        return memo[i]
    return parse(0)


def _in_range(r, k) -> bool:
    lo, lo_incl, hi, hi_incl = r[:4]
    return ((lo is None or k > lo or (k == lo and lo_incl))
            and (hi is None or k < hi or (k == hi and hi_incl)))


def _range_meets_line(r, line: tuple) -> bool:
    lo, _, hi, hi_incl = r[:4]
    line_lo, line_hi = _vkey(line), _vkey(_bump(line))
    return (hi is None or hi > line_lo or (hi == line_lo and hi_incl)) and (lo is None or lo < line_hi)


def _pw_load_watcher():
    """Load watch-advisories.py (hyphenated filename, so not importable by name)."""
    path = Path(__file__).resolve().parent / "watch-advisories.py"
    if not path.is_file():
        raise FileNotFoundError(f"--pwnwatch needs {path} (the pwn.watch client and sanitiser); "
                                f"it ships next to this script in the secaudit repo")
    spec = importlib.util.spec_from_file_location("secaudit_watch_advisories", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr in ("_get", "sanitise", "Unreachable", "load_state", "norm_time", "BASE", "CATEGORIES", "SLUG_RE"):
        if not hasattr(mod, attr):
            raise ImportError(f"{path} does not provide {attr}; it is not the expected version")
    mod.UA = PWN_UA                               # _get reads the module global at call time
    return mod


def _pw_default_state() -> Path | None:
    """A user cache dir, so a scan never writes into the repository it is scanning."""
    base = os.environ.get("XDG_CACHE_HOME")
    try:
        root = Path(base) if base and os.path.isabs(base) else Path.home() / ".cache"
    except RuntimeError:
        return None
    return root / "secaudit" / "pwnwatch-state.json"


# --- pwn.watch: what is in the repo ---------------------------------------------
def _pw_walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in PWN_SKIP_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


def _pw_safe(text, limit: int = 120) -> str:
    """Repo-controlled text (paths, constraints, FROM refs) as one printable-ASCII line."""
    s = re.sub(r"[^\x20-\x7e]", "?", str(text)).replace("`", "?")
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _pw_floor(text) -> str | None:
    """Lowest version a constraint admits: '^8.1 || ^8.2' -> 8.1, '>=20' -> 20.

    None when some alternative has no lower bound ('<20', '*') or nothing names a version.
    """
    floors = []
    for alt in str(text).split("||"):
        found = [m.group(2) for m in re.finditer(r"(>=|=>|<=|=<|>|<|\^|~>|~|=)?\s*v?(\d+(?:\.\d+){0,2})", alt)
                 if (m.group(1) or "") not in ("<", "<=", "=<")]
        if not found:
            return None
        floors.append(min(found, key=lambda f: _vkey(tuple(int(x) for x in f.split(".")))))
    return min(floors, key=lambda f: _vkey(tuple(int(x) for x in f.split(".")))) if floors else None


def _pw_version_pin(text) -> tuple[str | None, bool]:
    """A version file / pin: 'v20.11.1' -> ('20.11.1', True), '20.x' -> ('20', False), 'lts/*' -> (None, False)."""
    t = str(text).strip() if isinstance(text, str) else ""
    m = re.fullmatch(r"v?(\d+(?:\.\d+){0,2})(\.[xX*])?", t)
    if not m:
        return None, False
    return m.group(1), len(m.group(1).split(".")) >= 3 and not m.group(2)


def _pw_from_line(line: str):
    """FROM [--platform=..] image[:tag][@digest] [AS name] -> (ref, stage name or None)."""
    m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
    return (m.group(1), m.group(2)) if m else None


def _pw_image(ref: str):
    """Image reference -> (runtime, version, why the version is unknown, unresolved)."""
    if not re.fullmatch(r"[A-Za-z0-9._:/@${}-]+", ref):
        return None, None, "is not a valid image reference", True
    image = ref.split("@")[0]
    name, tag = image.rsplit(":", 1) if ":" in image.rsplit("/", 1)[-1] else (image, "")
    if "$" in name:
        return None, None, "is set by a build argument", True
    if "$" in tag:
        tag = "$"                                     # php:${V}-fpm: the runtime is known, its version is not
    parts = name.lower().split("/")
    registry = parts[0] if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost") else None
    path = "/".join(parts[1:] if registry else parts)
    if registry in (None, "docker.io", "index.docker.io", "registry-1.docker.io") and path.startswith("library/"):
        path = path[len("library/"):]
    if registry in (None, "docker.io", "index.docker.io", "registry-1.docker.io") and path in PWN_IMAGES:
        if not tag:
            return PWN_IMAGES[path], None, "no tag, so it floats with 'latest'", False
        m = re.fullmatch(r"v?(\d+(?:\.\d+)*)(?:-?((?:alpha|beta|rc|a|b)\d*))?((?:-[A-Za-z0-9._]+)*)", tag, re.I)
        if m:
            # '-RC1' is the pre-release; every other suffix must be a known variant, or the
            # version may not be what it looks like ('8.4.27-foo1' is not 8.4.27).
            if all(_PW_TAG_VARIANT.fullmatch(v) for v in m.group(3).split("-")[1:]):
                return PWN_IMAGES[path], m.group(1) + (m.group(2) or ""), None, False
            return (PWN_IMAGES[path], None, f"the tag '{_pw_safe(tag, 40)}' has a suffix this script does not "
                                            f"recognise, so its version is not read", False)
        if tag == "$":
            return PWN_IMAGES[path], None, "the tag is set by a build argument", False
        return PWN_IMAGES[path], None, f"the tag '{_pw_safe(tag, 40)}' does not name a version", False
    rt = PWN_IMAGE_TAILS.get(path.rsplit("/", 1)[-1])
    if rt:
        return rt, None, "not an official image, so its tag does not reliably state the runtime version", False
    return None, None, None, False


def pwn_detect(root: Path, deps, unchecked: list | None = None) -> tuple[list[str], list[dict]]:
    """Tags to query and the runtime versions the repo declares.

    A declaration that cannot be read becomes a runtime with version None, which matches every
    incident for that runtime as "check manually". A base image that cannot be resolved at all
    (FROM ${BASE}) is appended to `unchecked`.
    """
    tags: set[str] = set()
    runtimes: list[dict] = []
    notes = unchecked if unchecked is not None else []

    def runtime(rt, version, exact, source, detail, constraint=False, why=None):
        d = {"runtime": rt, "version": version, "exact": bool(exact and version), "constraint": constraint,
             "source": _pw_safe(source), "detail": _pw_safe(detail)}
        if why:
            d["why"] = _pw_safe(why, 160)

        def ident(r):
            if r["version"] is None or r["constraint"]:
                return r["runtime"], r["version"], r["constraint"], r["detail"]
            return r["runtime"], r["version"], r["exact"]
        if not any(ident(r) == ident(d) for r in runtimes):
            runtimes.append(d)
        tags.add(PWN_RUNTIME_TAG[rt])

    def image(ref, rel, detail):
        rt, ver, why, unresolved = _pw_image(ref)
        if unresolved:
            notes.append(f"{_pw_safe(rel)}: {_pw_safe(detail)} {why}, so the base image and any runtime "
                         f"in it were not checked")
        elif rt:
            runtime(rt, ver, bool(ver) and len(_vparse(ver)[0]) >= 3, rel, detail, why=why)

    def unreadable(rt, rel, what):
        runtime(rt, None, False, rel, what, why=f"{what}, so the runtime version it declares was not read")

    for f in _pw_walk(root):
        rel = str(f.relative_to(root))
        name = f.name
        tags.update(PWN_FILE_TAGS.get(name, ()))
        if f.parent.name == "workflows" and f.parent.parent.name == ".github" and f.suffix in (".yml", ".yaml"):
            tags.add("github-actions")
        try:
            if name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
                tags.add("docker")
                stages: set[str] = set()
                for line in f.read_text(errors="replace").splitlines():
                    hit = _pw_from_line(line)
                    if not hit:
                        continue
                    ref, stage = hit
                    if ref.lower() not in stages and ref.lower() != "scratch":
                        image(ref, rel, f"FROM {ref}")
                    if stage:
                        stages.add(stage.lower())
            elif name in PWN_COMPOSE or (name.startswith("docker-compose.") and f.suffix in (".yml", ".yaml")):
                tags.add("docker")
                for line in f.read_text(errors="replace").splitlines():
                    m = re.match(r"\s*-?\s*image:\s*[\"']?([^\"'\s#]+)", line)
                    if m:
                        image(m.group(1), rel, f"image: {m.group(1)}")
            elif name == "package.json":
                try:
                    data = json.loads(f.read_text(errors="replace"))
                except ValueError:
                    data = None
                if not isinstance(data, dict):
                    unreadable("node", rel, "package.json could not be parsed as a JSON object")
                    continue
                engines = data.get("engines")
                if engines is not None and not isinstance(engines, dict):
                    unreadable("node", rel, "package.json engines is not an object")
                for rt in ("node", "bun"):
                    if isinstance(engines, dict) and rt in engines:
                        c = engines[rt]
                        if isinstance(c, str):
                            runtime(rt, _pw_floor(c), False, rel, f"engines.{rt} {c}", constraint=True)
                        else:
                            unreadable(rt, rel, f"engines.{rt} is not a string")
                    volta = data.get("volta")
                    if isinstance(volta, dict) and rt in volta:
                        v, exact = _pw_version_pin(volta[rt])
                        runtime(rt, v, exact, rel, f"volta.{rt} {volta[rt]}",
                                why=None if v else f"volta.{rt} does not name a version")
                pm = data.get("packageManager")
                if isinstance(pm, str) and pm.lower().startswith("bun@"):
                    v, exact = _pw_version_pin(pm[4:].split("+")[0])
                    runtime("bun", v, exact, rel, f"packageManager {pm}",
                            why=None if v else "packageManager does not name a bun version")
            elif name == "composer.json":
                try:
                    data = json.loads(f.read_text(errors="replace"))
                except ValueError:
                    data = None
                if not isinstance(data, dict):
                    unreadable("php", rel, "composer.json could not be parsed as a JSON object")
                    continue
                req = data.get("require")
                if req is not None and not isinstance(req, dict):
                    unreadable("php", rel, "composer.json require is not an object")
                elif isinstance(req, dict) and "php" in req:
                    if isinstance(req["php"], str):
                        runtime("php", _pw_floor(req["php"]), False, rel, f"require.php {req['php']}", constraint=True)
                    else:
                        unreadable("php", rel, "require.php is not a string")
                config = data.get("config")
                platform = config.get("platform") if isinstance(config, dict) else None
                if isinstance(platform, dict) and "php" in platform:
                    if isinstance(platform["php"], str):
                        runtime("php", _pw_floor(platform["php"]), False, rel,
                                f"config.platform.php {platform['php']}", constraint=True)
                    else:
                        unreadable("php", rel, "config.platform.php is not a string")
            elif name in (".nvmrc", ".node-version", ".php-version", ".python-version"):
                rt = {".nvmrc": "node", ".node-version": "node", ".php-version": "php",
                      ".python-version": "python"}[name]
                lines = [ln.split("#")[0].strip() for ln in f.read_text(errors="replace").splitlines()]
                first = next((ln for ln in lines if ln), "")
                v, exact = _pw_version_pin(first)
                runtime(rt, v, exact, rel, f"{name} {first or '(empty)'}",
                        why=None if v else f"{name} does not name a version this script can compare")
            elif name == ".tool-versions":
                for ln in f.read_text(errors="replace").splitlines():
                    words = ln.split("#")[0].split()
                    if len(words) >= 2 and words[0].lower() in PWN_TOOL_VERSIONS:
                        v, exact = _pw_version_pin(words[1])
                        runtime(PWN_TOOL_VERSIONS[words[0].lower()], v, exact, rel,
                                f".tool-versions {words[0]} {words[1]}",
                                why=None if v else f".tool-versions {words[0]} does not name a version")
        except OSError as e:
            notes.append(f"{_pw_safe(rel)}: could not be read ({type(e).__name__}); "
                         f"runtime declarations in it were not checked")
    for eco, _, _ in deps:
        tags.update({"npm": ("node", "npm"), "PyPI": ("python", "pypi")}.get(eco, ()))
    return sorted(tags), runtimes


# --- pwn.watch: fetching, with an ETag cache that survives a 304 -------------------
def _pw_keep(wa, incidents, tag: str | None = None, warnings: list | None = None) -> list[dict]:
    """Live patch/supply-chain incidents, reduced to the fields the matcher reads."""
    out = []
    for inc in incidents if isinstance(incidents, list) else []:
        if not isinstance(inc, dict):
            continue
        slug, cat = inc.get("slug"), inc.get("category")
        if (inc.get("status") == "live" and isinstance(cat, str) and cat in wa.CATEGORIES
                and isinstance(slug, str) and wa.SLUG_RE.match(slug)):
            out.append({k: inc.get(k) for k in PWN_FIELDS})
    if len(out) > PWN_FEED_CAP and warnings is not None:
        warnings.append(f"pwn.watch tag '{tag}' lists {len(out)} live incidents; only the first "
                        f"{PWN_FEED_CAP} were matched, so the rest are unchecked")
    return out[:PWN_FEED_CAP]


def _pw_etag(value) -> str | None:
    return value if isinstance(value, str) and _PW_ETAG.fullmatch(value) else None


def pwn_fetch(wa, tags: list[str], state: dict, warnings: list | None = None) -> tuple[dict, dict]:
    """Returns ({tag: incidents}, {tag: why it is UNCHECKED}).

    The state keeps each tag's ETag AND its last filtered incident list. The ETag is sent
    only when that list is present, because a 304 carries no body: without the list a 304
    would leave nothing to match, and a lockfile that changed since the last run would
    never be re-checked against an unchanged feed.
    """
    warnings = warnings if warnings is not None else []
    store = state.get("tags")
    if not isinstance(store, dict):
        store = state["tags"] = {}
    feeds, unchecked = {}, {}
    failures = 0
    for tag in tags:
        url = f"{wa.BASE}/t/{tag}.json"
        entry = store.get(tag) if isinstance(store.get(tag), dict) else {}
        cached = entry.get("incidents") if isinstance(entry.get("incidents"), list) else None
        etag = _pw_etag(entry.get("etag")) if cached is not None else None
        stale = f" (matched against the list cached at {_pw_safe(entry.get('fetchedAt', 'an earlier run'), 40)})"

        def use_cache():
            if cached is not None:
                if entry.get("truncated"):
                    warnings.append(f"pwn.watch tag '{tag}': the cached list was truncated at {PWN_FEED_CAP} incidents")
                feeds[tag] = _pw_keep(wa, cached)
        if failures >= 2:                         # offline: do not wait out every retry
            unchecked[tag] = "skipped after repeated pwn.watch failures" + (stale if cached is not None else "")
            use_cache()
            continue
        try:
            status, body, new_etag = wa._get(url, etag)
            if status == 304 and etag is None:     # we sent no ETag; do not trust an empty 304
                status, body, new_etag = wa._get(url, None)
        except wa.Unreachable as e:
            failures += 1
            unchecked[tag] = _pw_safe(e, 300) + (stale if cached is not None else "")
            use_cache()
            continue
        failures = 0
        if status == 304:
            use_cache()
            continue
        incidents = body.get("incidents") if isinstance(body, dict) else None
        if not isinstance(incidents, list):
            unchecked[tag] = f"{url}: unexpected response shape" + (stale if cached is not None else "")
            use_cache()
            continue
        n_before = len(warnings)
        kept = _pw_keep(wa, incidents, tag, warnings)
        store[tag] = {"etag": _pw_etag(new_etag),
                      "fetchedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "incidents": kept}
        if len(warnings) > n_before:
            store[tag]["truncated"] = True
        feeds[tag] = kept
    return feeds, unchecked


def _pw_detail(wa, slug: str, updated, state: dict, warnings: list, budget: dict | None = None) -> dict | None:
    """Vendor sources for one incident, cached per slug until its updatedAt changes.

    After PWN_DETAIL_FAILS consecutive failures the remaining incidents are not fetched: they
    are reported with their vendor sources unavailable instead of each waiting out retries.
    """
    cache = state.get("details")
    if not isinstance(cache, dict):
        cache = state["details"] = {}
    c = cache.get(slug) if isinstance(cache.get(slug), dict) else None
    old = {"sources": c["sources"]} if c and isinstance(c.get("sources"), list) else None
    if old and c.get("updatedAt") == updated:
        return old
    budget = budget if budget is not None else {}
    if budget.get("fails", 0) >= PWN_DETAIL_FAILS:
        budget["skipped"] = budget.get("skipped", 0) + 1
        return old
    try:
        _, d, _ = wa._get(f"{wa.BASE}/i/{slug}.json")
    except wa.Unreachable as e:
        budget["fails"] = budget.get("fails", 0) + 1
        warnings.append(f"{_pw_safe(e, 300)} (vendor sources unavailable; read the tracker)")
        return old
    budget["fails"] = 0
    if isinstance(d, dict) and isinstance(d.get("incident"), dict):
        d = d["incident"]
    raw = d.get("sources") if isinstance(d, dict) else None
    urls = [s.get("url") if isinstance(s, dict) else s for s in (raw if isinstance(raw, list) else [])]
    urls = [u for u in urls if isinstance(u, str)][:20]
    cache[slug] = {"updatedAt": updated, "sources": urls}
    return {"sources": urls}


def _pw_load_state(wa, path: Path) -> dict:
    """The cache, or {} when it is missing, corrupt or written by a different version."""
    state = wa.load_state(path)
    return state if state.get("version") == PWN_STATE_VERSION else {}


def _pw_save_state(path: Path, state: dict, warnings: list) -> None:
    live = {inc.get("slug") for e in (state.get("tags") or {}).values() if isinstance(e, dict)
            for inc in (e.get("incidents") or []) if isinstance(inc, dict)}
    if isinstance(state.get("details"), dict):
        state["details"] = {k: v for k, v in state["details"].items() if k in live}
    state["version"] = PWN_STATE_VERSION
    tmp = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(state, indent=1) + "\n")
        os.replace(tmp, path)
        tmp = None
    except OSError as e:
        warnings.append(f"could not write pwn.watch state {path}: {e} (the next run refetches)")
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


# --- pwn.watch: matching ------------------------------------------------------------
_PW_NAME_TOKEN = re.compile(r"(?<![\w@/.-])@?[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9*][A-Za-z0-9._*-]*)*")
_PW_RANGE_WORDS = (r"before|prior\s+to|through|thru|up\s+to|up\s+until|until|from|since|between|below|under|"
                   r"less\s+than|lower\s+than|earlier\s+than|older\s+than")
# What may follow a package name for the text after it to be read as that package's range.
_PW_VSTART = re.compile(rf"\s*:?\s*(?:@?v?\d|[<>=^~]|(?:{_PW_RANGE_WORDS})\b|pre-\d)", re.I)
# A line with no package name that is still only versions: it belongs to the package before it.
_PW_VONLY = re.compile(rf"\s*(?:(?:all|any|every|versions?|releases?|and|also|plus|including|or)\s+)*"
                       rf"(?:v?\d|[<>=^~]|(?:{_PW_RANGE_WORDS})\b|pre-\d)", re.I)
_PW_JOIN = re.compile(r"(?:\s|,|/|&|\band\b|\bor\b)*", re.I)
# Words that may come before the first package name on a line without changing what it says.
_PW_PREFIX_OK = {"affected", "vulnerable", "versions", "version", "packages", "package", "all", "and", "also",
                 "plus", "including", "npm", "pypi"}


def _pw_norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()) if eco == "PyPI" else name.lower()


def _pw_alias(eco: str, name: str) -> str:
    """The form a name takes in sanitised feed text, which drops '_'. PyPI ignores -_. anyway."""
    n = name.lower()
    return re.sub(r"[-_.]+", "", n) if eco == "PyPI" else n.replace("_", "")


def _pw_common(norm: str) -> bool:
    return norm in PWN_COMMON or len(norm) <= 2


def _pw_token_deps(tok: str, aliases: dict) -> tuple[set, bool, bool]:
    """(installed packages a name-like token names, names one unambiguously, is a package label).

    Handles '@scope/name', 'scope/name' for '@scope/name', 'next/react' lists, and brand forms
    such as 'Next.js' or 'Express.js'. A scoped name is a label even when it is not installed.
    """
    base = tok.rstrip("._-")
    if not base or base[0].isdigit() or _vparse(base):
        return set(), False, False

    def look(word):
        found = set()
        for eco in ("npm", "PyPI"):
            found |= aliases.get((eco, _pw_alias(eco, word)), set())
        return found
    if base.startswith("@"):
        return look(base), True, "/" in base
    if "/" in base:
        scoped = look("@" + base)
        if scoped:
            return scoped, True, True
        pieces = [p for p in base.split("/") if p and p != "*"]
    else:
        pieces = [base]
    keys, strong = set(), False
    for p in pieces:
        variants = [(p, False)]
        if p.lower().endswith(".js") and len(p) > 3:
            variants.append((p[:-3], True))
        for variant, brand in variants:
            found = look(variant)
            keys |= found
            strong = strong or any(brand or not _pw_common(k[1]) for k in found)
    return keys, strong, bool(keys)


def _pw_line_groups(line: str, aliases: dict) -> list[dict]:
    """Package labels in one line: runs of names joined by ',', '/', '&', 'and', 'or'.

    A run made only of everyday-word names ('next', 'is') counts only when a version follows.
    """
    groups: list[dict] = []
    for m in _PW_NAME_TOKEN.finditer(line):
        keys, strong, label = _pw_token_deps(m.group(0), aliases)
        if not label:
            continue
        start, end = m.start(), m.start() + len(m.group(0).rstrip("._-"))
        if groups and _PW_JOIN.fullmatch(line[groups[-1]["end"]:start]):
            g = groups[-1]
            g["end"], g["strong"] = end, g["strong"] or strong
            g["keys"] |= keys
        else:
            groups.append({"start": start, "end": end, "keys": set(keys), "strong": strong})
    return [g for g in groups if g["strong"] or _PW_VSTART.match(line, g["end"])]


# --- pwn.watch: the one place a "not-affected" verdict is issued ------------------------
# Matchers never write verdict "not-affected" themselves. They hand _pw_candidate the reason
# and every doubt they found (blockers); _pw_conclude, called at the exit of both matchers,
# downgrades to "check" unless there is no blocker AND the incident text reached the matcher
# unaltered (sanitise() clean). A "not-affected" that did not come through _pw_candidate is
# downgraded too. "affected" verdicts pass through untouched.
def _pw_candidate(m: dict, blockers: list) -> dict:
    return {**m, "verdict": "not-affected", "_blockers": [b for b in blockers if b]}


def _pw_conclude(item: dict, matches: list) -> list:
    out = []
    for m in matches:
        m = dict(m)
        blockers = m.pop("_blockers", None)
        if m.get("verdict") == "not-affected":
            why = list(blockers) if blockers is not None else ["internal: this verdict skipped the checks"]
            if not item.get("clean"):
                fields = ", ".join(item.get("altered") or []) or "some field"
                why.insert(0, f"the feed text ({fields}) was altered or truncated while sanitising, "
                              f"so it was not read completely")
            if why:
                more = f" (+{len(why) - 1} more)" if len(why) > 1 else ""
                m["verdict"] = "check"
                m["reason"] = f"{m['reason']}; not cleared: {why[0]}{more}"
                m.pop("nofix", None)
        out.append(m)
    return out


# --- pwn.watch: attributing lines -----------------------------------------------------
# Every affected line must be either read for the subject being decided, or attributed to
# something else in a form this script recognises. Anything else blocks a clean verdict.
_PW_LABEL_END = re.compile(rf"(?<![A-Za-z0-9_./-])v?\d|@(?=v?\d|[<>=^~])|[<>=^~]|\b(?:{_PW_RANGE_WORDS})\b|\bpre-\d",
                           re.I)
_PW_ALL_RT = re.compile(r"(?<![\w./@-])(?:PHP|Node(?:\.js)?|Bun|C?Python|Deno)(?![\w/-])", re.I)
_PW_EOL = re.compile(r"\b(?:EOL|end-of-life|unpatched|no fix|unsupported)\b", re.I)


def _pw_split_label(text: str) -> tuple[str, str]:
    """'Windows builds: 8.4 before 8.4.10' -> ('Windows builds', '8.4 before 8.4.10')."""
    m = _PW_LABEL_END.search(text)
    if not m:
        return text.strip(" :,"), ""
    return text[:m.start()].strip(" :,"), text[m.start():].strip()


def _pw_split(text: str) -> list[str]:
    """Clauses: split on ';' outside brackets, and on ',' when a runtime name follows it."""
    out, cur, depth = [], [], 0
    for i, c in enumerate(text):
        depth = depth + 1 if c in "([" else max(0, depth - 1) if c in ")]" else depth
        if depth == 0 and (c == ";" or (c == "," and re.match(r"\s*(?:and\s+)?" + _PW_ALL_RT.pattern,
                                                              text[i + 1:], re.I))):
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return [x.strip() for x in out if x.strip(" ,")]


def _pw_simple_name(text: str) -> str:
    return re.sub(r"js$", "", re.sub(r"[^a-z0-9]", "", text.lower()))


def _pw_product_items(product: str) -> list[str]:
    """'Next.js (next on npm), sharp / librsvg' -> ['next.js', 'sharp', 'librsvg']."""
    bare = re.sub(r"\([^()]*\)", " ", product.translate(_PW_FOLD))
    return [re.sub(r"\s+", " ", x).strip().lower()
            for x in re.split(r"\s*(?:,|/|&|\+|;|\band\b)\s*", bare, flags=re.I) if x.strip()]


def _pw_other_label(label: str, body: str, item: dict, subjects: list[str], aliases: dict) -> bool:
    """Does a label name something other than the subjects, in a form this script recognises?

    Recognised: a scoped/vendor name ('@scope/pkg', 'laravel/framework'), 'name@<version>', an
    installed package, a runtime name, or an item of the incident's product field that is not a
    subject. Prose labels ('Canary', 'Self-hosted', 'Windows builds') are not.
    """
    lab = label.strip(" :,").lower()
    if not lab:
        return False
    # A name that contains a subject's name ('php-fpm' for PHP, 'nextjs' for next) may be it.
    related = lambda name: any(_pw_simple_name(x) and _pw_simple_name(x) in _pw_simple_name(name) for x in subjects)
    if body.startswith("@") and re.fullmatch(r"@?[a-z0-9][\w.-]*(?:/[\w.*-]+)?", lab):
        return not related(lab.split("/")[-1])
    if re.fullmatch(r"@?[a-z0-9][\w.-]*/[\w.*-]+", lab):
        return True
    if aliases and any(g["start"] == 0 and g["end"] >= len(label.strip(" :,"))
                       for g in _pw_line_groups(label.strip(" :,") + " 0", aliases)):
        return True                                   # the whole label is installed package names
    if not re.sub(r"\b(?:and|or)\b|[,&/\s]", "", _PW_ALL_RT.sub("", lab)):
        return True                                   # only runtime names: "Node.js", "Deno and Bun"
    return lab in _pw_product_items(item["product"]) and not related(lab)


def _pw_aliases(deps_index: dict) -> dict:
    aliases: dict[tuple, set] = {}
    for key, (name, _) in deps_index.items():
        aliases.setdefault((key[0], _pw_alias(key[0], name)), set()).add(key)
    return aliases


# --- pwn.watch: matching packages -----------------------------------------------------
def _pw_match_packages(item: dict, deps_index: dict) -> list[dict]:
    aliases = _pw_aliases(deps_index)
    segs: dict[tuple, list] = {}

    def add(keys, text, ranges):
        for k in keys:
            segs.setdefault(k, []).append((text, ranges))

    product = item["product"]
    bare_product = re.sub(r"\([^()]*\)", " ", product).strip()
    product_keys = set()
    for m in _PW_NAME_TOKEN.finditer(product):
        keys, strong, _ = _pw_token_deps(m.group(0), aliases)
        product_keys |= {k for k in keys if strong or _pw_alias(k[0], bare_product) == _pw_alias(k[0], deps_index[k][0])}

    last_keys = None
    loose = []                                        # lines no package of ours was found in
    for raw in item["affected"]:
        line = _pw_clean_line(raw)
        if not line:
            continue
        groups = _pw_line_groups(line, aliases)
        if not groups:
            if _PW_VONLY.match(line):                 # unlabelled: belongs to the package before it
                add(last_keys if last_keys is not None else product_keys, line, _pw_ranges(line))
            else:
                loose.append(line)
            continue
        prefix = line[:groups[0]["start"]]
        if re.search(r"\d", prefix) or re.sub(r"[\s:,;-]", "", re.sub(
                r"[a-z][\w-]*", lambda w: "" if w.group(0) in _PW_PREFIX_OK else w.group(0), prefix.lower())):
            # Versions before the name (whose are they?) or prose that may qualify or negate it
            # ("Not affected: next >= 14.2.25", "Pages Router: next < 14.2.25"): not read.
            add(groups[0]["keys"], line, None)
        for g, nxt in zip(groups, groups[1:] + [None]):
            seg = line[g["end"]:nxt["start"] if nxt else len(line)]
            seg = re.sub(r"(?:\s*(?:[,;/&]|\band\b|\bor\b|\bplus\b))+\s*$", "", seg, flags=re.I).strip(" :")
            add(g["keys"], f"{line[g['start']:g['end']]} {seg}".strip(), _pw_ranges(seg) if seg else None)
        last_keys = groups[-1]["keys"]

    subjects = sorted(set(segs) | product_keys)
    names = [deps_index[k][0] for k in subjects]
    # A line naming nothing we track, that is not attributed to something else we recognise
    # ("Canary <= 14.3.0", "Self-hosted: 14.x before 14.2.25"): whose versions are those?
    unattributed = [ln for ln in loose if not _pw_other_label(*_pw_split_label(ln), item, names, aliases)]
    shared = [f"'{_pw_safe(unattributed[0], 90)}' is not attributed to any package or product this script "
              f"recognises, so it may cover this package"] if unattributed else []

    out = []
    for key in subjects:
        name, versions = deps_index[key]
        segments = segs.get(key) or [("(no version text names this package)", None)]
        bad = next((t for t, r in segments if r is None), None)
        bounds = [b for _, r in segments if r for x in r for b in (x[0], x[2]) if b is not None]
        for ver in sorted(versions):
            p = _vparse(ver)
            label = f"{_pw_safe(name, 80)} {_pw_safe(ver, 40)}"
            m = {"kind": "package", "name": _pw_safe(name, 214), "version": _pw_safe(ver, 64)}
            if not p:
                out.append({**m, "verdict": "check", "reason": f"{label}: installed version is not comparable"})
                continue
            k = _vkey(p[0], p[1])
            hit = next((t for t, r in segments if r and any(_in_range(x, k) for x in r)), None)
            if bad is not None:
                also = f"; it is inside '{hit}', so treat it as affected until checked" if hit else ""
                out.append({**m, "verdict": "check",
                            "reason": f"{label}: affected text could not be parsed completely: '{bad}'{also}"})
            elif hit:
                out.append({**m, "verdict": "affected", "reason": f"{label} is inside '{hit}'"})
            elif any(x[4] for _, r in segments for x in r):
                soft = next(t for t, r in segments if any(x[4] for x in r))
                out.append({**m, "verdict": "check",
                            "reason": f"{label} is outside the caret/tilde range in '{soft}', which may not be "
                                      f"meant as a semver range"})
            else:
                amb = next((b for b in bounds if _v_ambiguous(k, b)), None)
                out.append(_pw_candidate(
                    {**m, "reason": f"{label} is outside " + "; ".join(f"'{t}'" for t, _ in segments)},
                    shared + ([f"{label} is a pre/post-release of a boundary version, and its order against "
                               f"that boundary is ambiguous"] if amb else [])))
    return _pw_conclude(item, out)


# --- pwn.watch: matching runtimes -----------------------------------------------------
def _pw_rt_classify(clause: str, rt: str, ctx: dict, lead_ok: frozenset = frozenset()) -> tuple[str, str]:
    """One clause, for runtime rt: ('self', text to parse) | ('other', '') | ('loose', clause).

    self: labelled with rt ('PHP 8.3 before 8.3.36', '8.3.36 (PHP)'), or unlabelled / generic
    ('EOL 8.1 and earlier') in an incident whose product is rt alone. other: labelled with
    another runtime or a recognised name, or unlabelled in an incident about some other product.
    loose: anything else that could still be about rt ('Windows builds: 8.4 before 8.4.10',
    'Odd-numbered lines are not patched', 'Next.js < 15 when running on Node.js 18').
    lead_ok: extra label words that are not a product name ('fixed in' on fixed clauses).
    """
    generic = PWN_GENERIC | lead_ok
    text = clause.translate(_PW_FOLD).strip()
    named: set = set()
    pm = re.search(r"\(\s*([^()]*?)\s*\)\s*$", text)
    if pm and re.fullmatch(_PW_ALL_RT.pattern, pm.group(1), re.I):
        named = {r for r, rx in PWN_RUNTIME_ANY.items() if rx.fullmatch(pm.group(1))} or {"other"}
        text = text[:pm.start()].rstrip()
    label, body = _pw_split_label(text)
    named |= {r for r, rx in PWN_RUNTIME_ANY.items() if rx.search(label)}
    if re.search(r"(?<![\w./@-])Deno(?![\w/-])", label, re.I):
        named.add("other")
    if rt in named:
        rest = _PW_ALL_RT.sub(" ", label)
        words = re.findall(r"[a-z][\w-]*", rest.lower())
        if all(w in generic or w in ("or",) for w in words):
            lead = re.sub(r"^(?:[\s,:&/]|\band\b|\bor\b)+", "", rest).strip(" :,")
            return "self", f"{lead} {body}".strip()
        return "self", text                           # labelled for rt, with words we cannot read
    mentions = bool(PWN_RUNTIME_ANY[rt].search(text))
    if named:
        return ("loose", text) if mentions else ("other", "")
    if mentions:                                      # "unpatched by the PHP project" / "on Node.js 18"
        return ("self", text) if ctx["product_is"] else ("loose", text)
    if all(w in generic for w in re.findall(r"[a-z][\w-]*", label.lower())):
        if ctx["product_is"]:
            return "self", text
        return ("loose", text) if ctx["product_names"] else ("other", "")
    if ctx["other"](label, body):
        return "other", ""
    return ("loose", text) if (ctx["product_is"] or ctx["product_names"]) else ("other", "")


_PW_FIX_LEAD = frozenset({"fixed", "patched", "resolved", "in", "version", "versions", "release", "releases"})


def _pw_fixed_versions(text: str):
    """Strict reading of a fixed clause: '8.3.36', 'fixed in 22.12.0, 20.18.1', '2.23.0+'.

    Every version must be a full release (no '8.3', no '8.x'). Returns [(nums, pre)], or None
    when anything else is left ('8.2.29 is not fixed', 'see 8.2.30', '8.3.36 [Windows only]').
    """
    t = _pw_tokens(_pw_clean_line(text, fixed_phrases=False).strip(" ,;:"))
    if not t:
        return None
    n, i, out = len(t), 0, []
    while i < n and t[i][0] == "word" and t[i][1] in _PW_FIX_LEAD:
        i += 1
    while True:
        if i < n and t[i][0] == "op" and t[i][1] in (">=", "=>"):
            i += 1
        if not (i < n and t[i][0] == "ver" and t[i][3] and not t[i][2][2]):
            return None
        out.append((t[i][2][0], t[i][2][1]))
        i += 1
        if i < n and t[i][1] == "+":
            i += 1
        elif i + 1 < n and t[i][1] in ("or", "and") and t[i + 1][1] in ("later", "newer", "above", "higher"):
            i += 2
        if i == n:
            return out
        if t[i][1] not in (",", "/", "&", "and"):
            return None
        i += 1
        if i < n and t[i][1] == "and":
            i += 1


def _pw_runtime_facts(item: dict, rt: str, aliases: dict | None = None) -> dict | None:
    """What the incident says about runtime rt, or None when it never names rt.

    fixes: newest strictly-read fixed release per line. ranges: parsed affected ranges.
    unparsed / loose / fixed_bad: clauses that could be about rt but were not read; each one
    blocks a clean verdict.
    """
    folded = lambda s: s.translate(_PW_FOLD)
    rx = PWN_RUNTIME_ANY[rt]
    product = item["product"]
    names_rt = bool(rx.search(folded(product)))
    if not (names_rt or any(rx.search(folded(x)) for x in item["affected"] + item["fixed"])):
        return None
    product_is = bool(PWN_RUNTIME_START[rt].match(folded(product))) and not any(
        o.search(folded(product)) for k, o in PWN_RUNTIME_ANY.items() if k != rt)
    ctx = {"product_is": product_is, "product_names": names_rt and not product_is,
           "other": lambda label, body: _pw_other_label(label, body, item, [PWN_RUNTIME_NAME[rt], rt], aliases or {})}
    parts = PWN_LINE_PARTS[rt]
    f = {"fixes": {}, "ranges": [], "unparsed": [], "loose": [], "fixed_bad": [], "eol": False}
    for line in item["fixed"]:
        for clause in _pw_split(line):
            kind, body = _pw_rt_classify(clause, rt, ctx, _PW_FIX_LEAD)
            if kind == "other":
                continue
            vs = _pw_fixed_versions(body) if kind == "self" else None
            if not vs:
                f["fixed_bad"].append(clause)
                continue
            for nums, pre in vs:
                ln = tuple(nums[:parts])
                if len(nums) <= parts:
                    f["fixed_bad"].append(clause)
                elif ln not in f["fixes"] or _vkey(nums, pre) > _vkey(*f["fixes"][ln]):
                    f["fixes"][ln] = (nums, pre)
    for line in item["affected"]:
        for clause in _pw_split(line):
            kind, body = _pw_rt_classify(clause, rt, ctx)
            if kind == "other":
                continue
            if kind == "loose":
                f["loose"].append(clause)
                continue
            f["eol"] = f["eol"] or bool(_PW_EOL.search(clause))
            r = _pw_ranges(body)
            if r is None:
                f["unparsed"].append(clause)
            else:
                f["ranges"].extend(r)
    if not any(f[k] for k in ("fixes", "ranges", "unparsed", "loose", "fixed_bad")):
        return None
    return f


def _pw_match_runtimes(item: dict, runtimes: list[dict], deps_index: dict | None = None) -> list[dict]:
    out = []
    aliases = _pw_aliases(deps_index or {})
    for rt in sorted({r["runtime"] for r in runtimes}):
        f = _pw_runtime_facts(item, rt, aliases)
        if f is None:
            continue                               # not an incident about this runtime
        fixes, ranges, eol = f["fixes"], f["ranges"], f["eol"]
        name = PWN_RUNTIME_NAME[rt]
        parts = PWN_LINE_PARTS[rt]
        fixed_txt = ", ".join(".".join(map(str, n)) + (f"-{p}" if p else "") for n, p in
                              sorted(fixes.values(), key=lambda x: _vkey(*x))) or "see the vendor source"
        newest_fixed_line = max((_vkey(x[0][:parts]) for x in fixes.values()), default=None)
        soft = any(r[4] for r in ranges)
        # Doubts that apply to every declaration of this runtime.
        shared = []
        if f["loose"]:
            shared.append(f"'{_pw_safe(f['loose'][0], 90)}' is not attributed to {name} or to another product "
                          f"this script recognises, so it may cover {name}")
        if f["unparsed"]:
            shared.append(f"part of the affected text could not be parsed: '{_pw_safe(f['unparsed'][0], 90)}'")
        if f["fixed_bad"]:
            shared.append(f"the fixed text '{_pw_safe(f['fixed_bad'][0], 90)}' could not be read completely")
        if soft:
            shared.append("a caret/tilde range may not be meant as a semver range")
        fix_unsure = bool(f["fixed_bad"] or f["loose"])
        bounds = [b for r in ranges for b in (r[0], r[2]) if b is not None]
        for d in (r for r in runtimes if r["runtime"] == rt):
            src = f"{d['source']}: {d['detail']}"
            label = f"{name} {_pw_safe(d['version'] or '(no version)', 40)} ({src})"
            m = {"kind": "runtime", "runtime": rt, "declared": d["version"], "exact": d["exact"],
                 "constraint": bool(d.get("constraint")), "source": src}
            p = _vparse(d["version"]) if d["version"] else None
            line = p[0][:parts] if p and len(p[0]) >= parts else None
            ln = ".".join(map(str, line)) if line else ""
            # A release line with no fixed release: covered by a parsed range, or older than the
            # newest fixed line in an incident that marks old/EOL lines unpatched.
            eol_old = (line is not None and line not in fixes and eol and newest_fixed_line is not None
                       and _vkey(line) < newest_fixed_line)
            nofix_line = line is not None and line not in fixes and (
                eol_old or any(_range_meets_line(r, line) for r in ranges))
            if d.get("constraint"):
                # A constraint (composer require.php, engines.node) admits many patch levels. It
                # says nothing about the one deployed, so it is never a hit and never urgent.
                note = (f"; note: it admits the {ln} line, which has no fixed release for this incident"
                        if nofix_line else "")
                out.append({**m, "verdict": "check",
                            "reason": f"{label}: a version constraint does not identify the deployed patch "
                                      f"level; check the runtime you deploy (fixed: {fixed_txt}){note}"})
                continue
            if line is None:
                why = d.get("why") or "no release line to compare"
                out.append({**m, "verdict": "check", "reason": f"{label}: {why}; fixed: {fixed_txt}; "
                                                              f"check the deployed runtime version"})
                continue
            floating = ("a floating image tag does not show the patch level: check the tag/digest"
                        if d["detail"].startswith(("FROM ", "image: ")) else
                        "this does not pin a patch release: check the deployed runtime version")
            k = _vkey(p[0], p[1])
            inside = any(_in_range(r, k) for r in ranges)
            amb = [f"{name} {d['version']} is a pre/post-release of a version the incident names, and its "
                   f"order against it is ambiguous"] if any(_v_ambiguous(k, b) for b in bounds) else []
            if line in fixes:
                fix = fixes[line]
                fk = _vkey(*fix)
                fs = ".".join(map(str, fix[0])) + (f"-{fix[1]}" if fix[1] else "")
                if not d["exact"]:
                    out.append({**m, "verdict": "check",
                                "reason": f"{label}: fixed in {fs} on the {ln} line; {floating}"})
                elif k < fk:
                    out.append({**m, "verdict": "affected", "reason": f"{label}: fixed in {fs} on the {ln} line"})
                elif inside:
                    out.append({**m, "verdict": "check",
                                "reason": f"{label}: listed as fixed in {fs} on the {ln} line, but it is inside "
                                          f"a parsed affected range; the incident contradicts itself"})
                else:
                    if _v_ambiguous(k, fk) and not amb:
                        amb = [f"{name} {d['version']} is a pre/post-release of the fixed version {fs}"]
                    out.append(_pw_candidate({**m, "reason": f"{label}: fixed in {fs} on the {ln} line"},
                                             shared + amb))
                continue
            # Urgent stays the loud default: unread fixed text only adds a note, it never quiets it.
            unsure = (f"; the fixed text could not be fully read, so check whether the {ln} line has a fix"
                      if fix_unsure else "")
            if inside if d["exact"] else (nofix_line and not eol_old):
                out.append({**m, "verdict": "affected", "nofix": True,
                            "reason": f"{label}: affected, and the {ln} line has no fixed release "
                                      f"(upgrade to a line with a fix: {fixed_txt}){unsure}"})
            elif eol_old:
                out.append({**m, "verdict": "affected", "nofix": True,
                            "reason": f"{label}: the {ln} line has no fixed release and the incident marks "
                                      f"old lines unpatched (upgrade to: {fixed_txt}){unsure}"})
            elif f["unparsed"] or soft:
                out.append({**m, "verdict": "check",
                            "reason": f"{label}: part of the affected text could not be parsed"})
            elif ranges:
                out.append(_pw_candidate({**m, "reason": f"{label}: outside the affected ranges"}, shared + amb))
            else:
                out.append({**m, "verdict": "check",
                            "reason": f"{label}: no fix listed for the {ln} line and the affected text does "
                                      f"not settle it (fixed: {fixed_txt})"})
    return _pw_conclude(item, out)


def run_pwnwatch(wa, root: Path, deps, state_path: Path | None) -> dict:
    """Never raises for a network problem: those become UNCHECKED entries and warnings."""
    notes: list[str] = []
    tags, runtimes = pwn_detect(root, deps, notes)
    result = {"tags": tags, "runtimes": runtimes, "incidents": [], "unchecked": list(notes), "warnings": []}
    if not tags:
        result["warnings"].append("no ecosystem under --path maps to a pwn.watch tag; nothing queried")
        return result
    state = _pw_load_state(wa, state_path) if state_path else {}
    if state_path is None:
        result["warnings"].append("no user cache directory; pwn.watch feeds fetched without an ETag cache")
    feeds, unchecked = pwn_fetch(wa, tags, state, result["warnings"])
    result["unchecked"] += [f"pwn.watch tag '{t}': {why}" for t, why in unchecked.items()]

    raw: dict[str, dict] = {}
    from_tags: dict[str, list[str]] = {}
    for tag in tags:
        for inc in feeds.get(tag, []):
            slug, prev = inc["slug"], raw.get(inc["slug"])
            # The same incident in two feeds: keep the most recently updated copy.
            if prev is None or (wa.norm_time(inc.get("updatedAt")) or "") > (wa.norm_time(prev.get("updatedAt")) or ""):
                raw[slug] = inc
            if tag not in from_tags.setdefault(slug, []):
                from_tags[slug].append(tag)

    deps_index: dict[tuple, tuple] = {}
    for eco, name, ver in deps:
        if eco in ("npm", "PyPI"):
            key = (eco, _pw_norm(eco, name))
            deps_index.setdefault(key, (name, set()))[1].add(ver)

    budget: dict = {}
    for slug, inc in raw.items():
        try:
            item = wa.sanitise(inc, None)
            if not item:
                continue
            matches = _pw_match_packages(item, deps_index) + _pw_match_runtimes(item, runtimes, deps_index)
        except Exception as e:                    # one malformed incident must not stop the run
            result["warnings"].append(f"{slug}: skipped malformed incident ({type(e).__name__})")
            continue
        verdict = min((m["verdict"] for m in matches), key=PWN_VERDICT.get, default=None)
        if verdict is None and item["severity"] not in ("critical", "high"):
            continue
        reportable = verdict in ("affected", "check")
        if reportable:
            detail = _pw_detail(wa, slug, inc.get("updatedAt"), state, result["warnings"], budget)
            item = wa.sanitise(inc, detail) or item
            if detail is None:
                item["sources_unavailable"] = True
        # Urgent = affected AND the incident is not fully patched: patchStatus partial or
        # unpatched (some affected product or line still has no fix, even if yours does), or
        # a matched runtime line has no fixed release at all.
        urgent = verdict == "affected" and (
            item["patchStatus"] in ("partial", "unpatched")
            or any(m.get("nofix") and m["verdict"] == "affected" for m in matches))
        item.pop("copilotOk", None)
        item.update({"verdict": verdict or "check", "urgent": urgent, "unmatched": verdict is None,
                     "matches": matches, "feeds": from_tags[slug]})
        result["incidents"].append(item)
    if budget.get("skipped"):
        result["warnings"].append(f"skipped {budget['skipped']} vendor-source fetch(es) after "
                                  f"{PWN_DETAIL_FAILS} consecutive failures; read those trackers for the "
                                  f"vendor advisory")
    # Matched: urgent, then not fully patched, then severity. Unmatched: critical first.
    result["incidents"].sort(key=lambda r: (PWN_VERDICT[r["verdict"]], r["unmatched"], not r["urgent"],
                                            PWN_SEVERITY.get(r["severity"], 9) if r["unmatched"] else 0,
                                            r["patchStatus"] not in ("partial", "unpatched"),
                                            PWN_SEVERITY.get(r["severity"], 9), r["slug"]))
    if state_path:
        _pw_save_state(state_path, state, result["warnings"])
    return result


def print_pwnwatch(pw: dict) -> None:
    print(f"\n  pwn.watch live incidents for: {', '.join(pw['tags']) or '(no detected stack)'}")
    print("  pwn.watch is a tracker. Act on and cite the vendor sources, not the tracker.")
    for d in pw.get("runtimes", []):
        if d["version"] is None and not d.get("constraint"):
            print(f"  [pwn.watch] runtime version not read: {d['source']}: {d['detail']} "
                  f"({d.get('why', 'no version')}); {PWN_RUNTIME_NAME[d['runtime']]} incidents are "
                  f"matched against it as check manually")
    matched = [r for r in pw["incidents"] if not r["unmatched"] and r["verdict"] != "not-affected"]
    for r in matched[:PWN_REPORT_CAP]:
        if r["verdict"] == "affected":
            tag = f"PWN {r['severity']}, {r['patchStatus']}" + (": URGENT" if r["urgent"] else "")
        else:
            tag = f"PWN check manually: {r['severity']}, {r['patchStatus']}"
        print(f"\n  [{tag}] {r['title']}")
        for m in sorted(r["matches"], key=lambda m: PWN_VERDICT[m["verdict"]]):
            if m["verdict"] != "not-affected":
                word = {"affected": "AFFECTED", "check": "CHECK"}[m["verdict"]]
                print(f"        {word}: {m['reason']}")
        if r["affected"]:
            print(f"        affected: {' | '.join(r['affected'])}")
        if r["fixed"]:
            print(f"        fixed: {' | '.join(r['fixed'])}")
        for s in sorted(r["sources"], key=lambda s: not s["trusted"]):
            print(f"        {'vendor' if s['trusted'] else 'source (unverified host)'}: {s['url']}")
        if not r["sources"]:
            why = "could not be fetched" if r.get("sources_unavailable") else "none listed"
            print(f"        vendor: {why}; find the vendor advisory before acting")
        print(f"        tracker: {r['tracker']}")
    if len(matched) > PWN_REPORT_CAP:
        print(f"\n  ... and {len(matched) - PWN_REPORT_CAP} more matched incidents (see --json)")
    manual = [r for r in pw["incidents"] if r["unmatched"]]
    if manual:
        print("\n  Live critical/high incidents for these stacks with no package or runtime match (check manually):")
    for r in manual[:PWN_MANUAL_CAP]:
        print(f"  [PWN check manually] {r['severity']}, {r['patchStatus']}: {r['title']}  tracker: {r['tracker']}")
    if len(manual) > PWN_MANUAL_CAP:
        print(f"  ... and {len(manual) - PWN_MANUAL_CAP} more (see --json)")
    clear = sum(1 for r in pw["incidents"] if r["verdict"] == "not-affected")
    if clear:
        print(f"\n  pwn.watch: {clear} matched incident(s) parsed as not affecting the installed versions")
    for u in pw["unchecked"]:
        print(f"\n  [UNCHECKED] {_pw_safe(u, 500)} — treat pwn.watch as unchecked for this stack, not clear")
    for w in pw["warnings"]:
        print(f"\n  [pwn.watch warning] {_pw_safe(w, 500)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", default=".", help="repo root to scan")
    ap.add_argument("--min-epss", type=float, default=0.0,
                    help="only report at or above this exploitation probability")
    ap.add_argument("--fail-on", choices=["any", "kev", "epss"], default="any",
                    help="what makes the exit code non-zero (default: any finding)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--pwnwatch", action="store_true",
                    help="also match live pwn.watch incidents (runtimes, vendor-only advisories)")
    ap.add_argument("--pwnwatch-state", type=Path, metavar="PATH",
                    help="ETag/incident cache for --pwnwatch (default: "
                         "$XDG_CACHE_HOME/secaudit/pwnwatch-state.json, else "
                         "~/.cache/secaudit/pwnwatch-state.json)")
    args = ap.parse_args()

    wa = None
    if args.pwnwatch:
        try:
            wa = _pw_load_watcher()
        except Exception as e:
            print(f"--pwnwatch unavailable: {e}", file=sys.stderr)
            return 2

    root = Path(args.path).resolve()
    deps, unchecked = discover(root)

    try:
        eol = runtime_eol(root)
        hits = scan(deps) if deps else {}
        add_cves(hits)
        add_epss(hits)
        add_kev(hits)
    except Unreachable as e:
        # Fail LOUD, never clean. "Could not check" must not read as "nothing found".
        print(f"could not complete the scan: {e}\n"
              f"Treat this as UNCHECKED, not clear.", file=sys.stderr)
        return 2

    findings = []
    for h in hits.values():
        h["packages"] = sorted(h["packages"])
        if h.get("kev") or h.get("epss", 0.0) >= args.min_epss:
            findings.append(h)
    # KEV first, then exploitation probability. This ordering IS the product.
    findings.sort(key=lambda h: (0 if h.get("kev") else 1, -h.get("epss", 0.0)))

    pw = None
    if wa is not None:
        try:
            pw = run_pwnwatch(wa, root, deps, args.pwnwatch_state or _pw_default_state())
        except Exception as e:
            # Optional source: its failure is reported, never fatal, and never "clear".
            pw = {"tags": [], "runtimes": [], "incidents": [], "warnings": [],
                  "unchecked": [_pw_safe(f"pwn.watch check failed ({type(e).__name__}: {e})", 300)]}
    pw_affected = [r for r in (pw or {}).get("incidents", []) if r["verdict"] == "affected"]

    if args.json:
        out = {"findings": findings, "eol": eol, "unchecked": unchecked,
               "dependencies_scanned": len(deps)}
        if pw is not None:
            out.update({"pwnwatch": pw["incidents"], "pwnwatch_tags": pw["tags"],
                        "pwnwatch_runtimes": pw["runtimes"], "pwnwatch_unchecked": pw["unchecked"],
                        "pwnwatch_warnings": pw["warnings"]})
            for w in pw["unchecked"] + pw["warnings"]:
                print(f"warning: {_pw_safe(w, 500)}", file=sys.stderr)
        print(json.dumps(out, indent=2))
    else:
        print(f"Scanned {len(deps)} dependencies in {root}\n")
        for e in eol:
            print(f"  [EOL] {e['product']} {e['cycle']} reached end of life on {e['eol']}")
            print("        No further security patches will be issued. Upgrade the runtime.\n")
        for h in findings[:40]:
            tag = f"KEV since {h['kev']}" if h.get("kev") else (
                f"EPSS {h['epss']:.3f}" if "epss" in h else "no EPSS score")
            print(f"  [{tag}] {h['cve'] or h['id']}")
            print(f"        {', '.join(h['packages'][:6])}")
        if len(findings) > 40:
            print(f"\n  ... and {len(findings) - 40} more below these")
        for u in unchecked:
            print(f"\n  [UNCHECKED] {u}")
        pw_loud = bool(pw and (pw["unchecked"] or any(r["verdict"] != "not-affected" for r in pw["incidents"])))
        if not findings and not eol and not unchecked and not pw_loud:
            print("  Nothing above threshold.")
        if pw is not None:
            print_pwnwatch(pw)

    if args.fail_on == "kev":
        bad = any(h.get("kev") for h in findings)
    elif args.fail_on == "epss":
        bad = any(h.get("epss", 0.0) >= max(args.min_epss, 0.1) for h in findings)
    else:
        bad = bool(findings)
    # pwn.watch carries no KEV or EPSS. An URGENT hit fails under every --fail-on: affected,
    # and the incident is not fully patched (patchStatus partial/unpatched — urgent even when
    # a fix exists for your own line, because some affected product or line still has none),
    # or a matched runtime line has no fixed release. Any other affected hit fails only under
    # "any". "Check manually" items and an unreachable pwn.watch never change the exit code.
    if args.fail_on == "any":
        bad = bad or bool(pw_affected)
    else:
        bad = bad or any(r["urgent"] for r in pw_affected)
    # An unparseable lockfile is a failure too: coverage gaps must not pass silently.
    return 1 if (bad or eol or unchecked) else 0


if __name__ == "__main__":
    sys.exit(main())
