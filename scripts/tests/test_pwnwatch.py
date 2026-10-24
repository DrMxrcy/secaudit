"""Fixture tests for `monitor-deps.py --pwnwatch`. Stdlib only; the network is fully mocked.

Run from the repo root:  python3 -m unittest discover -s scripts/tests

Nothing here touches the real user cache: XDG_CACHE_HOME points at a temp dir for the whole
module, every run passes an explicit temp --pwnwatch-state, and urllib's urlopen is replaced
so an unmocked request fails the test instead of reaching pwn.watch.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "monitor-deps.py"

NEXT = {"slug": "nextjs-october-2026-rce-security-release",
        "title": "Next.js out-of-band release fixes two unauthenticated RCEs (SVG image optimization CVE-2026-96889, use cache)",
        "product": "Next.js (next on npm), sharp / librsvg", "status": "live", "category": "patch",
        "severity": "critical", "patchStatus": "patched", "cveIds": ["CVE-2026-96889"],
        "affectedVersions": ["next >= 10.0.0, <= 15.5.27 (Image Optimization SVG RCE, CVE-2026-96889)",
                             "next >= 16.0.0, <= 16.4.0", "sharp < 0.35.5 (bundles vulnerable librsvg)"],
        "fixedVersions": ["next 15.5.28", "next 16.4.1", "sharp 0.35.5 (librsvg 2.63.2)"],
        "tags": ["node", "npm", "nextjs"], "updatedAt": "2026-10-22T10:00:00Z"}
NEXT_SOURCES = [
    {"url": "https://github.com/advisories/GHSA-673q-mjm6-r5xr"},
    {"url": "https://nextjs.org/blog/nextjs-security-update-october-14-2026"},
    {"url": "https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw"},
    {"url": "https://some-blog.example.net/next-rce"}]
NODE = {"slug": "nodejs-october-2026-security-releases", "title": "Node2Shell", "product": "Node.js",
        "status": "live", "category": "patch", "severity": "critical", "patchStatus": "patched",
        "affectedVersions": ["22.x before 22.23.4, 24.x before 24.22.1, 26.x before 26.12.1",
                             "End-of-life lines 20.x, 23.x, 25.x and older: affected, no fix (upgrade to a supported line)",
                             "Bun before 1.4.4", "Google Brotli 1.0.3 to 1.2.0 (fixed 1.0.10 / 1.1.1 / 1.2.1)"],
        "fixedVersions": ["22.23.4", "24.22.1", "26.12.1", "Bun 1.4.4", "PyPI Brotli 1.2.1"],
        "tags": ["node", "python"], "updatedAt": "2026-10-21T10:00:00Z"}
TENSOR = {"slug": "tensorlake-npm-shai-hulud-worm", "title": "tensorlake@0.5.144 npm worm", "product": "tensorlake (npm)",
          "status": "live", "category": "supply-chain", "severity": "critical", "patchStatus": "partial",
          "affectedVersions": ["0.5.144"], "fixedVersions": ["0.5.143 (safe pin); remove 0.5.144"],
          "updatedAt": "2026-10-20T10:00:00Z"}
CLOSED = dict(NEXT, slug="old-closed-one", status="closed")
BREACH = dict(NEXT, slug="a-breach", category="breach")
X402 = {"slug": "x402-sdk-critical-flaws-v12", "title": "x402 SDK flaws", "product": "x402 SDKs (TypeScript @x402/*, Python x402, Go)",
        "status": "live", "category": "patch", "severity": "critical", "patchStatus": "patched",
        "affectedVersions": ["@x402/svm 2.0.0 to 2.22.0 (Solana approval accepted as payment)",
                             "@x402/fetch and @x402/axios before 2.23.0 (no default spending limit)",
                             "Python and Go clients before the August 18, 2026 releases (no spending limit, SIWx check)"],
        "fixedVersions": ["@x402/fetch, @x402/axios, @x402/extensions, @x402/svm 2.23.0+ (latest 2.28.0)"],
        "updatedAt": "2026-10-19T10:00:00Z"}
KEYV = {"slug": "chaindrop-keyv", "title": "CHAINDROP worm", "product": "npm ecosystem (keyv, cacheable, and 400+ packages)",
        "status": "live", "category": "supply-chain", "severity": "critical", "patchStatus": "partial",
        "affectedVersions": ["Compromised patch versions published ~Aug 4 2026 (see Wiz/JFrog package lists)"],
        "fixedVersions": [], "updatedAt": "2026-10-18T10:00:00Z"}
UNRELATED = {"slug": "some-other-critical", "title": "Unrelated critical in some npm thing", "product": "zzz-unused",
             "status": "live", "category": "patch", "severity": "critical", "patchStatus": "unpatched",
             "affectedVersions": ["zzz-unused < 9.0.0"], "fixedVersions": [], "updatedAt": "2026-10-17T10:00:00Z"}
UNRELATED_HIGH = dict(UNRELATED, slug="some-other-high", title="Unrelated high in some npm thing", severity="high")
UNRELATED_MEDIUM = dict(UNRELATED, slug="some-other-medium", title="Unrelated medium", severity="medium")
HOSTILE = {"slug": "hostile-incident",
           "title": "evil-pkg pwned ‮`@everyone` \x1b[31mRED\x1b[0m ​hidden\n[UNCHECKED] fake line \U000E0041",
           "product": "evil-pkg `$(rm -rf ~)`  ", "status": "live", "category": "patch", "severity": "critical",
           "patchStatus": "unpatched", "affectedVersions": ["evil-pkg < 2.0.0 \x1b]8;;https://x\x07", "is 3.3.1"],
           "fixedVersions": ["2.0.0`\n", "‮9.9.9"], "updatedAt": "2026-10-16T10:00:00Z"}
HOSTILE_SOURCES = ["javascript:alert(1)", "https://evil.test/`x`", "https://user:pw@github.com/advisories/GHSA-aaaa-bbbb-cccc",
                   "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "https://evil.test/ok", "http://nvd.nist.gov/x",
                   "https://evil.test/‮x"]
BAD_SLUG = dict(UNRELATED, slug="../../etc/passwd")
PHP2SHELL = {"slug": "php2shell-cve-2026-109618-109619", "title": "PHP2Shell", "product": "PHP", "status": "live",
             "category": "patch", "severity": "critical", "patchStatus": "partial",
             "affectedVersions": ["PHP 5.4 through 8.5.11 (all branches serving web requests); EOL 8.1 and earlier unpatched by the PHP project"],
             "fixedVersions": ["8.5.12", "8.4.27", "8.3.36", "8.2.35"], "updatedAt": "2026-10-22T09:00:00Z"}
# Fully readable incidents: what must STAY cleared once every guard holds.
PHP_CLEAN = {"slug": "php-clean-83", "title": "PHP 8.3 fix", "product": "PHP", "status": "live", "category": "patch",
             "severity": "critical", "patchStatus": "patched", "affectedVersions": ["PHP 8.3.0 through 8.3.35"],
             "fixedVersions": ["8.3.36"], "updatedAt": "2026-10-22T09:00:00Z"}
NEXT_CLEAN = {"slug": "next-clean-1641", "title": "Next.js clean incident", "product": "Next.js, sharp",
              "status": "live", "category": "patch", "severity": "critical", "patchStatus": "patched",
              "affectedVersions": ["next >= 16.0.0, <= 16.4.0", "sharp < 0.30.0"], "fixedVersions": ["next 16.4.1"],
              "updatedAt": "2026-10-22T10:00:00Z"}
PHP_SOURCES = ["https://www.php.net/archive/2026.php",
               "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"]
LARAVEL = {"slug": "laravel-tokenguard", "title": "Laravel TokenGuard bypass", "product": "Laravel framework (laravel/framework) TokenGuard",
           "status": "live", "category": "patch", "severity": "critical", "patchStatus": "patched",
           "affectedVersions": ["laravel/framework < 12.68.0"], "fixedVersions": ["laravel/framework 12.68.0"],
           "updatedAt": "2026-10-22T08:00:00Z"}
LITELLM = {"slug": "litellm-1-107-0-pypi-compromise", "title": "LiteLLM compromise", "product": "LiteLLM (PyPI + Docker)",
           "status": "live", "category": "supply-chain", "severity": "critical", "patchStatus": "patched",
           "affectedVersions": ["litellm==1.107.0; Docker/GHCR tags v1.107.0"], "fixedVersions": ["1.106.2"],
           "updatedAt": "2026-10-21T08:00:00Z"}

FEEDS = {
    "npm": [NEXT, TENSOR, CLOSED, BREACH, X402, KEYV, UNRELATED, HOSTILE, BAD_SLUG],
    "node": [NEXT, NODE, TENSOR],
    "php": [PHP2SHELL, LARAVEL],
    "docker": [LITELLM],
    "python": [NODE, LITELLM], "pypi": [LITELLM], "github-actions": [],
}
DETAILS = {NEXT["slug"]: {"incident": {"sources": NEXT_SOURCES}}, PHP2SHELL["slug"]: {"sources": PHP_SOURCES},
           HOSTILE["slug"]: {"sources": HOSTILE_SOURCES}}

LOCK_NEXT = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"next": "16.4.0"}},
    "node_modules/next": {"version": "16.4.0"}, "node_modules/react": {"version": "19.2.0"},
    "node_modules/is": {"version": "3.3.1"}, "node_modules/ms": {"version": "2.1.3"},
    "node_modules/sharp": {"version": "0.35.5"}}}


def _lock(next_version):
    lock = copy.deepcopy(LOCK_NEXT)
    lock["packages"][""]["dependencies"]["next"] = next_version
    lock["packages"]["node_modules/next"]["version"] = next_version
    return json.dumps(lock)


REPOS = {
    "empty": {},
    "next1640": {"package-lock.json": _lock("16.4.0"), "package.json": '{"name":"app","engines":{"node":">=22"}}'},
    "next1641": {"package-lock.json": _lock("16.4.1"), "package.json": '{"name":"app","engines":{"node":">=22"}}'},
    "php": {"composer.json": '{"name":"acme/app","require":{"php":"^8.1","laravel/framework":"^12.0"}}',
            "composer.lock": "{}", "Dockerfile": "FROM php:8.3-apache\nRUN docker-php-ext-install pdo\n"},
    "php2": {"composer.json": '{"name":"acme/app","require":{"php":"^8.1","laravel/framework":"^12.0"}}',
             "Dockerfile": "FROM php:8.3-apache\nRUN docker-php-ext-install pdo\n"},
    "php835": {"Dockerfile": "FROM php:8.3.35-cli\n"},
    "mixed": {"requirements.txt": "pillow==12.3.0\nrequests==2.32.0\n", ".nvmrc": "v20.11.1\n",
              "Dockerfile": "FROM --platform=linux/amd64 node:20-alpine AS build\nFROM python:3.12.4-slim\n",
              ".github/workflows/ci.yml": "on: push\njobs: {}\n"},
    "hostile": {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "h"}, "node_modules/evil-pkg": {"version": "1.0.0"}, "node_modules/is": {"version": "3.3.1"},
        "node_modules/tensorlake": {"version": "0.5.144"}, "node_modules/keyv": {"version": "5.0.0"},
        "node_modules/@x402/fetch": {"version": "2.22.9"}, "node_modules/@x402/svm": {"version": "2.23.0"}}})},
}

_TMP = None
_OLD_ENV = {}
_REAL_URLOPEN = urllib.request.urlopen


def _no_network(*a, **k):
    raise AssertionError("unmocked network request in a test")


def setUpModule():
    global _TMP, FX
    _TMP = Path(tempfile.mkdtemp(prefix="pwnwatch-tests-"))
    _OLD_ENV["XDG_CACHE_HOME"] = os.environ.get("XDG_CACHE_HOME")
    os.environ["XDG_CACHE_HOME"] = str(_TMP / "xdg")
    urllib.request.urlopen = _no_network
    FX = _TMP / "fx"
    for name, files in REPOS.items():
        make_repo(FX / name, files)


def tearDownModule():
    urllib.request.urlopen = _REAL_URLOPEN
    if _OLD_ENV["XDG_CACHE_HOME"] is None:
        os.environ.pop("XDG_CACHE_HOME", None)
    else:
        os.environ["XDG_CACHE_HOME"] = _OLD_ENV["XDG_CACHE_HOME"]
    shutil.rmtree(_TMP, ignore_errors=True)


def make_repo(root: Path, files: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


class FakePwn:
    def __init__(self, wa, offline=False, feeds=None, details=None, detail_fail=False):
        self.wa, self.offline, self.calls = wa, offline, []
        self.feeds = feeds if feeds is not None else FEEDS
        self.details = details if details is not None else DETAILS
        self.detail_fail = detail_fail

    def get(self, url, etag=None, attempts=3):
        self.calls.append((url, etag))
        if self.offline:
            raise self.wa.Unreachable(f"{url}: <urlopen error [Errno 8] nodename nor servname provided>")
        base = self.wa.BASE
        if url.startswith(f"{base}/t/"):
            tag = url[len(base) + 3:-5]
            if tag not in self.feeds:
                raise self.wa.Unreachable(f"{url}: HTTP 404")
            body = {"tag": tag, "incidents": copy.deepcopy(self.feeds[tag])}
            tag_etag = f'"etag-{tag}-{len(self.feeds[tag])}"'
            if etag == tag_etag:
                return 304, None, etag
            return 200, body, tag_etag
        if url.startswith(f"{base}/i/"):
            if self.detail_fail:
                raise self.wa.Unreachable(f"{url}: timed out")
            slug = url[len(base) + 3:-5]
            return 200, copy.deepcopy(self.details.get(slug, {"sources": []})), None
        raise AssertionError(url)


def load_md():
    spec = importlib.util.spec_from_file_location("md_under_test", SCRIPT)
    md = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(md)

    def post(url, payload, attempts=3):
        return {"results": [{} for _ in payload["queries"]]}

    def get(url, attempts=3):
        if "known_exploited" in url:
            return {"vulnerabilities": []}
        if "endoflife" in url:
            return [{"cycle": "22", "eol": "2027-04-30"}]
        return {}
    md._post, md._get = post, get
    return md


def run(path, *args, offline=False, state=None, feeds=None, details=None, detail_fail=False, osv_fail=False):
    md = load_md()
    if osv_fail:
        def boom(url, payload, attempts=3):
            raise md.Unreachable(f"{url}: down")
        md._post = boom
    orig = md._pw_load_watcher
    holder = {}

    def patched():
        wa = orig()
        holder["fake"] = FakePwn(wa, offline=offline, feeds=feeds, details=details, detail_fail=detail_fail)
        wa._get = holder["fake"].get
        return wa
    md._pw_load_watcher = patched
    argv = ["monitor-deps.py", "--path", str(path), *args]
    if "--pwnwatch" in args and state is not None:
        argv += ["--pwnwatch-state", str(state)]
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv
    sys.argv = argv
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = md.main()
    finally:
        sys.argv = old
    return code, out.getvalue(), err.getvalue(), holder.get("fake")


def by_slug(data, slug):
    return next((r for r in data["pwnwatch"] if r["slug"] == slug), None)


_MD = None


def md_wa():
    global _MD
    if _MD is None:
        md = load_md()
        _MD = (md, md._pw_load_watcher())
    return _MD


def range_verdict(text, installed):
    """What the grammar alone says: check (unparsed), affected, or not-affected."""
    md, _ = md_wa()
    r = md._pw_ranges(text)
    if r is None:
        return "check"
    p = md._vparse(installed)
    k = md._vkey(p[0], p[1])
    if any(md._in_range(x, k) for x in r):
        return "affected"
    return "check" if any(x[4] for x in r) else "not-affected"


def pkg_verdicts(deps, product, affected, fixed=None):
    md, wa = md_wa()
    inc = {"slug": "x", "title": product, "product": product, "status": "live", "category": "patch",
           "severity": "critical", "patchStatus": "patched", "affectedVersions": affected,
           "fixedVersions": fixed or []}
    item = wa.sanitise(inc, None)
    idx = {}
    for eco, name, ver in deps:
        idx.setdefault((eco, md._pw_norm(eco, name)), (name, set()))[1].add(ver)
    return {(m["name"], m["version"]): m["verdict"] for m in md._pw_match_packages(item, idx)}


def runtime_verdicts(files, inc, tmp):
    md, wa = md_wa()
    d = make_repo(Path(tempfile.mkdtemp(dir=tmp)), files)
    notes = []
    _, rts = md.pwn_detect(d, [], notes)
    ms = md._pw_match_runtimes(wa.sanitise(inc, None), rts)
    return [(m["runtime"], m["declared"], m["verdict"], bool(m.get("nofix"))) for m in ms], rts, notes


# --- Finding 1 + 7: the range grammar (text, installed, expected) -------------------------
RANGE_CASES = [
    # open-ended upward ranges: inside is affected, below is not
    ("1.0.0 or later", "1.9.0", "affected"), ("1.0.0 or later", "0.9.0", "not-affected"),
    ("1.0.0 and later", "1.9.0", "affected"), ("1.0.0 and later", "0.5.0", "not-affected"),
    ("1.0.0 and above", "9.0.0", "affected"), ("1.0.0 or newer", "9.0.0", "affected"),
    ("1.0.0 and newer", "9.0.0", "affected"), ("1.0.0 onwards", "9.0.0", "affected"),
    ("1.0.0+", "9.0.0", "affected"), ("1.0.0+", "0.9.9", "not-affected"),
    ("from 1.0.0", "9.0.0", "affected"), ("since 1.0.0", "9.0.0", "affected"),
    ("since 1.0.0", "0.9.0", "not-affected"), ("after 1.0.0", "1.0.0", "not-affected"),
    ("after 1.0.0", "1.0.1", "affected"), ("greater than 1.0.0", "9.0.0", "affected"),
    ("newer than 1.0.0", "9.0.0", "affected"), ("1.0.0 and all later versions", "9.0.0", "affected"),
    (">= 2.0.0", "9.0.0", "affected"), ("≥ 2.0.0", "9.0.0", "affected"),
    # upper bounds
    ("less than 2.0.0", "1.0.0", "affected"), ("less than 2.0.0", "2.0.0", "not-affected"),
    ("lower than 2.0.0", "1.0.0", "affected"), ("under 2.0.0", "1.0.0", "affected"),
    ("until 2.0.0", "1.0.0", "affected"), ("up until 2.0.0", "2.0.0", "not-affected"),
    ("before 2.0.0", "1.9.9", "affected"), ("prior to 2.0.0", "2.0.0", "not-affected"),
    ("pre-2.0.0", "1.0.0", "affected"), ("pre-2.0.0", "2.0.0", "not-affected"),
    ("through 2.0.0", "2.0.0", "affected"), ("thru 2.0.0", "2.0.1", "not-affected"),
    ("up to 2.0.0", "2.0.0", "affected"), ("2.0.0 and earlier", "1.0.0", "affected"),
    ("2.0.0 and prior", "2.0.0", "affected"), ("2.0.0 or lower", "2.0.1", "not-affected"),
    ("everything before 2.0.0", "1.0.0", "affected"), ("any version prior to 2.0.0", "1.0.0", "affected"),
    ("<2.0.0 only", "1.0.0", "affected"), ("<2", "1.9.9", "affected"), ("≤ 2.0.0", "2.0.0", "affected"),
    ("< 2.x", "1.9.0", "affected"), ("<2.x", "2.1.0", "not-affected"), ("<= 2.x", "2.9.0", "affected"),
    # two-sided
    ("between 1.0 and 2.0", "1.5.0", "affected"), ("between 1.0 and 2.0", "2.1.0", "not-affected"),
    ("2.0.0 to 2.5.0", "2.2.0", "affected"), ("2.0.0 through 2.5.0", "2.5.0", "affected"),
    ("2.0.0 - 2.5.0", "2.6.0", "not-affected"), ("2.0.0-2.5.0", "2.2.0", "affected"),
    ("2.0.0 – 2.5.0", "2.2.0", "affected"), ("2.0.0..2.5.0", "2.2.0", "affected"),
    ("2.0.0 -> 2.5.0", "2.2.0", "affected"), ("2.0.0 -> 2.5.0", "1.0.0", "not-affected"),
    ("2.0-2.5", "2.5.9", "affected"), ("from 2.0.0 to 2.5.0", "2.5.0", "affected"),
    ("2019.3.9 to before 2026.10.19", "2026.10.19", "not-affected"),
    (">= 10.0.0, <= 15.5.27", "15.5.27", "affected"), (">= 10.0.0, <= 15.5.27", "15.5.28", "not-affected"),
    (">= 10.0.0, <= 15.5.27", "9.9.9", "not-affected"), (">=10.0.0 <15.5.28", "11.0.0", "affected"),
    ("1.x before 1.4.2, 2.x before 2.1.1", "2.0.5", "affected"),
    ("1.x before 1.4.2, 2.x before 2.1.1", "3.0.0", "not-affected"),
    ("0.x < 0.5.2", "0.5.1", "affected"), ("8.3 before 8.3.36", "8.3.35", "affected"),
    ("8.3 before 8.3.36", "8.2.0", "not-affected"), ("8.3 before 8.4.1", "8.3.5", "check"), ("16.0.0-canary.1 to 16.4.0", "16.2.0", "affected"),
    # caret / tilde: inside proves affected, outside is only "check"
    ("^1.2.3", "1.5.0", "affected"), ("^1.2.3", "2.0.0", "check"), ("~1.2.3", "1.2.9", "affected"),
    ("~1.2.3", "1.3.0", "check"), ("~> 1.2", "1.9.0", "affected"),
    # exact version lists only
    ("1.2.3 and 1.2.4", "1.2.4", "affected"), ("1.2.3, 1.2.4 / 1.2.5", "1.2.6", "not-affected"),
    ("0.5.144", "0.5.144", "affected"), ("2.x", "2.0.0", "affected"), ("2.x", "3.0.0", "not-affected"),
    # finding 7: "fixed in X" is not an affected version
    ("4.0.0 to 4.17.20, fixed in 4.17.21", "4.17.21", "not-affected"),
    ("4.0.0 to 4.17.20, fixed in 4.17.21", "4.17.20", "affected"),
    ("4.0.0 to 4.17.20 (fixed 4.17.21)", "4.17.21", "not-affected"),
    ("13.0.0 to 14.1.0 fixed 14.1.1", "14.1.1", "not-affected"),
    ("1.0 to 1.5, fixed in 1.6, 2.0 to 2.5", "2.2.0", "affected"),
    # anything left over -> check, never a verdict
    ("1.2.3 and later 1.x", "1.9.0", "check"), ("2.0.0 (and later)", "9.0.0", "check"),
    ("fixed before 2.0.0", "1.0.0", "check"), ("not fixed until 2.0.0", "1.0.0", "check"),
    ("x < 2.0.0", "1.0.0", "check"), ("v <2.0.0", "1.0.0", "check"), ("*", "1.0.0", "check"),
    ("latest", "1.0.0", "check"), ("all", "1.0.0", "check"), ("2", "2.0.0", "check"),
    ("Windows 10 before 1.2.3", "1.0.0", "check"), ("before 2.0.0 and 3", "9.0.0", "check"),
    ("1.0.0 or later except 1.5.0", "1.5.0", "check"), ("14.0.0 < 14.1.1", "14.0.0", "check"),
    ("v1.2.3-v1.2.9", "1.2.5", "affected"), ("2.0.0 2.5.0", "2.2.0", "check"), ("!= 1.0.0", "2.0.0", "check"),
    ("2026-10-19", "2026.10.19", "check"), ("See vendor advisory", "1.0.0", "check"), ("", "1.0.0", "check"),
    ("before the August 18, 2026 releases", "1.0.0", "check"),
    ("Compromised patch versions published ~Aug 4 2026", "1.0.0", "check"),
    # PEP 440 post-releases (finding 9)
    ("< 5.0.0", "5.0.0.post1", "not-affected"), ("<= 5.0.0", "5.0.0.post1", "not-affected"),
    ("5.0.0.post1", "5.0.0.post1", "affected"), ("< 5.0.0", "5.0.0rc1", "affected"),
]


class RangeGrammar(unittest.TestCase):
    def test_range_table(self):
        for text, installed, want in RANGE_CASES:
            with self.subTest(text=text, installed=installed):
                self.assertEqual(range_verdict(text, installed), want)

    def test_version_order(self):
        md, _ = md_wa()
        k = lambda v: md._vkey(*md._vparse(v)[:2])
        order = ["5.0.0.dev1", "5.0.0a1", "5.0.0rc1", "5.0.0", "5.0.0.post1", "5.0.0.post2", "5.0.1"]
        self.assertEqual(sorted(order, key=k), order)


# --- Findings 2 + 3 + 7: package segments (deps, product, affected, expected) ---------------
PKG_CASES = [
    # finding 1 at package level
    ([("npm", "axios", "1.9.0")], "axios", ["axios 1.0.0 or later"], {("axios", "1.9.0"): "affected"}),
    ([("npm", "axios", "0.9.0")], "axios", ["axios 1.0.0 or later"], {("axios", "0.9.0"): "not-affected"}),
    ([("npm", "axios", "0.5.0")], "axios", ["axios less than 1.0.0"], {("axios", "0.5.0"): "affected"}),
    # finding 2: multi-range text after one name
    ([("npm", "express", "5.0.0")], "Express", ["express 4.x before 4.19.2; 5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.1")], "Express", ["express 4.x before 4.19.2; 5.x before 5.0.1"], {("express", "5.0.1"): "not-affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express 4.x before 4.19.2, and 5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express 4.x before 4.19.2, or 5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express 4.x before 4.19.2, plus 5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express 4.x before 4.19.2, all 5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express 4.x before 4.19.2, v5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express 4.x before 4.19.2", "5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.1")], "x", ["express 4.x before 4.19.2", "5.x before 5.0.1"], {("express", "5.0.1"): "not-affected"}),
    ([("npm", "express", "5.0.0")], "Express", ["4.x before 4.19.2; 5.x before 5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express <4.19.2, versions >=5.0.0 <5.0.1"], {("express", "5.0.0"): "affected"}),
    ([("npm", "express", "5.0.0")], "x", ["express < 4.19.2; < 5.0.1 on 5.x"], {("express", "5.0.0"): "check"}),
    ([("npm", "next", "14.0.0")], "x", ["next 13.x before 13.5.1, v14.x before 14.1.1"], {("next", "14.0.0"): "affected"}),
    ([("npm", "next", "14.1.1")], "x", ["next 13.x before 13.5.1, v14.x before 14.1.1"], {("next", "14.1.1"): "not-affected"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.5.1, Canary <= 14.1.0"], {("next", "14.0.0"): "check"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.5.1, app-router 14.0.0 to 14.1.0"], {("next", "14.0.0"): "check"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.5.1, v14.0.0 < 14.1.1"], {("next", "14.0.0"): "check"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.5.1, since 14.0.0 < 14.1.1"], {("next", "14.0.0"): "check"}),
    # two installed packages on one line split at the second name; an uninstalled one does not
    ([("npm", "next", "14.0.0"), ("npm", "react", "18.0.0")], "x", ["next < 13.0.0, react < 19.0.0"],
     {("next", "14.0.0"): "not-affected", ("react", "18.0.0"): "affected"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.0.0, react < 19.0.0"], {("next", "14.0.0"): "check"}),
    # finding 3: everyday-word names are never dropped silently once a version follows them
    ([("npm", "next", "15.1.0")], "x", ["next 15.0.0 - 15.5.27 when using Node 18"], {("next", "15.1.0"): "check"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.5.1 and 14 before 14.1.1"], {("next", "14.0.0"): "affected"}),
    ([("npm", "next", "14.1.1")], "x", ["next < 13.5.1 and 14 before 14.1.1"], {("next", "14.1.1"): "not-affected"}),
    ([("npm", "next", "14.0.0")], "x", ["next < 13.5.1 and 14 before 15.1.1"], {("next", "14.0.0"): "check"}),
    ([("npm", "next", "14.0.0")], "Foo", ["foo < 1.0.0; fixed in the next release"], {}),
    # brand tokens, slash lists, scope-less scoped names, PyPI '_' (dropped by the sanitiser)
    ([("npm", "next", "15.1.0")], "Next.js", ["15.0.0 to 15.5.27"], {("next", "15.1.0"): "affected"}),
    ([("npm", "next", "15.1.0")], "web", ["Next.js 15.0.0 to 15.5.27"], {("next", "15.1.0"): "affected"}),
    ([("npm", "express", "4.18.0")], "Express.js", ["< 4.19.2"], {("express", "4.18.0"): "affected"}),
    ([("npm", "next", "14.0.0"), ("npm", "react", "18.0.0")], "x", ["next/react < 99.0.0"],
     {("next", "14.0.0"): "affected", ("react", "18.0.0"): "affected"}),
    ([("npm", "@nestjs/core", "10.0.0")], "NestJS", ["nestjs/core < 10.4.16"], {("@nestjs/core", "10.0.0"): "affected"}),
    ([("PyPI", "typing_extensions", "4.11.0")], "x", ["typing_extensions < 4.12.0"], {("typing_extensions", "4.11.0"): "affected"}),
    # The sanitiser deletes '_', so the text counts as altered: never cleared, only check (H1).
    ([("PyPI", "Typing-Extensions", "4.12.0")], "x", ["typing_extensions < 4.12.0"], {("Typing-Extensions", "4.12.0"): "check"}),
    ([("PyPI", "Typing-Extensions", "4.12.0")], "x", ["typing-extensions < 4.12.0"], {("Typing-Extensions", "4.12.0"): "not-affected"}),
    # finding 7 at package level
    ([("npm", "lodash", "4.17.21")], "lodash", ["lodash 4.0.0 to 4.17.20, fixed in 4.17.21"], {("lodash", "4.17.21"): "not-affected"}),
    ([("npm", "lodash", "4.17.20")], "lodash", ["lodash 4.0.0 to 4.17.20, fixed in 4.17.21"], {("lodash", "4.17.20"): "affected"}),
    # name@version and a product-only name with a bare version line
    ([("npm", "tensorlake", "0.5.144")], "x", ["tensorlake@0.5.144"], {("tensorlake", "0.5.144"): "affected"}),
    ([("npm", "tensorlake", "0.5.143")], "tensorlake (npm)", ["0.5.144"], {("tensorlake", "0.5.143"): "not-affected"}),
]


class PackageSegments(unittest.TestCase):
    def test_package_table(self):
        for deps, product, affected, want in PKG_CASES:
            with self.subTest(affected=affected, deps=deps):
                self.assertEqual(pkg_verdicts(deps, product, affected), want)


# --- Findings 4 + 6: runtime declarations (files, incident, expected) ----------------------
RUNTIME_CASES = [
    # finding 6: constraints are check, never a hit, never nofix
    ({"composer.json": '{"require":{"php":"^8.1"}}'}, PHP2SHELL, [("php", "8.1", "check", False)]),
    ({"composer.json": '{"require":{"php":">=8.1 <8.5"}}'}, PHP2SHELL, [("php", "8.1", "check", False)]),
    ({"composer.json": '{"require":{"php":"^8.3"},"config":{"platform":{"php":"8.1.0"}}}'}, PHP2SHELL,
     [("php", "8.3", "check", False), ("php", "8.1.0", "check", False)]),
    ({"package.json": '{"engines":{"node":">=18"}}'}, NODE, [("node", "18", "check", False)]),
    ({"package.json": '{"engines":{"node":"<20"}}'}, NODE, [("node", None, "check", False)]),
    ({"package.json": '{"engines":{"node":"22.23.3"}}'}, NODE, [("node", "22.23.3", "check", False)]),
    # finding 4: unreadable declarations become a version-less runtime -> check
    ({".nvmrc": "lts/*\n"}, NODE, [("node", None, "check", False)]),
    ({".nvmrc": "lts/iron\n"}, NODE, [("node", None, "check", False)]),
    ({".nvmrc": "node\n"}, NODE, [("node", None, "check", False)]),
    ({".nvmrc": "# pinned\n20\n"}, NODE, [("node", "20", "affected", True)]),
    ({".nvmrc": "20.x\n"}, NODE, [("node", "20", "affected", True)]),
    ({"package.json": '{"engines":{"node":18}}'}, NODE, [("node", None, "check", False)]),
    ({"package.json": '{"engines":"node >=18"}'}, NODE, [("node", None, "check", False)]),
    ({"package.json": "{not json"}, NODE, [("node", None, "check", False)]),
    ({"package.json": "[]"}, NODE, [("node", None, "check", False)]),
    ({"package.json": '{"volta":{"node":"18.0.0"}}'}, NODE, [("node", "18.0.0", "affected", True)]),
    ({"package.json": '{"packageManager":"bun@1.1.0"}'}, NODE, [("bun", "1.1.0", "affected", True)]),
    # NODE's EOL line does not parse and its Brotli line names nothing we recognise: not cleared.
    ({".tool-versions": "nodejs 22.23.4\n"}, NODE, [("node", "22.23.4", "check", False)]),
    ({"docker-compose.yml": "services:\n  web:\n    image: php:8.1-apache\n"}, PHP2SHELL, [("php", "8.1", "affected", True)]),
    ({"Dockerfile": "FROM mirror.example.com/php:8.1\n"}, PHP2SHELL, [("php", None, "check", False)]),
    ({"Dockerfile": "FROM bitnami/node:22.23.4\n"}, NODE, [("node", None, "check", False)]),
    ({"Dockerfile": "ARG V=8.1\nFROM php:${V}-fpm\n"}, PHP2SHELL, [("php", None, "check", False)]),
    ({"Dockerfile": "FROM php:8.4.27RC1-cli\n"}, PHP2SHELL, [("php", "8.4.27RC1", "affected", False)]),
    ({"Dockerfile": "FROM php:8.4.27-RC1\n"}, PHP2SHELL, [("php", "8.4.27RC1", "affected", False)]),
    ({"Dockerfile": "FROM php:8.4.27-rc1-fpm-alpine3.20\n"}, PHP2SHELL, [("php", "8.4.27rc1", "affected", False)]),
    ({"Dockerfile": "FROM php:8.4.27-foo1\n"}, PHP2SHELL, [("php", None, "check", False)]),
    ({"Dockerfile": "FROM php:8.3.35-fpm-bookworm\n"}, PHP2SHELL, [("php", "8.3.35", "affected", False)]),
    ({"Dockerfile": "FROM php:8.3-apache AS base\nFROM base AS prod\n"}, PHP2SHELL, [("php", "8.3", "check", False)]),
    # exact deployed versions keep their verdicts
    ({"Dockerfile": "FROM php:8.3.35-cli\n"}, PHP2SHELL, [("php", "8.3.35", "affected", False)]),
    # PHP2SHELL's "(all branches serving web requests)" and NODE's EOL/Brotli lines are not read
    # completely, so the fixed versions are check, not cleared (guards c/d).
    ({"Dockerfile": "FROM php:8.3.36-cli\n"}, PHP2SHELL, [("php", "8.3.36", "check", False)]),
    ({"Dockerfile": "FROM node:22.23.4-alpine\n"}, NODE, [("node", "22.23.4", "check", False)]),
    ({"Dockerfile": "FROM php:8.3.36-cli\n"}, PHP_CLEAN, [("php", "8.3.36", "not-affected", False)]),
    ({"Dockerfile": "FROM php:8.3.35-cli\n"}, PHP_CLEAN, [("php", "8.3.35", "affected", False)]),
]


class Runtimes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=_TMP))

    def test_runtime_table(self):
        for files, inc, want in RUNTIME_CASES:
            with self.subTest(files=files):
                self.assertEqual(runtime_verdicts(files, inc, self.tmp)[0], want)

    def test_unresolvable_base_image_is_unchecked(self):
        for df in ("ARG BASE=php:8.1\nFROM ${BASE}\n", "FROM php:8.3.35-\x1b[2J\x1b]8;;http://evil\x07PWNED\n"):
            _, rts, notes = runtime_verdicts({"Dockerfile": df}, PHP2SHELL, self.tmp)
            self.assertEqual(rts, [])
            self.assertEqual(len(notes), 1)
            self.assertIn("were not checked", notes[0])
            self.assertNotIn("\x1b", notes[0])

    def test_constraint_reason_and_eol_note(self):
        md, wa = md_wa()
        d = make_repo(self.tmp / "c", {"composer.json": '{"require":{"php":"^8.1"}}'})
        _, rts = md.pwn_detect(d, [])
        (m,) = md._pw_match_runtimes(wa.sanitise(PHP2SHELL, None), rts)
        self.assertIn("a version constraint does not identify the deployed patch level", m["reason"])
        self.assertIn("note: it admits the 8.1 line", m["reason"])
        self.assertTrue(m["constraint"])
        self.assertNotIn("nofix", m)

    def test_floor(self):
        md, _ = md_wa()
        for text, want in (("<20", None), ("<=24", None), ("*", None), (">=18", "18"), ("^8.1 || ^8.2", "8.1"),
                           (">=8.1 <8.5", "8.1"), ("8.3.*", "8.3"), ("~8.4.0", "8.4.0"), (">5 || <3", None),
                           ("1.2 - 2.3", "1.2"), ("lts/*", None)):
            with self.subTest(text=text):
                self.assertEqual(md._pw_floor(text), want)

    def test_nvmrc_range_plus_exact_docker_is_not_reported_clean(self):
        feeds = {"node": [NODE], "docker": [], "npm": []}
        d = make_repo(self.tmp / "nv", {".nvmrc": "20.x\n", "Dockerfile": "FROM node:22.23.4\n"})
        code, text, _, _ = run(d, "--pwnwatch", state=self.tmp / "s.json", feeds=feeds)
        self.assertNotIn("parsed as not affecting", text)
        self.assertIn("AFFECTED: Node.js 20 (.nvmrc: .nvmrc 20.x)", text)
        d2 = make_repo(self.tmp / "nv2", {".nvmrc": "lts/iron\n", "Dockerfile": "FROM node:22.23.4\n"})
        code, text, _, _ = run(d2, "--pwnwatch", state=self.tmp / "s2.json", feeds=feeds)
        self.assertNotIn("parsed as not affecting", text)
        self.assertIn("PWN check manually", text)
        self.assertIn("runtime version not read: .nvmrc", text)
        self.assertEqual(code, 0)                  # check manually never changes the exit code


class T(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=_TMP))
        self.state = self.tmp / "state.json"

    # --- plan acceptance: Next.js match with vendor link and fix -------------------------
    def test_next_1640_affected_with_vendor_link_and_fix(self):
        code, out, err, fake = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        data = json.loads(out)
        r = by_slug(data, NEXT["slug"])
        self.assertEqual(r["verdict"], "affected")
        self.assertIn("next 16.4.1", r["fixed"])
        urls = {s["url"]: s["trusted"] for s in r["sources"]}
        self.assertTrue(urls["https://github.com/advisories/GHSA-673q-mjm6-r5xr"])
        self.assertTrue(urls["https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw"])
        self.assertFalse(urls["https://some-blog.example.net/next-rce"])
        self.assertEqual(r["tracker"], f"https://pwn.watch/i/{NEXT['slug']}")
        self.assertFalse(r["urgent"])
        m = [x for x in r["matches"] if x["kind"] == "package"]
        # sharp's "(bundles vulnerable librsvg)" is not an allow-listed parenthetical: check.
        self.assertEqual({(x["name"], x["verdict"]) for x in m}, {("next", "affected"), ("sharp", "check")})
        self.assertEqual(code, 1)
        code_t, text, _, _ = run(FX / "next1640", "--pwnwatch", state=self.state)
        self.assertIn("vendor: https://github.com/advisories/GHSA-673q-mjm6-r5xr", text)
        self.assertIn("source (unverified host): https://some-blog.example.net/next-rce", text)
        self.assertIn(f"tracker: https://pwn.watch/i/{NEXT['slug']}", text)
        self.assertIn("fixed: next 15.5.28 | next 16.4.1", text)
        self.assertIn("AFFECTED: next 16.4.0 is inside 'next >= 16.0.0, <= 16.4.0'", text)

    def test_next_1641_not_affected(self):
        code, out, err, _ = run(FX / "next1641", "--pwnwatch", "--json", state=self.state)
        r = by_slug(json.loads(out), NEXT["slug"])
        v = {m["name"]: m["verdict"] for m in r["matches"] if m["kind"] == "package"}
        # next itself is cleared; sharp's unrecognised parenthetical keeps the incident at check.
        self.assertEqual(v, {"next": "not-affected", "sharp": "check"})
        self.assertEqual(r["verdict"], "check")
        code_t, text, _, _ = run(FX / "next1641", "--pwnwatch", state=self.state)
        self.assertIn("PWN check manually: critical, patched] Next.js out-of-band", text)
        self.assertNotIn("CHECK: next 16.4.1", text)

    def test_clean_incident_end_to_end_is_parsed_not_affecting(self):
        feeds = {"node": [], "npm": [NEXT_CLEAN]}
        code, out, _, _ = run(FX / "next1641", "--pwnwatch", "--json", state=self.state, feeds=feeds)
        r = by_slug(json.loads(out), NEXT_CLEAN["slug"])
        self.assertEqual(r["verdict"], "not-affected")
        code, text, _, _ = run(FX / "next1641", "--pwnwatch", state=self.state, feeds=feeds)
        self.assertIn("pwn.watch: 1 matched incident(s) parsed as not affecting", text)
        code, out, _, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state, feeds=feeds)
        self.assertEqual(by_slug(json.loads(out), NEXT_CLEAN["slug"])["verdict"], "affected")

    def test_filters_live_patch_supply_chain_only(self):
        code, out, err, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        slugs = {r["slug"] for r in json.loads(out)["pwnwatch"]}
        self.assertNotIn("old-closed-one", slugs)
        self.assertNotIn("a-breach", slugs)
        self.assertNotIn("../../etc/passwd", slugs)

    # --- PHP --------------------------------------------------------------------------
    def test_php2shell_constraint_and_floating_tag_are_check(self):
        code, out, err, fake = run(FX / "php2", "--pwnwatch", "--json", state=self.state)
        data = json.loads(out)
        self.assertEqual(data["pwnwatch_tags"], ["docker", "php"])
        r = by_slug(data, PHP2SHELL["slug"])
        self.assertEqual(r["verdict"], "check")
        self.assertFalse(r["urgent"])
        ms = {m["source"]: m for m in r["matches"]}
        m81 = ms["composer.json: require.php ^8.1"]
        self.assertEqual(m81["verdict"], "check")
        self.assertIn("constraint does not identify the deployed patch level", m81["reason"])
        m83 = ms["Dockerfile: FROM php:8.3-apache"]
        self.assertEqual(m83["verdict"], "check")
        self.assertIn("fixed in 8.3.36", m83["reason"])
        self.assertIn("check the tag/digest", m83["reason"])
        self.assertIn("https://www.php.net/archive/2026.php", [s["url"] for s in r["sources"]])
        lar = by_slug(data, LARAVEL["slug"])
        self.assertTrue(lar["unmatched"])
        self.assertEqual(lar["verdict"], "check")

    def test_php_exact_tags(self):
        d = make_repo(self.tmp / "phpx", {"Dockerfile": "FROM php:8.3.30-fpm AS a\nFROM php:8.3.36-apache\nFROM php:8.6.1-cli\n"})
        code, out, err, _ = run(d, "--pwnwatch", "--json", state=self.state)
        r = by_slug(json.loads(out), PHP2SHELL["slug"])
        v = {m["declared"]: m["verdict"] for m in r["matches"]}
        # 8.3.36 and 8.6.1: the affected text ("(all branches serving web requests)", "EOL 8.1 and
        # earlier unpatched by ...") is not read completely, so neither is cleared.
        self.assertEqual(v, {"8.3.30": "affected", "8.3.36": "check", "8.6.1": "check"})
        self.assertTrue(r["urgent"])

    def test_php835_partial_is_urgent_and_fails_every_mode(self):
        # Finding 5: behaviour kept. patchStatus partial => urgent even though 8.3.36 exists.
        for mode in ("any", "kev", "epss"):
            code, text, _, _ = run(FX / "php835", "--pwnwatch", "--fail-on", mode, state=self.state)
            self.assertEqual(code, 1, mode)
            self.assertIn("[PWN critical, partial: URGENT] PHP2Shell", text)
            self.assertIn("fixed in 8.3.36 on the 8.3 line", text)

    def test_node_runtime(self):
        d = make_repo(self.tmp / "nodex", {".nvmrc": "v20.11.1\n", "Dockerfile":
                      "FROM node:22.23.0-alpine\nFROM node:24.22.1\nFROM node:lts\nFROM oven/bun:1.3.2\n"})
        code, out, err, _ = run(d, "--pwnwatch", "--json", state=self.state)
        r = by_slug(json.loads(out), NODE["slug"])
        v = {(m["runtime"], m["declared"]): m["verdict"] for m in r["matches"]}
        self.assertEqual(v[("node", "20.11.1")], "affected")
        self.assertEqual(v[("node", "22.23.0")], "affected")
        self.assertEqual(v[("node", "24.22.1")], "check")           # NODE's text is not read completely
        self.assertEqual(v[("node", None)], "check")
        self.assertEqual(v[("bun", "1.3.2")], "affected")
        self.assertTrue(r["urgent"])            # line 20 has no fix

    # --- fail-on ----------------------------------------------------------------------
    def test_fail_on(self):
        feeds = {k: [i for i in v if i is not HOSTILE] for k, v in FEEDS.items()}
        self.assertEqual(run(FX / "php835")[0], 0)
        for mode in ("any", "kev", "epss"):
            self.assertEqual(run(FX / "php835", "--pwnwatch", "--fail-on", mode, state=self.state)[0], 1, mode)
        # constraint + floating tag only: check manually, never a failure (finding 6)
        for mode in ("any", "kev", "epss"):
            self.assertEqual(run(FX / "php2", "--pwnwatch", "--fail-on", mode, state=self.state)[0], 0, mode)
        for mode, want in (("any", 1), ("kev", 0), ("epss", 0)):
            self.assertEqual(run(FX / "next1640", "--pwnwatch", "--fail-on", mode, state=self.state,
                                 feeds=feeds)[0], want, mode)
        self.assertEqual(run(FX / "next1641", "--pwnwatch", state=self.state, feeds=feeds)[0], 0)
        self.assertEqual(run(FX / "next1640", "--pwnwatch", "--fail-on", "kev", state=self.tmp / "s2")[0], 1)

    # --- 304 / ETag / state (plan acceptance + finding 9) --------------------------------
    def test_304_reuses_cached_incidents_and_rematches_changed_lockfile(self):
        code1, out1, _, fake1 = run(FX / "next1641", "--pwnwatch", "--json", state=self.state)
        self.assertTrue(all(etag is None for url, etag in fake1.calls if "/t/" in url))
        st = json.loads(self.state.read_text())
        self.assertIn("incidents", st["tags"]["npm"])
        self.assertEqual(by_slug(json.loads(out1), NEXT["slug"])["verdict"], "check")
        code2, out2, _, fake2 = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        tag_calls = [(u, e) for u, e in fake2.calls if "/t/" in u]
        self.assertTrue(tag_calls and all(e and e.startswith('"etag-') for u, e in tag_calls))
        r = by_slug(json.loads(out2), NEXT["slug"])
        self.assertEqual(r["verdict"], "affected")
        self.assertTrue(r["sources"])
        self.assertEqual(code2, 1)

    def test_etag_not_sent_without_cached_incidents(self):
        self.state.write_text(json.dumps({"version": 1, "tags": {"npm": {"etag": '"etag-npm-9"'}}}))
        code, out, _, fake = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        self.assertTrue(all(e is None for u, e in fake.calls if "/t/" in u))
        self.assertEqual(by_slug(json.loads(out), NEXT["slug"])["verdict"], "affected")

    def test_bad_etag_in_state_is_dropped_not_unchecked_forever(self):
        run(FX / "next1640", "--pwnwatch", state=self.state)
        st = json.loads(self.state.read_text())
        st["tags"]["npm"]["etag"] = '"x"\r\nX-Evil: 1'
        self.state.write_text(json.dumps(st))
        code, out, _, fake = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        npm_calls = [e for u, e in fake.calls if u.endswith("/t/npm.json")]
        self.assertEqual(npm_calls, [None])
        self.assertFalse(json.loads(out)["pwnwatch_unchecked"])
        self.assertEqual(json.loads(self.state.read_text())["tags"]["npm"]["etag"], '"etag-npm-9"')

    def test_state_from_other_version_is_ignored(self):
        run(FX / "next1640", "--pwnwatch", state=self.state)
        st = json.loads(self.state.read_text())
        st["version"] = 99
        self.state.write_text(json.dumps(st))
        code, out, _, fake = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        self.assertTrue(all(e is None for u, e in fake.calls if "/t/" in u))
        self.assertEqual(json.loads(self.state.read_text())["version"], 1)

    def test_state_file_is_private_and_no_tmp_left(self):
        run(FX / "next1640", "--pwnwatch", state=self.state)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertEqual([p.name for p in self.tmp.iterdir()], ["state.json"])

    def test_same_slug_in_two_feeds_keeps_newest(self):
        old = dict(UNRELATED, slug="dup-incident", title="old title", updatedAt="2026-10-01T00:00:00Z")
        new = dict(UNRELATED, slug="dup-incident", title="new title", updatedAt="2026-10-20T00:00:00Z")
        code, out, _, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state,
                              feeds={"node": [new], "npm": [old]})
        r = by_slug(json.loads(out), "dup-incident")
        self.assertEqual(r["title"], "new title")
        self.assertEqual(sorted(r["feeds"]), ["node", "npm"])

    def test_truncated_feed_warns(self):
        many = [dict(UNRELATED_MEDIUM, slug=f"inc-{i}") for i in range(305)]
        code, out, _, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state,
                              feeds={"node": [], "npm": many})
        self.assertTrue(any("only the first 300" in w for w in json.loads(out)["pwnwatch_warnings"]))
        code, out, _, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state,
                              feeds={"node": [], "npm": many})
        self.assertTrue(any("truncated at 300" in w for w in json.loads(out)["pwnwatch_warnings"]))

    def test_detail_failure_budget(self):
        incs = [dict(UNRELATED, slug=f"crit-{i}", title=f"crit {i}", product="next",
                     affectedVersions=["next < 99.0.0"]) for i in range(5)]
        code, out, _, fake = run(FX / "next1640", "--pwnwatch", "--json", state=self.state,
                                 feeds={"node": [], "npm": incs}, detail_fail=True)
        detail_calls = [u for u, _ in fake.calls if "/i/" in u]
        self.assertEqual(len(detail_calls), 2)
        data = json.loads(out)
        self.assertTrue(any("skipped 3 vendor-source fetch" in w for w in data["pwnwatch_warnings"]))
        self.assertTrue(all(r.get("sources_unavailable") for r in data["pwnwatch"]))

    def test_corrupt_state_is_ignored(self):
        self.state.write_text("{not json")
        code, out, _, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        self.assertEqual(by_slug(json.loads(out), NEXT["slug"])["verdict"], "affected")
        self.assertEqual(json.loads(self.state.read_text())["version"], 1)

    def test_tampered_cache_is_resanitised_and_refiltered(self):
        run(FX / "next1640", "--pwnwatch", "--json", state=self.state)
        st = json.loads(self.state.read_text())
        st["tags"]["npm"]["incidents"].append(dict(HOSTILE, slug="tampered", status="closed"))
        st["tags"]["npm"]["incidents"][0]["title"] = "\x1b[31mX‮"
        self.state.write_text(json.dumps(st))
        code, out, err, _ = run(FX / "next1640", "--pwnwatch", state=self.state)
        self.assertNotIn("tampered", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    # --- offline (plan acceptance) ------------------------------------------------------
    def test_offline_is_unchecked_not_clean_and_exit_unchanged(self):
        for fx in ("next1641", "php2", "next1640", "php"):
            base = run(FX / fx)[0]
            code, out, err, fake = run(FX / fx, "--pwnwatch", offline=True, state=self.state)
            self.assertEqual(code, base, fx)
            self.assertNotEqual(code, 2)
            self.assertIn("[UNCHECKED] pwn.watch tag", out)
            self.assertIn("not clear", out)
            self.assertNotIn("Nothing above threshold", out)
            self.assertLessEqual(len([c for c in fake.calls if "/t/" in c[0]]), 2)
        code, out, err, _ = run(FX / "next1641", "--pwnwatch", "--json", offline=True, state=self.state)
        self.assertTrue(json.loads(out)["pwnwatch_unchecked"])
        self.assertIn("warning:", err)

    def test_offline_with_cache_still_matches_and_says_unchecked(self):
        run(FX / "next1641", "--pwnwatch", state=self.state)
        code, out, err, _ = run(FX / "next1640", "--pwnwatch", "--json", offline=True, state=self.state)
        data = json.loads(out)
        self.assertEqual(by_slug(data, NEXT["slug"])["verdict"], "affected")
        self.assertTrue(any("cached" in u for u in data["pwnwatch_unchecked"]))

    def test_osv_failure_unchanged_exit_2(self):
        code, out, err, _ = run(FX / "next1640", "--pwnwatch", osv_fail=True, state=self.state)
        self.assertEqual(code, 2)
        self.assertIn("UNCHECKED, not clear", err)

    def test_missing_watcher_is_clear_error(self):
        d = self.tmp / "solo"
        d.mkdir()
        shutil.copy(SCRIPT, d / "monitor-deps.py")
        env = dict(os.environ, XDG_CACHE_HOME=str(self.tmp / "xdg"))
        p = subprocess.run([sys.executable, "-I", str(d / "monitor-deps.py"), "--path", str(FX / "empty"), "--pwnwatch"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("--pwnwatch unavailable", p.stderr)
        self.assertIn("watch-advisories.py", p.stderr)

    def test_help_names_the_default_state_path(self):
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--help"], capture_output=True, text=True)
        flat = " ".join(p.stdout.split())
        self.assertIn("$XDG_CACHE_HOME/secaudit/pwnwatch-state.json, else ~/.cache/secaudit/pwnwatch-state.json", flat)

    # --- matcher edges on the hostile fixture ---------------------------------------------
    def test_package_matcher_edges(self):
        code, out, err, _ = run(FX / "hostile", "--pwnwatch", "--json", state=self.state)
        data = json.loads(out)
        t = by_slug(data, TENSOR["slug"])
        self.assertEqual(t["verdict"], "affected")
        self.assertTrue(t["urgent"])
        x = by_slug(data, X402["slug"])
        # Both X402 lines end in descriptive parentheticals that are not allow-listed: check.
        self.assertEqual({m["name"]: m["verdict"] for m in x["matches"]},
                         {"@x402/fetch": "check", "@x402/svm": "check"})
        k = by_slug(data, KEYV["slug"])
        self.assertEqual(k["verdict"], "check")
        self.assertFalse(k["unmatched"])

    def test_unmatched_high_listed_check_manually_medium_not(self):
        code, out, _, _ = run(FX / "next1640", "--pwnwatch", "--json", state=self.state,
                              feeds={"node": [], "npm": [UNRELATED, UNRELATED_HIGH, UNRELATED_MEDIUM]})
        data = json.loads(out)
        self.assertTrue(by_slug(data, "some-other-high")["unmatched"])
        self.assertIsNone(by_slug(data, "some-other-medium"))
        code, text, _, _ = run(FX / "next1640", "--pwnwatch", state=self.state,
                               feeds={"node": [], "npm": [UNRELATED_HIGH, dict(UNRELATED, patchStatus="patched")]})
        self.assertIn("Live critical/high incidents", text)
        self.assertLess(text.index("Unrelated critical"), text.index("Unrelated high"))

    # --- hostile text (feed and repo) -------------------------------------------------------
    def _assert_clean(self, blob):
        for bad in ("\x1b", "‮", "​", "\U000E0041", "`", "\x07", "\r"):
            self.assertNotIn(bad, blob, repr(bad))
        self.assertTrue(all(c == "\n" or 32 <= ord(c) < 127 or c == "—" for c in blob),
                        {c for c in blob if not (c == "\n" or 32 <= ord(c) < 127)})

    def test_hostile_feed_fields_never_reach_output(self):
        code, text, err, _ = run(FX / "hostile", "--pwnwatch", state=self.state)
        code_j, js, err_j, _ = run(FX / "hostile", "--pwnwatch", "--json", state=self.state)
        for blob in (text, js, err, err_j):
            self._assert_clean(blob)
            for bad in ("javascript:", "user:pw@", "http://nvd", "evil.test/`"):
                self.assertNotIn(bad, blob)
        self.assertNotIn("\n[UNCHECKED] fake line", text)
        self.assertNotIn("\n  [UNCHECKED] fake", text)
        r = by_slug(json.loads(js), "hostile-incident")
        self.assertFalse(r["clean"])
        self.assertEqual(r["verdict"], "affected")
        srcs = {s["url"]: s["trusted"] for s in r["sources"]}
        self.assertEqual(srcs, {"https://github.com/advisories/GHSA-aaaa-bbbb-cccc": True, "https://evil.test/ok": False})

    def test_hostile_repo_strings_are_sanitised(self):
        # Finding 8: repo-controlled strings (require.php, engines.node, FROM ref) are printed.
        d = make_repo(self.tmp / "inj", {
            "composer.json": json.dumps({"require": {"php": ">=8.1\n  Nothing above threshold."}}),
            "package.json": json.dumps({"engines": {"node": "18\n\n  [PWN URGENT] FAKE LINE\u001b[31m"}}),
            "Dockerfile": "FROM php:8.3.35-cli\nFROM node:22.23.4 AS x\x1b[2J\n"})
        feeds = {"php": [PHP2SHELL], "node": [NODE], "npm": [], "docker": []}
        code, text, err, _ = run(d, "--pwnwatch", state=self.state, feeds=feeds)
        code_j, js, err_j, _ = run(d, "--pwnwatch", "--json", state=self.state, feeds=feeds)
        for blob in (text, js, err, err_j):
            self._assert_clean(blob)
        self.assertNotIn("\n  Nothing above threshold.", text)
        self.assertNotIn("\n  [PWN URGENT] FAKE", text)
        self.assertIn("require.php >=8.1? Nothing above threshold.", text)

    # --- no-flag invariance and the cache location -----------------------------------------
    def test_no_flag_json_has_no_pwnwatch_key_and_no_network(self):
        code, out, err, fake = run(FX / "next1640", "--json")
        self.assertNotIn("pwnwatch", out)
        self.assertIsNone(fake)

    def test_state_default_is_user_cache_not_repo(self):
        md = load_md()
        old = os.environ.get("XDG_CACHE_HOME")
        try:
            os.environ["XDG_CACHE_HOME"] = str(self.tmp / "xdg")
            self.assertEqual(md._pw_default_state(), self.tmp / "xdg" / "secaudit" / "pwnwatch-state.json")
            os.environ["XDG_CACHE_HOME"] = "relative/path"
            self.assertEqual(md._pw_default_state(), Path.home() / ".cache" / "secaudit" / "pwnwatch-state.json")
            d = self.tmp / "repo"
            shutil.copytree(FX / "next1640", d)
            os.environ["XDG_CACHE_HOME"] = str(self.tmp / "xdg")
            run(d, "--pwnwatch")
        finally:
            os.environ["XDG_CACHE_HOME"] = old
        self.assertEqual(sorted(p.name for p in d.rglob("*")), ["package-lock.json", "package.json"])
        self.assertTrue((self.tmp / "xdg" / "secaudit" / "pwnwatch-state.json").is_file())

    def test_tag_mapping(self):
        md = load_md()
        tags, rts = md.pwn_detect(FX / "mixed", [])
        self.assertEqual(tags, ["docker", "github-actions", "node", "pypi", "python"])
        self.assertEqual({(r["runtime"], r["version"], r["exact"]) for r in rts},
                         {("node", "20.11.1", True), ("node", "20", False), ("python", "3.12.4", True)})
        tags, _ = md.pwn_detect(FX / "php", [])
        self.assertEqual(tags, ["docker", "php"])
        d = self.tmp / "m2"
        (d / "node_modules" / "x").mkdir(parents=True)
        (d / "node_modules" / "x" / "composer.json").write_text('{"require":{"php":"^5.6"}}')
        for f in ("Gemfile.lock", "go.sum", "yarn.lock"):
            (d / f).write_text("")
        tags, rts = md.pwn_detect(d, [])
        self.assertEqual(tags, ["go", "node", "npm", "ruby"])
        self.assertEqual(rts, [])


# --- Fix round 2: every route to "not-affected" goes through _pw_conclude ----------------
def _inc(product, affected, fixed=(), title=None):
    return {"slug": "guard-case", "title": title or product, "product": product, "status": "live",
            "category": "patch", "severity": "critical", "patchStatus": "patched",
            "affectedVersions": list(affected), "fixedVersions": list(fixed)}


def _rt(rt, version, exact=True, detail="FROM x"):
    return {"runtime": rt, "version": version, "exact": exact, "constraint": False, "source": "Dockerfile",
            "detail": detail}


def guard_pkg(product, affected, deps, fixed=(), title=None):
    md, wa = md_wa()
    item = wa.sanitise(_inc(product, affected, fixed, title), None)
    idx = {}
    for eco, name, ver in deps:
        idx.setdefault((eco, md._pw_norm(eco, name)), (name, set()))[1].add(ver)
    return {(m["name"], m["version"]): m["verdict"] for m in md._pw_match_packages(item, idx)}


def guard_rt(product, affected, fixed, rts):
    md, wa = md_wa()
    item = wa.sanitise(_inc(product, affected, fixed), None)
    return {(m["runtime"], m["declared"]): m["verdict"] for m in md._pw_match_runtimes(item, rts)}


N14 = [("npm", "next", "14.2.10")]
# (product, affected, deps, expected); title defaults to the product
GUARD_PKG_CASES = [
    # H1: Unicode hyphens/minus fold to '-' before the sanitiser runs, so these are real ranges
    ("lodash", ["4.0.0‑4.17.20"], [("npm", "lodash", "4.17.0")], {("lodash", "4.17.0"): "affected"}),
    ("lodash", ["4.0.0−4.17.20"], [("npm", "lodash", "4.17.0")], {("lodash", "4.17.0"): "affected"}),
    ("lodash", ["4.0.0‐4.17.20"], [("npm", "lodash", "4.17.0")], {("lodash", "4.17.0"): "affected"}),
    ("lodash", ["lodash 4.0.0‒4.17.20"], [("npm", "lodash", "4.17.0")], {("lodash", "4.17.0"): "affected"}),
    ("lodash", ["4.0.0―4.17.20"], [("npm", "lodash", "4.17.21")], {("lodash", "4.17.21"): "not-affected"}),
    # H1: altered or truncated text is never cleared
    ("lodash", ["< 4.17.21​"], [("npm", "lodash", "4.17.21")], {("lodash", "4.17.21"): "check"}),
    ("lodash", [f"{i}.x before {i}.0.9" for i in range(1, 14)], [("npm", "lodash", "13.0.1")],
     {("lodash", "13.0.1"): "check"}),
    ("lodash", ["lodash " + ", ".join(f"{i}.0.0 - {i}.0.5" for i in range(1, 30))], [("npm", "lodash", "28.0.1")],
     {("lodash", "28.0.1"): "check"}),
    # H2: a separate line with versions that names nothing we recognise blocks the verdict
    ("Next.js", ["13.x before 13.5.7", "Affected: 14.0.0 to 14.2.24"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "Canary <= 14.3.0"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "Self-hosted: 14.x before 14.2.25"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "Only 14.0.0 to 14.2.24"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "Anything below 14.2.25"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "App Router 14.0.0 - 14.2.24"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "Vulnerable versions: < 14.2.25"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["13.x before 13.5.7", "Additionally 14.0.0 to 14.2.24"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["next 13.x before 13.5.7", "Middleware 14.0.0 to 14.2.24"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["next 13.x before 13.5.7", "Standalone output 14.x before 14.2.25"], N14, {("next", "14.2.10"): "check"}),
    # prose before the first package name may qualify or negate it: not read
    ("Next.js", ["13.x before 13.5.7", "Pages Router: next < 14.2.25"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["Not affected: next >= 14.2.25"], N14, {("next", "14.2.10"): "check"}),
    ("Next.js", ["Unaffected: next 14.2.25 and later"], [("npm", "next", "14.2.10")], {("next", "14.2.10"): "check"}),
    ("Next.js", ["Affected: next < 14.2.25"], [("npm", "next", "14.2.25")], {("next", "14.2.25"): "not-affected"}),
    ("Next.js", ["next < 14.2.25", "nextjs-canary 14.0.0 to 14.3.0"], [("npm", "next", "14.2.25")],
     {("next", "14.2.25"): "check"}),
    ("lodash", ["lodash < 4.17.21", "All versions with the legacy plugin enabled"], [("npm", "lodash", "4.17.21")],
     {("lodash", "4.17.21"): "check"}),
    # LOW(i): only allow-listed parentheticals are dropped
    ("Next.js", ["< 15.2.3 (including canary releases)"], [("npm", "next", "15.3.0-canary.5")],
     {("next", "15.3.0-canary.5"): "check"}),
    ("lodash", ["< 4.17.21 (and the legacy branch)"], [("npm", "lodash", "5.0.0")], {("lodash", "5.0.0"): "check"}),
    ("lodash", ["< 4.17.21 (Windows only)"], [("npm", "lodash", "4.17.21")], {("lodash", "4.17.21"): "check"}),
    ("lodash", ["< 4.17.21 (all platforms)"], [("npm", "lodash", "4.17.21")], {("lodash", "4.17.21"): "check"}),
    ("lodash", ["< 4.17.21 (npm)"], [("npm", "lodash", "4.17.21")], {("lodash", "4.17.21"): "not-affected"}),
    ("lodash", ["< 4.17.21 (CVE-2026-12345)"], [("npm", "lodash", "4.17.21")], {("lodash", "4.17.21"): "not-affected"}),
    ("lodash", ["< 4.17.21 (Prototype pollution, CVE-2026-12345)"], [("npm", "lodash", "4.17.21")],
     {("lodash", "4.17.21"): "not-affected"}),
    ("lodash", ["< 4.17.21 (all branches, CVE-2026-12345)"], [("npm", "lodash", "4.17.21")],
     {("lodash", "4.17.21"): "check"}),
    # M1: pre-releases order numerically; a pre-release of a boundary version is check
    ("tensorflow", ["tensorflow before 2.16.0rc10"], [("PyPI", "tensorflow", "2.16.0rc9")],
     {("tensorflow", "2.16.0rc9"): "affected"}),
    ("foo", ["foo through 3.0.0-rc.1"], [("PyPI", "foo", "3.0.0rc1")], {("foo", "3.0.0rc1"): "affected"}),
    ("foo", ["foo 3.0.x"], [("PyPI", "foo", "3.0.0rc1")], {("foo", "3.0.0rc1"): "check"}),
    ("foo", ["foo < 1.0.0a1"], [("PyPI", "foo", "1.0.0a1.dev1")], {("foo", "1.0.0a1.dev1"): "affected"}),
    ("foo", ["foo <= 1.0.0"], [("PyPI", "foo", "1.0.0.post1")], {("foo", "1.0.0.post1"): "check"}),
    ("foo", ["foo < 3.0.0-alpha10"], [("npm", "foo", "3.0.0-alpha9")], {("foo", "3.0.0-alpha9"): "affected"}),
    ("foo", ["foo < 15.0.0-canary.6"], [("npm", "foo", "15.0.0-canary.7")], {("foo", "15.0.0-canary.7"): "check"}),
    ("foo", ["foo < 2.0.0-rc.1"], [("npm", "foo", "2.0.0")], {("foo", "2.0.0"): "not-affected"}),
    # STAY cleared: every guard holds
    ("Express", ["before 4.19.2"], [("npm", "express", "4.19.2")], {("express", "4.19.2"): "not-affected"}),
    ("Express", ["before 4.19.2"], [("npm", "express", "4.19.1")], {("express", "4.19.1"): "affected"}),
    ("Next.js, sharp", ["next < 15.2.3", "sharp < 0.35.5"], [("npm", "next", "15.2.3")],
     {("next", "15.2.3"): "not-affected"}),
    ("Next.js", ["next < 15.2.3", "@next/swc < 15.2.3", "Node.js 18 before 18.20.5", "sharp@<0.35.5"],
     [("npm", "next", "15.2.3")], {("next", "15.2.3"): "not-affected"}),
    ("Laravel", ["laravel/framework < 12.68.0", "next < 15.2.3"], [("npm", "next", "15.2.3")],
     {("next", "15.2.3"): "not-affected"}),
]

PHP = ("php", "8.3.36")
GUARD_RT_CASES = [
    # H2: lines naming nothing we recognise in a runtime's own incident
    ("PHP", ["8.1 before 8.1.33", "Windows builds: 8.4 before 8.4.10"], ["8.1.33"], [_rt("php", "8.4.5")],
     {("php", "8.4.5"): "check"}),
    ("Node.js", ["22.x before 22.12.0", "Current release line 23"], ["22.12.0"], [_rt("node", "23.1.0")],
     {("node", "23.1.0"): "check"}),
    ("Node.js", ["22.x before 22.12.0", "Odd-numbered lines are not patched"], ["22.12.0"], [_rt("node", "23.1.0")],
     {("node", "23.1.0"): "check"}),
    ("Node.js", ["Next.js < 15.2.3 when running on Node.js 18"], ["15.2.3, Node.js 18.20.5"],
     [_rt("node", "18.20.5")], {("node", "18.20.5"): "check"}),
    ("PHP, php-fpm", ["PHP 8.3 before 8.3.36", "php-fpm 8.4 before 8.4.10"], ["8.3.36"], [_rt("php", "8.4.5")],
     {("php", "8.4.5"): "check"}),
    ("PHP, Symfony", ["PHP 8.3 before 8.3.36", "Symfony 7.1 before 7.1.5"], ["8.3.36"], [_rt("php", "8.4.5")],
     {("php", "8.4.5"): "not-affected"}),
    # H3: the fixed-line shortcut needs guard (d)
    ("PHP", ["PHP 8.3.0 through 8.3.36"], ["8.3.36"], [_rt(*PHP)], {PHP: "check"}),
    ("PHP", ["PHP 8.3 before 8.3.36; all 8.3 builds with opcache.jit enabled"], ["8.3.36"], [_rt(*PHP)],
     {PHP: "check"}),
    ("PHP", ["PHP 5.4 through 8.3.35"], ["8.3.36 (PHP)", "7.1.5 (Symfony)"], [_rt("php", "7.1.33")],
     {("php", "7.1.33"): "affected"}),
    ("PHP", ["PHP 5.4 through 8.3.35"], ["8.3.36 (PHP)", "7.1.5 (Symfony)"], [_rt(*PHP)], {PHP: "check"}),
    ("PHP", ["PHP < 8.3.36"], ["8.3.36 (Windows only)"], [_rt(*PHP)], {PHP: "check"}),
    ("PHP", ["PHP < 8.3.36", "8.3.36 on Linux with FPM"], ["8.3.36 (Windows)"], [_rt(*PHP)], {PHP: "check"}),
    ("PHP", ["all versions"], ["8.3.36 (incomplete; 8.3.37 completes the fix)"], [_rt(*PHP)], {PHP: "check"}),
    # H4: fixedVersions are read with the strict grammar (contradictory fixed lists)
    ("PHP", ["8.2 before 8.2.29, 8.3 before 8.3.36"], ["8.3.36", "8.2.29 is not fixed; see 8.2.30"],
     [_rt("php", "8.2.29")], {("php", "8.2.29"): "check"}),
    ("PHP", ["8.2 before 8.2.29, 8.3 before 8.3.36"], ["8.3.36", "8.2.29 is not fixed"],
     [_rt("php", "8.2.29")], {("php", "8.2.29"): "check"}),
    ("PHP", ["PHP 8.3.0 through 8.3.35"], ["8.3.36", "8.3.37"], [_rt(*PHP)], {PHP: "affected"}),
    # H1 at runtime level: altered fixed text
    ("PHP", ["PHP 8.3.0 through 8.3.35"], ["8.3.36​"], [_rt(*PHP)], {PHP: "check"}),
    # M1: rc9 < rc10 on a fixed line
    ("Python", ["CPython before 3.12.5"], ["3.12.5, 3.13.0rc10"], [_rt("python", "3.13.0rc9")],
     {("python", "3.13.0rc9"): "affected"}),
    ("Python", ["CPython 3.12 before 3.12.5", "3.13.0rc1 and earlier pre-releases"], ["3.12.5", "3.13.0rc2"],
     [_rt("python", "3.13.0b1")], {("python", "3.13.0b1"): "affected"}),
    ("PHP", ["PHP 8.4.0RC1 through 8.4.0RC3"], ["8.4.0"], [_rt("php", "8.4.0RC2")], {("php", "8.4.0RC2"): "affected"}),
    # M2: comma-joined multi-runtime clauses are split and attributed
    ("Node.js and Bun", ["Node.js 22 before 22.12.0, Bun before 1.1.38"], ["22.12.0, 1.1.38"],
     [_rt("bun", "1.1.30"), _rt("node", "22.12.0")], {("bun", "1.1.30"): "affected", ("node", "22.12.0"): "check"}),
    ("Node.js", ["Node.js 22 before 22.12.0, Bun before 1.1.38"], ["Node.js 22.12.0; Bun 1.1.38"],
     [_rt("bun", "1.1.30"), _rt("node", "22.12.0")],
     {("bun", "1.1.30"): "affected", ("node", "22.12.0"): "not-affected"}),
    ("Node.js", ["22 before 22.12.0", "Deno and Bun: all versions before 2.1"], ["22.12.0"],
     [_rt("bun", "1.1.30"), _rt("node", "22.12.0")],
     {("bun", "1.1.30"): "affected", ("node", "22.12.0"): "not-affected"}),
    ("Node.js, Bun", ["22 before 22.12.0", "Bun before 1.1.38"], ["22.12.0"],
     [_rt("bun", "1.1.30"), _rt("node", "22.12.0")], {("bun", "1.1.30"): "affected", ("node", "22.12.0"): "check"}),
    # STAY cleared
    ("PHP", ["PHP 8.3.0 through 8.3.35"], ["8.3.36"], [_rt(*PHP)], {PHP: "not-affected"}),
    ("PHP", ["PHP 8.3 before 8.3.36"], ["fixed in 8.3.36"], [_rt(*PHP)], {PHP: "not-affected"}),
    ("Node.js", ["Node.js 22 before 22.12.0"], ["22.12.0"], [_rt("node", "22.12.0")], {("node", "22.12.0"): "not-affected"}),
    ("Node.js", ["22.x before 22.12.0, 24.x before 24.1.1"], ["22.12.0", "24.1.1"], [_rt("node", "23.1.0")],
     {("node", "23.1.0"): "not-affected"}),
    ("Next.js", ["Next.js < 15.2.3"], ["15.2.3"], [_rt("node", "22.1.0")], {}),
]


class Guards(unittest.TestCase):
    def test_package_guards(self):
        for product, affected, deps, want in GUARD_PKG_CASES:
            with self.subTest(product=product, affected=affected, deps=deps):
                self.assertEqual(guard_pkg(product, affected, deps), want)

    def test_runtime_guards(self):
        for product, affected, fixed, rts, want in GUARD_RT_CASES:
            with self.subTest(product=product, affected=affected, fixed=fixed):
                self.assertEqual(guard_rt(product, affected, fixed, rts), want)

    def test_unclean_title_alone_blocks_clearing(self):
        self.assertEqual(guard_pkg("lodash", ["< 4.17.21"], [("npm", "lodash", "4.17.21")], title="x \U0001f525"),
                         {("lodash", "4.17.21"): "check"})

    def test_choke_point(self):
        md, _ = md_wa()
        base = {"kind": "package", "name": "a", "version": "1.0.0", "reason": "r"}
        clean, dirty = {"clean": True}, {"clean": False, "altered": ["affected"]}
        self.assertEqual(md._pw_conclude(clean, [md._pw_candidate(base, [])])[0]["verdict"], "not-affected")
        self.assertNotIn("_blockers", md._pw_conclude(clean, [md._pw_candidate(base, [])])[0])
        self.assertEqual(md._pw_conclude(clean, [md._pw_candidate(base, ["doubt"])])[0]["verdict"], "check")
        (m,) = md._pw_conclude(dirty, [md._pw_candidate(base, [])])
        self.assertEqual(m["verdict"], "check")
        self.assertIn("(affected) was altered or truncated", m["reason"])
        # a "not-affected" that skipped _pw_candidate is never trusted
        self.assertEqual(md._pw_conclude(clean, [dict(base, verdict="not-affected")])[0]["verdict"], "check")
        self.assertEqual(md._pw_conclude(dirty, [dict(base, verdict="affected")])[0]["verdict"], "affected")

    def test_only_conclude_writes_not_affected(self):
        src = SCRIPT.read_text()
        self.assertEqual(src.count('"verdict": "not-affected"'), 1)   # inside _pw_candidate
        self.assertNotIn("'not-affected'", src.split("def run_pwnwatch")[0].split("def _pw_candidate")[1])

    def test_watcher_flags_altered_fields(self):
        _, wa = md_wa()
        item = wa.sanitise(_inc("lodash", [f"{i}.0.0" for i in range(20)], ["1.0.0"]), None)
        self.assertFalse(item["clean"])
        self.assertEqual(item["altered"], ["affected"])
        item = wa.sanitise(_inc("lodash", ["4.0.0‑4.17.20"]), None)
        self.assertTrue(item["clean"])
        self.assertEqual(item["affected"], ["4.0.0-4.17.20"])
        self.assertEqual(item["altered"], [])

    def test_version_order_numeric_prerelease(self):
        md, _ = md_wa()
        k = lambda v: md._vkey(*md._vparse(v)[:2])
        order = ["1.0.0.dev1", "1.0.0a1.dev1", "1.0.0a1", "1.0.0a1.post1", "1.0.0b2", "1.0.0rc9", "1.0.0rc10",
                 "1.0.0", "1.0.0.post1.dev1", "1.0.0.post1", "1.0.0.post10", "1.0.1"]
        self.assertEqual(sorted(reversed(order), key=k), order)
        self.assertEqual(k("3.0.0-rc.1"), k("3.0.0rc1"))
        self.assertEqual(k("3.0.0RC1"), k("3.0.0rc1"))
        self.assertEqual(k("6.14.12a0"), k("6.14.12-alpha.0"))

    def test_hostile_lockfile_version_and_name(self):
        md, wa = md_wa()
        item = wa.sanitise(_inc("lodash", ["lodash < 4.17.21"]), None)
        bad = "4.0.0\x1b[2J\n\n  [PWN URGENT] FAKE `x`"
        (m,) = md._pw_match_packages(item, {("npm", "lodash"): ("lodash", {bad})})
        self.assertEqual(m["verdict"], "check")
        for blob in (m["reason"], m["version"]):
            self.assertTrue(all(32 <= ord(c) < 127 for c in blob), repr(blob))
            self.assertNotIn("`", blob)
            self.assertNotIn("\n", blob)

    def test_unreachable_reason_is_sanitised(self):
        md, wa = md_wa()

        class Fake:
            BASE, CATEGORIES, SLUG_RE, Unreachable = wa.BASE, wa.CATEGORIES, wa.SLUG_RE, wa.Unreachable

            @staticmethod
            def _get(url, etag=None):
                raise wa.Unreachable(f"{url}: HTTP Error 503: \x1b[2J\n[UNCHECKED] fake `x`")
        warnings = []
        _, unchecked = md.pwn_fetch(Fake, ["npm"], {}, warnings)
        self.assertTrue(all(32 <= ord(c) < 127 for c in unchecked["npm"]), repr(unchecked["npm"]))
        self.assertNotIn("`", unchecked["npm"])
        self.assertEqual(wa._err_text(Exception("HTTP Error 503: ok\x1b\nX `y`")), "HTTP Error 503: ok??X 'y'")

    def test_strict_fixed_reader(self):
        md, _ = md_wa()
        for text, want in (("8.3.36", [((8, 3, 36), "")]), ("fixed in 22.12.0, 20.18.1", [((22, 12, 0), ""), ((20, 18, 1), "")]),
                           ("2.23.0+", [((2, 23, 0), "")]), ("8.3.36 or later", [((8, 3, 36), "")]),
                           ("8.2.29 is not fixed", None), ("see 8.2.30", None), ("8.3.36 (Windows only)", None),
                           ("8.3", None), ("8.x", None), ("not fixed in 8.3.36", None), ("", None)):
            with self.subTest(text=text):
                self.assertEqual(md._pw_fixed_versions(text), want)


# --- Seeded differential test: range phrases vs installed versions (from the reviewer's fuzzer) ---
_ORD = {"dev": 0, "alpha": 1, "beta": 2, "rc": 3, "": 4, "post": 5}


def _okey(v):
    return (v[0], _ORD[v[1]], v[2])


def _fmt(v, style):
    n = ".".join(map(str, v[0]))
    kind, num = v[1], v[2]
    if not kind:
        return n
    if style == "npm":
        return f"{n}-{kind}.{num}" if kind not in ("post", "dev") else f"{n}.{kind}{num}"
    return n + {"alpha": "a", "beta": "b", "rc": "rc", "post": ".post", "dev": ".dev"}[kind] + str(num)


class Differential(unittest.TestCase):
    """No phrase may yield "not-affected" for a version it covers; a condition must yield check.

    Two readings are deliberate and excluded: '>= X, < Y' / '>= X and < Y' is one bounded range
    (so '>= V' is only generated last), and a trailing 'only' narrows nothing.
    """
    def test_no_false_clean(self):
        import random
        md, wa = md_wa()
        rnd = random.Random(20261023)

        def rv(pre_p=0.15):
            nums = (rnd.randint(0, 15), rnd.randint(0, 15), rnd.randint(0, 30))
            if rnd.random() < pre_p:
                return (nums, rnd.choice(["alpha", "beta", "rc", "post", "dev"]), rnd.randint(0, 5))
            return (nums, "", 0)

        def clause(last):
            v, w = sorted((rv(), rv()), key=_okey)
            s = rnd.choice(["npm", "pep"])
            V, W = _fmt(v, s), _fmt(w, s)
            le = lambda a, incl: (lambda x: _okey(x) < _okey(a) or (incl and _okey(x) == _okey(a)))
            ge = lambda a: (lambda x: _okey(x) >= _okey(a))
            span = lambda x: _okey(v) <= _okey(x) <= _okey(w)
            a, b = v[0][0], v[0][1]
            w2 = ((a, w[0][1], w[0][2]), w[1], w[2])
            forms = [(f"< {V}", le(v, False)), (f"<={V}", le(v, True)), (f"before {V}", le(v, False)),
                     (f"prior to {V}", le(v, False)), (f"through {V}", le(v, True)), (f"up to {V}", le(v, True)),
                     (f"{V} and earlier", le(v, True)), (f"{V} to {W}", span), (f"{V} - {W}", span),
                     (f"{a}.{b}.x", lambda x: x[0][:2] == (a, b)), (f"versions {V} and {W}",
                      lambda x: _okey(x) in (_okey(v), _okey(w))), (f">= {V}, < {W}",
                      lambda x: _okey(v) <= _okey(x) < _okey(w)), (f"from {V} to {W}", span),
                     (f"between {V} and {W}", span), (f"{V}+", ge(v)), (f"{V} or later", ge(v)),
                     (f"{a}.x before {_fmt(w2, s)}", lambda x: x[0][0] == a and _okey(x) < _okey(w2)),
                     (V, lambda x: _okey(x) == _okey(v)), (f"{V} through {W}", span),
                     (f"all versions before {V}", le(v, False)), (f"{a}.{b}", lambda x: x[0][:2] == (a, b)),
                     (f"<= {V} inclusive", le(v, True))]
            if last:
                forms.append((f">= {V}", ge(v)))
            return rnd.choice(forms)

        seps = ["; ", ", ", " and ", ", or ", " or ", "; and ", ", and "]
        trail = [" when using Node 18", " on Windows only", " except 1.2.3", " excluding 2.0.0", " with SSR enabled",
                 " (only when using the App Router)", " (Windows only)", " (when debug is enabled)",
                 " if experimental flag set", " for self-hosted deployments", " (all platforms)", " (except 3.1.4)",
                 " (including canary releases)", " (and the legacy branch)"]
        false_clean = []
        for _ in range(450):
            n = rnd.choice([1, 1, 2, 2, 3])
            cs = [clause(i == n - 1) for i in range(n)]
            txt = cs[0][0] + "".join(rnd.choice(seps) + c[0] for c in cs[1:])
            cond = rnd.random() < 0.3
            if cond:
                txt += rnd.choice(trail)
            item = wa.sanitise(_inc("libfoo", [txt]), None)
            cands = [rv(0.3)]
            for c in cs:
                for mm in re.finditer(r"\d+\.\d+(?:\.\d+)?", c[0]):
                    p = (tuple(int(z) for z in mm.group(0).split(".")) + (0,))[:3]
                    cands += [(p, "", 0), (p[:2] + (p[2] + 1,), "", 0), (p[:2] + (max(p[2] - 1, 0),), "", 0),
                              (p, "rc", 1), (p, "post", 1), (p, "alpha", 0), ((p[0], p[1] + 1, 0), "", 0)]
            vers = {_fmt(inst, rnd.choice(["npm", "pep"])): inst for inst in rnd.sample(cands, min(5, len(cands)))}
            idx = {("npm", "libfoo"): ("libfoo", set(vers))}
            for m in md._pw_match_packages(item, idx):
                inst = vers[m["version"]]
                if (cond and m["verdict"] != "check") or (any(c[1](inst) for c in cs) and m["verdict"] == "not-affected"):
                    false_clean.append((txt, m["version"], m["verdict"]))
        self.assertEqual(false_clean[:5], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
