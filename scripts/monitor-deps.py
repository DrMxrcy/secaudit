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

Exit codes: 0 = nothing above threshold, 1 = something is, 2 = the script itself failed.
Stdlib only — nothing to install, nothing to keep patched.
"""

from __future__ import annotations

import argparse
import datetime
import json
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", default=".", help="repo root to scan")
    ap.add_argument("--min-epss", type=float, default=0.0,
                    help="only report at or above this exploitation probability")
    ap.add_argument("--fail-on", choices=["any", "kev", "epss"], default="any",
                    help="what makes the exit code non-zero (default: any finding)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

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

    if args.json:
        print(json.dumps({"findings": findings, "eol": eol, "unchecked": unchecked,
                          "dependencies_scanned": len(deps)}, indent=2))
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
        if not findings and not eol and not unchecked:
            print("  Nothing above threshold.")

    if args.fail_on == "kev":
        bad = any(h.get("kev") for h in findings)
    elif args.fail_on == "epss":
        bad = any(h.get("epss", 0.0) >= max(args.min_epss, 0.1) for h in findings)
    else:
        bad = bool(findings)
    # An unparseable lockfile is a failure too: coverage gaps must not pass silently.
    return 1 if (bad or eol or unchecked) else 0


if __name__ == "__main__":
    sys.exit(main())
