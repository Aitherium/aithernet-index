"""awindex: resolve .aither keywords and read the AitherNet Index from the shell.

    awindex resolve neocities.aither      # route + trust tier, exit 1 = not indexed
    awindex search "digital garden"       # matching entries
    awindex show neocities.org            # one record with its evidence
    awindex check                         # validate a checkout (exit 0 / 1 / 2)
    awindex --self-test

Reads a local checkout when one exists (records/ beside the package, or
AWINDEX_ROOT, or --root). Otherwise it reads the published index at
https://index.aitherium.com, so a plain `pip install` works with no clone.
Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from . import __version__, netindex

BASE = "https://index.aitherium.com"
UA = f"awindex/{__version__}"


def _fetch(path: str) -> Optional[dict]:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (fixed https base)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _local(root: Optional[Path]) -> Optional[netindex.Index]:
    root = root or netindex.DEFAULT_ROOT
    if Path(root).is_dir():
        records, _ = netindex.load(Path(root))
        if records:
            return netindex.Index(records)
    return None


def _record_dict(r: netindex.Record) -> dict:
    return {"id": r.id, "kind": r.kind, "title": r.title, "url": r.url, "tags": r.tags,
            "names": r.names, "route": r.route, "edges": r.edges,
            "validated": r.provenance.get("validated", {}),
            "trust": netindex.TIERS[netindex.trust(r)]}


def cmd_resolve(name: str, idx: Optional[netindex.Index]) -> int:
    name = name.strip().lower().rstrip(".")
    if not name.endswith(netindex.NAME_SUFFIX):
        name += netindex.NAME_SUFFIX
    if idx is not None:
        hit = idx.resolve(name)
        if hit:
            hit["trust"] = netindex.TIERS[netindex.trust(idx.records[hit["id"]])]
    else:
        hit = _fetch(f"/n/{name}.json")
    if not hit:
        print(f"NXDOMAIN {name}")
        return 1
    print(json.dumps(hit, indent=2))
    return 0


def _all(idx: Optional[netindex.Index]) -> list:
    if idx is not None:
        return [_record_dict(r) for r in idx.records.values()]
    data = _fetch("/index.json") or {}
    return data.get("records", [])


def cmd_search(query: str, idx: Optional[netindex.Index], limit: int) -> int:
    toks = [t for t in query.lower().split() if t]
    scored = []
    for r in _all(idx):
        hay = " ".join([r["id"], r["title"], *r.get("tags", []), *r.get("names", [])]).lower()
        s = sum(1 for t in toks if t in hay)
        if s:
            scored.append((-s, r["id"], r))
    scored.sort(key=lambda x: (x[0], x[1]))
    for _, _, r in scored[:limit]:
        print(f"{r['trust']:<13} {r['kind']:<8} {r['title']}  {r.get('url', '')}")
    return 0 if scored else 1


def cmd_show(rid: str, idx: Optional[netindex.Index]) -> int:
    for r in _all(idx):
        if r["id"] == rid:
            print(json.dumps(r, indent=2))
            return 0
    print(f"not indexed: {rid}")
    return 1


def cmd_check(root: Optional[Path]) -> int:
    root = Path(root or netindex.DEFAULT_ROOT)
    if not root.is_dir():
        print(f"could not judge: {root} is not a directory")
        return 2
    records, findings = netindex.load(root)
    if not records:
        print(f"could not judge: no records under {root}")
        return 2
    findings += netindex.validate(records)
    for f in findings:
        print(f)
    print(f"awindex: {len(records)} records, {len(findings)} findings")
    return 1 if findings else 0


def self_test() -> int:
    good = netindex._parse(None, {
        "id": "a", "kind": "site", "title": "A", "url": "https://a.example",
        "tags": ["alpha"], "names": ["a.aither"],
        "route": {"type": "web", "target": "https://a.example"},
        "provenance": {"added_by": "t", "sources": ["x"],
                       "validated": {"at": "2026-01-01", "by": "t", "method": "http-200"}}})
    idx = netindex.Index([good])
    checks = {
        "resolve hit": idx.resolve("a.aither") is not None,
        "resolve miss": idx.resolve("zz.aither") is None,
        "trust reachable": netindex.TIERS[netindex.trust(good)] == "reachable",
        "search": [r.id for r in idx.search("alpha")] == ["a"],
    }
    for k, v in checks.items():
        print(f"{'PASS' if v else 'FAIL'} {k}")
    return 0 if all(checks.values()) else 1


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="awindex", description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, help="a records/ directory (default: local or web)")
    ap.add_argument("--web", action="store_true", help="ignore any local checkout")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--version", action="version", version=f"awindex {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("resolve").add_argument("name")
    s = sub.add_parser("search")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=20)
    sub.add_parser("show").add_argument("id")
    sub.add_parser("check")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if a.cmd == "check":
        return cmd_check(a.root)
    idx = None if a.web else _local(a.root)
    if a.cmd == "resolve":
        return cmd_resolve(a.name, idx)
    if a.cmd == "search":
        return cmd_search(a.query, idx, a.limit)
    if a.cmd == "show":
        return cmd_show(a.id, idx)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
