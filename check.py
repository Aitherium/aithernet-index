#!/usr/bin/env python3
"""Validate the git-tracked AitherNet Index (records/).

Exit 0 clean, 1 violation, 2 could not judge (no records found / unreadable root).
Rules NI000-NI008 live in ``netindex.py::validate``.

    python check.py
    python check.py --resolve docs.aither
    python check.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import netindex  # noqa: E402


def _run(root: Path) -> int:
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
    names = sum(len(r.names) for r in records)
    print(f"netindex: {len(records)} records, {names} names, {len(findings)} findings")
    return 1 if findings else 0


def _self_test() -> int:
    good = {"id": "a", "kind": "site", "title": "A", "url": "https://a.example",
            "names": ["a.aither"], "route": {"type": "web", "target": "https://a.example"},
            "provenance": {"added_by": "t", "sources": ["x"],
                           "validated": {"at": "2026-01-01", "by": "t", "method": "m"}}}
    cases = {
        "clean": ([good], set()),
        "name collision": ([good, {**good, "id": "b"}], {"NI003"}),
        "bad suffix": ([{**good, "names": ["a.com"]}], {"NI005"}),
        "http route": ([{**good, "route": {"type": "web", "target": "http://a"}}], {"NI007"}),
        "dangling edge": ([{**good, "edges": [{"rel": "links_to", "to": "nope"}]}], {"NI004"}),
        "no provenance": ([{**good, "provenance": {}}], {"NI008"}),
        "self vouch": ([{**good, "provenance": {**good["provenance"],
                        "vouches": [{"by": "t", "at": "2026-01-02"}]}}], {"NI009"}),
        "future validation": ([{**good, "provenance": {**good["provenance"], "validated":
                               {"at": "2999-01-01", "by": "t", "method": "m"}}}], {"NI008"}),
    }
    ok = True
    for label, (raws, want) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            for r in raws:
                Path(d, f"{r['id']}.json").write_text(json.dumps(r), encoding="utf-8")
            recs, f0 = netindex.load(Path(d))
            got = {f.code for f in f0 + netindex.validate(recs, today=dt.date(2026, 11, 8))}
        passed = got == want
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'} {label}: want {sorted(want)} got {sorted(got)}")
    v2 = {**good, "provenance": {**good["provenance"], "validated":
          {"at": "2026-01-01", "by": "t", "method": "http-200"},
          "vouches": [{"by": "u", "at": "x"}, {"by": "w", "at": "x"}]}}
    tiers = [netindex.trust(netindex._parse(None, x)) for x in (good, v2)]
    t_ok = tiers == [0, 3]
    ok &= t_ok
    print(f"{'PASS' if t_ok else 'FAIL'} trust tiers: want [0, 3] got {tiers}")
    def _ev(e):
        return netindex.trust(netindex._parse(None, {**v2, "provenance": {
            **v2["provenance"], "evidence": e}}))
    caps = [_ev({"sanctions_hits": 1}), _ev({"threat_level": "high"}),
            _ev({"domain_age_days": 5}), _ev({"domain_age_days": 4000}),
            _ev({"shared_host": "github.io", "threat_level": "HIGH"})]
    e_ok = caps == [0, 0, 1, 3, 3]
    ok &= e_ok
    print(f"{'PASS' if e_ok else 'FAIL'} osint evidence caps: want [0, 0, 1, 3, 3] got {caps}")
    idx = netindex.Index([netindex._parse(None, good)])
    r_ok = idx.resolve("A.aither.") is not None and idx.resolve("zz.aither") is None
    print(f"{'PASS' if r_ok else 'FAIL'} resolve hit/NXDOMAIN")
    with tempfile.TemporaryDirectory() as d:
        empty_ok = _run(Path(d)) == 2
    print(f"{'PASS' if empty_ok else 'FAIL'} empty root exits 2")
    return 0 if ok and r_ok and empty_ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--resolve", metavar="NAME")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    if a.resolve:
        hit = netindex.Index.from_root(a.root).resolve(a.resolve)
        print(json.dumps(hit, indent=2) if hit else f"NXDOMAIN {a.resolve}")
        return 0 if hit else 1
    return _run(a.root)


if __name__ == "__main__":
    sys.exit(main())
