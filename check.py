#!/usr/bin/env python3
"""Validate the git-tracked AitherNet Index (records/).

Exit 0 clean, 1 violation, 2 could not judge (no records found / unreadable root).
Record rules NI000-NI010 live in ``netindex.py::validate``; the re-check's
``state/health.json`` (NI020/NI021) and the "approved without an artifact" rule
(NI022) live in ``recheck.py`` and are checked here so there is one validator,
never two.

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
import recheck  # noqa: E402


def _run(root: Path, state_path: "Path | None" = None) -> int:
    if not root.is_dir():
        print(f"could not judge: {root} is not a directory")
        return 2
    records, findings = netindex.load(root)
    if not records:
        print(f"could not judge: no records under {root}")
        return 2
    findings += netindex.validate(records)
    # NI022: a listing approved after the artifact rule shipped must have been stamped
    # with the backlink it carries. Offline: it reads provenance, never the network.
    findings += recheck.artifact_findings(records)
    if state_path is not None and Path(state_path).exists():
        findings += recheck.state_findings(recheck.load_state(state_path), records)
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
        "good business": ([{**good, "kind": "business", "listing": {
            "description": "Bakery", "category": "bakery", "address": "1 Main St",
            "area_served": "Springfield", "phone": "+1 (555) 010-0000", "email": "hi@a.example",
            "hours": ["Mo-Fr 07:00-15:00", "Sa,Su 08:00-12:00"],
            "same_as": ["https://social.example/a"], "geo": {"lat": 45.5, "lng": -122.6}}}],
            set()),
        "business without url": ([{**good, "kind": "business", "url": ""}], {"NI010"}),
        "bad hours": ([{**good, "listing": {"hours": ["9 to 5"]}}], {"NI010"}),
        "unknown listing field": ([{**good, "listing": {"ssn": "000"}}], {"NI010"}),
        "bad geo": ([{**good, "listing": {"geo": {"lat": 200, "lng": 0}}}], {"NI010"}),
        "http same_as": ([{**good, "listing": {"same_as": ["http://a"]}}], {"NI010"}),
        "listing not object": ([{**good, "listing": "open 9-5"}], {"NI010"}),
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
    # NI020/NI021: the re-check state is machine-written, but a bad commit is a finding.
    rec = netindex._parse(None, good)
    clean_state = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                   "entries": {"a": {"status": "warn"}}}
    bad_state = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                 "entries": {"a": {"status": "exploded"}, "ghost": {"status": "active"}}}
    # An orphan entry (record deleted by a delist PR) is pruned by the next run and is
    # not a finding; a bad status is.
    s_ok = (recheck.state_findings(clean_state, [rec]) == []
            and {f.code for f in recheck.state_findings(bad_state, [rec])} == {"NI020"}
            and len(recheck.state_findings(bad_state, [rec])) == 1)
    ok &= s_ok
    print(f"{'PASS' if s_ok else 'FAIL'} NI020 state/health.json")
    # NI022: a listing approved after 2026-11-18 must have been stamped with the
    # artifact it carries; a pre-grace record and an exempt community are not judged.
    late = {**good, "provenance": {**good["provenance"], "validated":
            {"at": "2026-11-20", "by": "t", "method": "http-200"}}}
    stamped = {**late, "provenance": {**late["provenance"],
               "fingerprint": {"artifact": "meta"}}}
    old = {**good, "provenance": {**good["provenance"], "validated":
           {"at": "2026-01-01", "by": "t", "method": "http-200"}}}
    disco = {**late, "id": "discord_1", "kind": "discord",
             "url": "https://discord.gg/abc"}
    a_codes = [[f.code for f in recheck.artifact_findings([netindex._parse(None, x)])]
               for x in (late, stamped, old, disco)]
    want = [[recheck.ARTIFACT_RULE], [], [], []]
    a_ok = a_codes == want
    ok &= a_ok
    print(f"{'PASS' if a_ok else 'FAIL'} NI022 approved record needs an artifact: "
          f"want {want} got {a_codes}")
    state_p = recheck.DEFAULT_STATE
    rel = Path("records")
    rel_ok = (rel.resolve() != netindex.DEFAULT_ROOT.resolve()
              or state_for_root(rel, state_p) == state_p)
    r_ok = (state_for_root(netindex.DEFAULT_ROOT, state_p) == state_p and rel_ok
            and state_for_root(tempfile.gettempdir(), state_p) is None)
    ok &= r_ok
    print(f"{'PASS' if r_ok else 'FAIL'} explicit --root records validates state")
    return 0 if ok and empty_ok and s_ok and a_ok and r_ok else 1


def state_for_root(root: Path, state: Path) -> "Path | None":
    """The state file to judge, or None when --root is not this repo's records.

    Compares resolved paths so the documented `check.py --root records` spelling is
    judged too (a relative Path never equals the absolute default by string).
    """
    try:
        same = Path(root).resolve() == netindex.DEFAULT_ROOT.resolve()
    except OSError:
        same = False
    return state if (state.exists() and same) else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--state", type=Path, default=recheck.DEFAULT_STATE)
    ap.add_argument("--resolve", metavar="NAME")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    if a.resolve:
        hit = netindex.Index.from_root(a.root).resolve(a.resolve)
        print(json.dumps(hit, indent=2) if hit else f"NXDOMAIN {a.resolve}")
        return 0 if hit else 1
    return _run(a.root, state_for_root(a.root, a.state))


if __name__ == "__main__":
    sys.exit(main())
