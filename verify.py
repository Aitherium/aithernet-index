#!/usr/bin/env python3
"""Live evidence for records: is the URL up, does the page carry its backlink, and
does the site's owner claim it?

    python verify.py                 # report every record, exit 1 if any URL is down
    python verify.py --ids a b       # only these
    python verify.py --ids a --stamp # write the evidence into provenance.validated

Owner proof: the site serves https://<host>/.well-known/aithernet.json containing
{"records": ["<id>", ...]}. Only someone who controls the site can put that file
there, so it separates the owner's entry from an impersonation.

Backlink artifact (see artifact.py): a listing must carry ONE of the well-known file
above, a <link rel="aithernet">, a <meta name="aithernet">, or a visible link to
https://index.aitherium.com/r/<id>. The re-check job (recheck.py) enforces it over
time; here it is reported at listing time, and --stamp records the page fingerprint
the re-check later compares against.

Stdlib only. Exit 0 every checked page carries its artifact, 1 any unreachable or
reachable-without-a-backlink page (a listing without the artifact is not approved),
2 nothing to check. Exempt communities (Discord, first-party services) are skipped.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifact  # noqa: E402
import fingerprint  # noqa: E402
import netindex  # noqa: E402

UA = artifact.UA


def _get(url: str, limit: int = 65536) -> "tuple[int, bytes]":
    """(status, body). The one fetcher lives in artifact.py so every caller agrees."""
    res = artifact.fetch(url, limit=limit)
    return res.status, res.body.encode("utf-8")


def evidence(rec: netindex.Record) -> dict:
    """Everything verify.py can see from outside, for one record.

    ``method`` keeps its old meaning (well-known = owner-proven, http-200 = reachable)
    so ``netindex.trust`` is unchanged. ``artifact`` names which backlink form the page
    carries, and ``fingerprint`` is the page as it looks today.
    """
    if not rec.url.startswith("https://"):
        return {"id": rec.id, "status": None, "method": None, "artifact": None,
                "note": "no https url"}
    page = artifact.fetch(rec.url)
    host = artifact.host_of(page.final_url or rec.url)
    out: dict = {"id": rec.id, "status": page.status, "method": None, "artifact": None,
                 "host": host}
    if not page.ok:
        out["note"] = page.error or f"http {page.status}"
        return out
    claimed: "list[str]" = []
    if host:
        code, body = _get(f"https://{host}/.well-known/aithernet.json")
        if code == 200:
            claimed = artifact.claimed_ids(body.decode("utf-8", "replace"))
    det = artifact.detect(rec.id, page.body, claimed)
    out["artifact"] = det.form
    out["artifact_reason"] = det.reason
    # A page with no backlink is NOT approved: stamping it "http-200" would turn a
    # reachable-but-unlinked site into a trusted listing with nothing to re-check.
    if det.form == "well-known":
        out["method"] = "well-known"
    elif det.ok:
        out["method"] = "http-200"
    else:
        out["method"] = None
        out["note"] = det.reason
    out["fingerprint"] = fingerprint.page(page.body, host)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--stamp", action="store_true")
    ap.add_argument("--by", default="aithernet-bot")
    a = ap.parse_args()
    records, _ = netindex.load(a.root)
    if a.ids:
        wanted = set(a.ids)
        records = [r for r in records if r.id in wanted]
    records = [r for r in records if r.url
               and not artifact.exempt_reason(r.kind, r.url)]
    if not records:
        print("nothing to check")
        return 2
    down = unproven = 0
    for rec in records:
        ev = evidence(rec)
        print(json.dumps(ev))
        if ev["method"] is None:
            if ev.get("status") == 200:
                unproven += 1          # reachable but carries no backlink artifact
            else:
                down += 1              # unreachable
            continue
        current = (rec.provenance.get("validated") or {}).get("method")
        if a.stamp and current != "owner-asserted":
            raw = json.loads(rec.path.read_text(encoding="utf-8"))
            prov = raw.setdefault("provenance", {})
            prov["validated"] = {
                "at": dt.date.today().isoformat(), "by": a.by, "method": ev["method"]}
            # The listing-time fingerprint the daily re-check compares against. Stored
            # with the record so a page cannot be swapped between approval and day one.
            if isinstance(ev.get("fingerprint"), dict):
                prov["fingerprint"] = {**ev["fingerprint"],
                                       "at": dt.date.today().isoformat(),
                                       "artifact": ev.get("artifact")}
            rec.path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    print(f"verify: {len(records)} checked, {down} unreachable, "
          f"{unproven} reachable without a backlink")
    return 1 if (down or unproven) else 0


if __name__ == "__main__":
    sys.exit(main())
