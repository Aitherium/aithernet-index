#!/usr/bin/env python3
"""Live evidence for records: is the URL up, and does the site's owner claim it?

    python verify.py                 # report every record, exit 1 if any URL is down
    python verify.py --ids a b       # only these
    python verify.py --ids a --stamp # write the evidence into provenance.validated

Owner proof: the site serves https://<host>/.well-known/aithernet.json containing
{"records": ["<id>", ...]}. Only someone who controls the site can put that file
there, so it separates the owner's entry from an impersonation.
Stdlib only. Exit 0 all reachable, 1 any unreachable, 2 nothing to check.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import netindex  # noqa: E402

UA = "aithernet-index-verify/1 (+https://index.aitherium.com)"


def _get(url: str, limit: int = 65536) -> "tuple[int, bytes]":
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (https only)
            return resp.status, resp.read(limit)
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError, ValueError):
        return 0, b""


def evidence(rec: netindex.Record) -> dict:
    if not rec.url.startswith("https://"):
        return {"id": rec.id, "status": None, "method": None, "note": "no https url"}
    status, _ = _get(rec.url)
    out = {"id": rec.id, "status": status, "method": "http-200" if status == 200 else None}
    host = urlsplit(rec.url).hostname or ""
    code, body = _get(f"https://{host}/.well-known/aithernet.json")
    if code == 200:
        try:
            claimed = json.loads(body.decode("utf-8")).get("records") or []
        except (ValueError, AttributeError):
            claimed = []
        if rec.id in claimed and status == 200:
            out["method"] = "well-known"
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
    records = [r for r in records if r.url]
    if not records:
        print("nothing to check")
        return 2
    down = 0
    for rec in records:
        ev = evidence(rec)
        print(json.dumps(ev))
        if ev["method"] is None:
            down += 1
            continue
        current = (rec.provenance.get("validated") or {}).get("method")
        if a.stamp and current != "owner-asserted":
            raw = json.loads(rec.path.read_text(encoding="utf-8"))
            raw.setdefault("provenance", {})["validated"] = {
                "at": dt.date.today().isoformat(), "by": a.by, "method": ev["method"]}
            rec.path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    print(f"verify: {len(records)} checked, {down} unreachable")
    return 1 if down else 0


if __name__ == "__main__":
    sys.exit(main())
