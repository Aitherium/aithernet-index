#!/usr/bin/env python3
"""Turn a 'Submit a site' issue into a record file. Run by .github/workflows/intake.yml.

The issue body is UNTRUSTED. It is read from the event JSON (never a shell
argument), every field is length-capped and pattern-checked, and the id is
derived from the URL, not chosen by the submitter. The record enters at tier 0
('submitted'); verify.py then stamps whatever evidence it can actually see.

    python intake.py --event "$GITHUB_EVENT_PATH"   # prints the new record id
    python intake.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import netindex  # noqa: E402

FORM_KINDS = {"site", "garden", "room", "space", "dataset", "org", "service"}
_SAFE = re.compile(r"[^a-z0-9._-]+")


def parse_form(body: str) -> dict:
    """GitHub issue forms render as '### Label' followed by the value."""
    out: dict = {}
    key = None
    for line in (body or "").splitlines():
        if line.startswith("### "):
            key = line[4:].strip().lower()
            out[key] = []
        elif key is not None:
            out[key].append(line)
    joined = {k: "\n".join(v).strip() for k, v in out.items()}
    return {k: v for k, v in joined.items() if v not in ("", "_No response_")}


def record_from(form: dict, login: str, today: dt.date) -> dict:
    url = form.get("url", "").strip()
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or len(url) > 300:
        raise ValueError("url must be a valid https:// address")
    host = parts.hostname.lower()
    path = _SAFE.sub("-", parts.path.strip("/").lower()).strip("-")[:40]
    rid = host + (f"_{path}" if path else "")
    kind = form.get("kind", "site").strip().lower()
    if kind not in FORM_KINDS:
        raise ValueError(f"kind must be one of {sorted(FORM_KINDS)}")
    title = form.get("title", "").strip()[:120] or host
    tags = [_SAFE.sub("-", t.strip().lower())[:30] for t in form.get("tags", "").split(",")]
    rec: dict = {"id": rid, "kind": kind, "title": title, "url": url,
                 "tags": [t for t in tags if t][:8]}
    name = form.get("keyword", "").strip().lower()
    if name:
        if not re.fullmatch(r"[a-z0-9-]{2,40}\.aither", name):
            raise ValueError("keyword must look like my-site.aither")
        rec["names"] = [name]
        rec["route"] = {"type": "web", "target": url}
    rec["provenance"] = {
        "added_by": f"github:{login}",
        "sources": [url],
        "validated": {"at": today.isoformat(), "by": f"github:{login}", "method": "submitted"},
    }
    return rec


def _self_test() -> int:
    day = dt.date(2026, 11, 8)
    body = ("### URL\n\nhttps://Example.com/My Garden\n\n### Title\n\nEx\n\n"
            "### Kind\n\ngarden\n\n### Tags\n\nA, b c\n\n### Keyword\n\n_No response_")
    r = record_from(parse_form(body), "alice", day)
    ok = (r["id"] == "example.com_my-garden" and r["kind"] == "garden"
          and r["tags"] == ["a", "b-c"] and "names" not in r
          and r["provenance"]["validated"]["method"] == "submitted")
    for bad in ({"url": "http://x.com"}, {"url": "https://x.com", "keyword": "evil;rm.aither"},
                {"url": "https://x.com", "kind": "admin"}):
        try:
            record_from(bad, "m", day)
            ok = False
        except ValueError:
            pass
    print("PASS intake" if ok else f"FAIL intake {r}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--event", type=Path)
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    event = json.loads(a.event.read_text(encoding="utf-8"))
    issue = event["issue"]
    try:
        rec = record_from(parse_form(issue.get("body", "")), issue["user"]["login"],
                          dt.date.today())
    except ValueError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 1
    path = a.root / f"{rec['id']}.json"
    if path.exists():
        print(f"already indexed: {rec['id']}", file=sys.stderr)
        return 3
    path.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    print(rec["id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
