#!/usr/bin/env python3
"""Import the 'Digital Garden Directory' from MaggieAppleton/digital-gardeners (MIT).

Each garden becomes a `garden` record linked (`part_of`) to one webring hub record.
Only https gardens that answer 200 are written; everything else is reported and
skipped, never guessed. Re-running is safe: existing ids are left alone.

    python tools/import_digital_gardeners.py README.md        # a downloaded copy
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import netindex  # noqa: E402
import verify  # noqa: E402

SOURCE = "https://github.com/MaggieAppleton/digital-gardeners"
HUB = "ring_digital-gardeners"
ROW = re.compile(r"^\|\s*(⭐️\s*)?\[([^\]]+)\]\((https?://[^)\s]+)\)\s*\|([^|]*)\|([^|]*)")
SAFE = re.compile(r"[^a-z0-9._-]+")


def rows(readme: str):
    section = readme.split("## Digital Garden Directory", 1)[-1].split("\n## ", 1)[0]
    for line in section.splitlines():
        m = ROW.match(line.strip())
        if m:
            yield bool(m.group(1)), m.group(2).strip(), m.group(3).strip(), m.group(5)


def main() -> int:
    readme = Path(sys.argv[1]).read_text(encoding="utf-8")
    today = dt.date.today().isoformat()
    recs = netindex.DEFAULT_ROOT
    hub = recs / f"{HUB}.json"
    if not hub.exists():
        hub.write_text(json.dumps({
            "id": HUB, "kind": "dataset", "title": "Digital Gardeners webring",
            "url": SOURCE, "tags": ["digital-garden", "webring", "tools-for-thought"],
            "names": ["gardens.aither"], "route": {"type": "web", "target": SOURCE},
            "provenance": {"added_by": "import:digital-gardeners (MIT, Maggie Appleton)",
                           "sources": [SOURCE],
                           "validated": {"at": today, "by": "aithernet-bot",
                                         "method": "http-200"}}}, indent=2) + "\n",
            encoding="utf-8")
    added = skipped = 0
    for featured, who, url, themes in rows(readme):
        if url.startswith("http://"):
            url = "https://" + url[len("http://"):]
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = SAFE.sub("-", parts.path.strip("/").lower()).strip("-")[:40]
        rid = host + (f"_{path}" if path else "")
        if not host or (recs / f"{rid}.json").exists():
            continue
        tags = [SAFE.sub("-", t.strip().lower()).strip("-")[:30] for t in themes.split(",")]
        tags = ["digital-garden"] + [t for t in tags if t][:6]
        if featured:
            tags.append("featured")
        rec = netindex._parse(None, {"id": rid, "kind": "garden", "title": who, "url": url})
        ev = verify.evidence(rec)
        if ev["method"] is None:
            print(f"skip {rid}: status {ev['status']}")
            skipped += 1
            continue
        (recs / f"{rid}.json").write_text(json.dumps({
            "id": rid, "kind": "garden", "title": f"{who}'s garden", "url": url,
            "tags": tags, "edges": [{"rel": "part_of", "to": HUB}],
            "provenance": {"added_by": "import:digital-gardeners (MIT, Maggie Appleton)",
                           "sources": [SOURCE, url],
                           "validated": {"at": today, "by": "aithernet-bot",
                                         "method": ev["method"]}}}, indent=2) + "\n",
            encoding="utf-8")
        added += 1
    print(f"imported {added}, skipped {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
