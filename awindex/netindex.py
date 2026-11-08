"""AitherNet Index: a curated, validated internet graph that lives in git.

One JSON file per entity under ``records/``. The file
IS the record; git history is the audit log; a pull request is how a
contribution arrives (from a person, awfind/awresearch harvest, ShadowBroker
gates or the Tagalong Town residents). Nothing here crawls or fetches: this
module loads, validates, resolves names and walks edges. Validation that needs
the network (is the URL alive) is recorded IN the record by whoever checked it,
under ``provenance.validated``, so a reviewer can re-run it.

Name resolution is the AitherNet DNS/router seam: ``resolve("docs.aither")``
returns the route a client should take. Two records claiming one name is a
validation error (NI003), never a silent first-wins.

Python 3.10 compatible; stdlib only.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# A checkout of the index repo (records/ beside the package), or AWINDEX_ROOT.
# A pip install has no records/: the CLI then reads index.aitherium.com instead.
DEFAULT_ROOT = Path(os.environ.get("AWINDEX_ROOT")
                    or Path(__file__).resolve().parents[1] / "records")

# garden = a personal digital garden (Neocities-style); room = an AitherRelay channel;
# space = an AitherSpace. A .aither name on any of them is its AOL-style keyword.
KINDS = {"site", "service", "org", "gate", "world", "dataset",
         "garden", "room", "space"}
ROUTE_TYPES = {"web", "aithernet", "relay-gate", "world", "relay-room", "space"}
EDGE_RELS = {"owned_by", "links_to", "mirrors", "part_of", "bridges", "about", "alternative_to"}
NAME_SUFFIX = ".aither"


@dataclass
class Finding:
    code: str
    record: str
    message: str

    def __str__(self) -> str:
        return f"{self.code} {self.record}: {self.message}"


@dataclass
class Record:
    id: str
    kind: str
    title: str
    url: str = ""
    tags: list = field(default_factory=list)
    names: list = field(default_factory=list)
    route: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    path: Optional[Path] = None


def _parse(path: Path, raw: dict) -> Record:
    return Record(
        id=raw.get("id", ""),
        kind=raw.get("kind", ""),
        title=raw.get("title", ""),
        url=raw.get("url", ""),
        tags=list(raw.get("tags") or []),
        names=list(raw.get("names") or []),
        route=dict(raw.get("route") or {}),
        edges=list(raw.get("edges") or []),
        provenance=dict(raw.get("provenance") or {}),
        path=path,
    )


def load(root: Path = DEFAULT_ROOT) -> "tuple[list[Record], list[Finding]]":
    """Load every record. Unreadable JSON is a finding, not an exception."""
    records: list = []
    findings: list = []
    for path in sorted(Path(root).rglob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            findings.append(Finding("NI000", path.name, f"unreadable JSON: {exc}"))
            continue
        if not isinstance(raw, dict):
            findings.append(Finding("NI000", path.name, "top level is not an object"))
            continue
        records.append(_parse(path, raw))
    return records, findings


def validate(records: Iterable[Record], today: Optional[_dt.date] = None) -> "list[Finding]":
    """Every rule the index must hold. Empty list = clean."""
    today = today or _dt.date.today()
    recs = list(records)
    out: list = []
    ids = {}
    for r in recs:
        if r.id in ids:
            out.append(Finding("NI002", r.id, f"duplicate id (also {ids[r.id]})"))
        ids[r.id] = r.path.name if r.path else r.id

    names: dict = {}
    for r in recs:
        rid = r.id or (r.path.name if r.path else "?")
        if not r.id or not r.title:
            out.append(Finding("NI001", rid, "id and title are required"))
        if r.kind not in KINDS:
            out.append(Finding("NI001", rid, f"kind {r.kind!r} not in {sorted(KINDS)}"))
        if r.path is not None and r.path.stem != r.id.replace(":", "_"):
            out.append(Finding("NI002", rid, f"file name {r.path.name} != id"))
        if r.url and not r.url.startswith("https://"):
            out.append(Finding("NI007", rid, "url must be https://"))
        for n in r.names:
            if not isinstance(n, str) or not n.endswith(NAME_SUFFIX) or n != n.lower():
                msg = f"name {n!r} must be lowercase and end in {NAME_SUFFIX}"
                out.append(Finding("NI005", rid, msg))
            if n in names:
                out.append(Finding("NI003", rid, f"name {n!r} already claimed by {names[n]}"))
            names.setdefault(n, rid)
        if r.names:
            rtype = r.route.get("type")
            if rtype not in ROUTE_TYPES or not r.route.get("target"):
                msg = f"a named record needs route.type in {sorted(ROUTE_TYPES)} and route.target"
                out.append(Finding("NI006", rid, msg))
            elif rtype == "web" and not str(r.route["target"]).startswith("https://"):
                out.append(Finding("NI007", rid, "web route target must be https://"))
        for e in r.edges:
            rel, to = (e or {}).get("rel"), (e or {}).get("to")
            if rel not in EDGE_RELS:
                out.append(Finding("NI004", rid, f"edge rel {rel!r} not in {sorted(EDGE_RELS)}"))
            if to not in ids:
                out.append(Finding("NI004", rid, f"edge to unknown record {to!r}"))
        prov = r.provenance
        val = prov.get("validated") or {}
        if not prov.get("added_by") or not prov.get("sources"):
            msg = "provenance.added_by and provenance.sources are required"
            out.append(Finding("NI008", rid, msg))
        if not val.get("at") or not val.get("by") or not val.get("method"):
            out.append(Finding("NI008", rid, "provenance.validated needs at, by, method"))
        else:
            try:
                when = _dt.date.fromisoformat(str(val["at"]))
            except ValueError:
                out.append(Finding("NI008", rid, f"validated.at {val['at']!r} is not YYYY-MM-DD"))
            else:
                if when > today:
                    out.append(Finding("NI008", rid, f"validated.at {when} is in the future"))
        seen = set()
        for v in prov.get("vouches") or []:
            who = (v or {}).get("by")
            if not who or not (v or {}).get("at"):
                out.append(Finding("NI009", rid, "a vouch needs by and at"))
            elif who == prov.get("added_by"):
                out.append(Finding("NI009", rid, f"{who} cannot vouch for their own submission"))
            elif who in seen:
                out.append(Finding("NI009", rid, f"{who} vouched twice"))
            seen.add(who)
    return out


# Trust is COMPUTED from evidence in the record, never typed in by a contributor.
# A submitter can claim anything; only these facts move an entry up a tier.
TIERS = {0: "submitted", 1: "reachable", 2: "owner-proven", 3: "vouched"}
_REACH_METHODS = {"http-200"}
_OWNER_METHODS = {"well-known", "owner-asserted"}


def trust(r: Record) -> int:
    """0 submitted · 1 reachable (bot fetched it) · 2 owner-proven (the site serves
    /.well-known/aithernet.json naming this id) · 3 vouched (reachable or better AND
    at least two distinct people other than the submitter vouched)."""
    method = (r.provenance.get("validated") or {}).get("method", "")
    tier = 2 if method in _OWNER_METHODS else 1 if method in _REACH_METHODS else 0
    vouchers = {v.get("by") for v in r.provenance.get("vouches") or [] if v.get("by")}
    vouchers.discard(r.provenance.get("added_by"))
    if tier >= 1 and len(vouchers) >= 2:
        tier = 3
    return tier


class Index:
    """In-memory view: name -> route, id -> record, edge walks."""

    def __init__(self, records: Iterable[Record]):
        self.records = {r.id: r for r in records}
        self.names = {n: r.id for r in self.records.values() for n in r.names}

    @classmethod
    def from_root(cls, root: Path = DEFAULT_ROOT) -> "Index":
        recs, _ = load(root)
        return cls(recs)

    def resolve(self, name: str) -> Optional[dict]:
        """The AitherNet DNS seam. None = NXDOMAIN; never a guess."""
        rid = self.names.get(name.strip().lower().rstrip("."))
        if rid is None:
            return None
        r = self.records[rid]
        return {"name": name, "id": r.id, "kind": r.kind, **r.route}

    def neighbours(self, rid: str) -> "list[tuple[str, str, str]]":
        """(direction, rel, other_id) for every edge touching ``rid``."""
        out = []
        for r in self.records.values():
            for e in r.edges:
                if r.id == rid:
                    out.append(("out", e.get("rel", ""), e.get("to", "")))
                elif e.get("to") == rid:
                    out.append(("in", e.get("rel", ""), r.id))
        return out

    def search(self, query: str, limit: int = 10) -> "list[Record]":
        """Plain token match over id/title/tags; the AitherSearch provider seam."""
        toks = [t for t in query.lower().split() if t]
        scored = []
        for r in self.records.values():
            hay = " ".join([r.id, r.title, *r.tags, *r.names]).lower()
            s = sum(1 for t in toks if t in hay)
            if s:
                scored.append((s, r.id, r))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [r for _, _, r in scored[:limit]]
