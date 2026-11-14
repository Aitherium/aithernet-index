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
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# A checkout of the index repo (records/ beside the package), or AWINDEX_ROOT.
# A pip install has no records/: the CLI then reads index.aitherium.com instead.
DEFAULT_ROOT = Path(os.environ.get("AWINDEX_ROOT")
                    or Path(__file__).resolve().parents[1] / "records")

# garden = a personal digital garden (Neocities-style); room = an AitherRelay channel;
# space = an AitherSpace. A .aither name on any of them is its AOL-style keyword.
# business = a place or company that wants to be found (hours, area, contact): its
# facts live in ``listing`` and are published as schema.org data search engines and
# AI agents read. Claiming one is the same owner proof as any record (well-known).
KINDS = {"site", "service", "org", "gate", "world", "dataset",
         "garden", "room", "space", "business"}
ROUTE_TYPES = {"web", "aithernet", "relay-gate", "world", "relay-room", "space"}
EDGE_RELS = {"owned_by", "links_to", "mirrors", "part_of", "bridges", "about", "alternative_to"}
NAME_SUFFIX = ".aither"

# listing: the facts a business wants found. Every field optional and capped (NI010).
LISTING_TEXT = {"description": 500, "category": 60, "address": 200, "area_served": 120,
                "phone": 40, "email": 120}
LISTING_KEYS = set(LISTING_TEXT) | {"hours", "same_as", "geo"}
_DAY = "(Mo|Tu|We|Th|Fr|Sa|Su)"
_HHMM = "([01][0-9]|2[0-4]):[0-5][0-9]"
# schema.org openingHours, e.g. "Mo-Fr 09:00-17:00" or "Sa,Su 10:00-14:00"
HOURS_RE = re.compile(f"^{_DAY}([-,]{_DAY})* {_HHMM}-{_HHMM}$")
PHONE_RE = re.compile("^[+]?[0-9][0-9 ()./-]{4,38}$")
EMAIL_RE = re.compile("^[^@ <>\"']+@[^@ <>\"']+[.][A-Za-z]{2,}$")
_CTRL = re.compile("[" + chr(0) + "-" + chr(31) + chr(127) + "]")


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
    listing: dict = field(default_factory=dict)
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
        listing=raw["listing"] if isinstance(raw.get("listing"), dict) else (
            {"_invalid": True} if raw.get("listing") is not None else {}),
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
        out += listing_findings(rid, r.kind, r.url, r.listing)
    return out


def listing_findings(rid: str, kind: str, url: str, listing: dict) -> "list[Finding]":
    """NI010: a listing holds only known, capped, well-formed facts."""
    out: list = []
    if kind == "business" and not url:
        out.append(Finding("NI010", rid, "a business needs an https url (owner proof is per host)"))
    if not listing:
        return out
    if listing.get("_invalid"):
        return out + [Finding("NI010", rid, "listing must be an object")]
    for k in sorted(set(listing) - LISTING_KEYS):
        out.append(Finding("NI010", rid, f"unknown listing field {k!r}"))
    for k, cap in LISTING_TEXT.items():
        v = listing.get(k)
        if v is None:
            continue
        if not isinstance(v, str) or not v.strip() or len(v) > cap or _CTRL.search(v):
            out.append(Finding("NI010", rid, f"listing.{k} must be text of 1-{cap} chars"))
    if isinstance(listing.get("phone"), str) and not PHONE_RE.match(listing["phone"]):
        out.append(Finding("NI010", rid, "listing.phone is not a phone number"))
    if isinstance(listing.get("email"), str) and not EMAIL_RE.match(listing["email"]):
        out.append(Finding("NI010", rid, "listing.email is not an email address"))
    hours = listing.get("hours")
    if hours is not None:
        if not isinstance(hours, list) or len(hours) > 14:
            out.append(Finding("NI010", rid, "listing.hours must be a list of up to 14 entries"))
        else:
            for h in hours:
                if not isinstance(h, str) or not HOURS_RE.match(h):
                    out.append(Finding("NI010", rid, f"listing.hours {h!r} is not like 'Mo-Fr 09:00-17:00'"))
    same = listing.get("same_as")
    if same is not None:
        if not isinstance(same, list) or len(same) > 10:
            out.append(Finding("NI010", rid, "listing.same_as must be a list of up to 10 urls"))
        else:
            for u in same:
                if not isinstance(u, str) or not u.startswith("https://") or len(u) > 300:
                    out.append(Finding("NI010", rid, f"listing.same_as {u!r} must be an https url"))
    geo = listing.get("geo")
    if geo is not None:
        lat = geo.get("lat") if isinstance(geo, dict) else None
        lng = geo.get("lng") if isinstance(geo, dict) else None
        nums = all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (lat, lng))
        if not nums or not (-90 <= lat <= 90 and -180 <= lng <= 180):
            out.append(Finding("NI010", rid, "listing.geo needs numeric lat (-90..90) and lng (-180..180)"))
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
    # OSINT evidence (ShadowBroker: provenance.evidence) can only LOWER trust: a
    # sanctions hit or a HIGH/CRITICAL threat level is tier 0, and a domain younger
    # than 30 days never rises above `reachable`. A shared host carries no verdict.
    ev = r.provenance.get("evidence") or {}
    if not ev.get("shared_host"):
        threat = str(ev.get("threat_level", "")).upper()
        if ev.get("sanctions_hits", 0) > 0 or threat in ("HIGH", "CRITICAL"):
            return 0
        age = ev.get("domain_age_days")
        if isinstance(age, (int, float)) and age < 30:
            tier = min(tier, 1)
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
