#!/usr/bin/env python3
"""Live evidence for records: is the URL up, and does the site's owner claim it?

    python verify.py                 # report every record, exit 1 if any URL is down
    python verify.py --ids a b       # only these
    python verify.py --ids a --stamp # write the evidence into provenance.validated
    python verify.py --self-test

Owner proof: the site serves https://<host>/.well-known/aithernet.json containing
{"records": ["<id>", ...]}. Only someone who controls the site can put that file
there, so it separates the owner's entry from an impersonation.

A Discord community has no host to serve that file. Its address is an invite, so the
re-check is the invite: GET https://discord.com/api/v10/invites/<code> (public, no
token) must still resolve, and the guild it names must be the record's server id.
This re-check keeps a listing honest about being alive; it never invents the
``discord-bot`` stamp (only the bot that is IN the server observed Manage Server).
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
from typing import Callable, Optional, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import netindex  # noqa: E402

UA = "aithernet-index-verify/1 (+https://index.aitherium.com)"
DISCORD_API = "https://discord.com/api/v10/invites/"

JsonFetcher = Callable[[str], "Tuple[int, Optional[dict]]"]


def _get(url: str, limit: int = 65536) -> "tuple[int, bytes]":
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (https only)
            return resp.status, resp.read(limit)
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError, ValueError):
        return 0, b""


def _get_json(url: str) -> "tuple[int, Optional[dict]]":
    """GET and parse JSON; (0, None) when it could not be read at all."""
    status, body = _get(url)
    if not body:
        return status, None
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, None
    return status, data if isinstance(data, dict) else None


def invite_code(url: str) -> str:
    """The code in a permanent invite URL; "" when it is not one."""
    text = str(url or "").strip()
    if not netindex.DISCORD_INVITE_RE.match(text):
        return ""
    return text.rsplit("/", 1)[-1]


def discord_evidence(rec: netindex.Record,
                     fetch: JsonFetcher = _get_json) -> dict:
    """Resolve the invite and compare the guild it names with the record's server id."""
    code = invite_code(rec.url)
    if not code:
        return {"id": rec.id, "status": None, "method": None,
                "note": "not a https://discord.gg/ invite"}
    status, data = fetch(DISCORD_API + code + "?with_counts=true")
    if not isinstance(data, dict):
        return {"id": rec.id, "status": status or None, "method": None,
                "note": "the invite did not resolve"}
    guild = data.get("guild") if isinstance(data.get("guild"), dict) else {}
    found = str(guild.get("id") or "")
    want = str((rec.listing or {}).get("guild") or "")
    if not found:
        return {"id": rec.id, "status": status or None, "method": None,
                "note": "the invite names no guild"}
    if found != want:
        return {"id": rec.id, "status": status, "method": None, "guild": found,
                "expected": want, "note": "the invite resolves to another server"}
    return {"id": rec.id, "status": status, "method": "discord-bot", "guild": found,
            "members": data.get("approximate_member_count")}


def evidence(rec: netindex.Record) -> dict:
    if rec.kind == netindex.DISCORD_KIND:
        return discord_evidence(rec)
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


def _write(rec: netindex.Record, prov: dict) -> None:
    raw = json.loads(rec.path.read_text(encoding="utf-8"))
    raw["provenance"] = prov
    rec.path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def stamp(rec: netindex.Record, ev: dict, by: str, today: dt.date) -> None:
    """Record what this pass saw, without ever upgrading the proof beyond it."""
    if rec.path is None:
        return
    iso = today.isoformat()
    if rec.kind == netindex.DISCORD_KIND:
        prov = dict(rec.provenance)
        val = dict(prov.get("validated") or {})
        if ev["method"] == "discord-bot" and val.get("method") == "discord-bot":
            # Alive at this invite: refresh the date, keep the bot's attestation.
            val["at"] = iso
            prov["validated"] = val
            prov.pop("stale", None)
        elif ev["method"] is None:
            # Gone: say so. The record keeps who proved it and what they proved.
            prov["stale"] = {"at": iso, "reason": ev.get("note") or "invite did not resolve"}
        else:
            return
        _write(rec, prov)
        return
    if (rec.provenance.get("validated") or {}).get("method") == "owner-asserted":
        return
    prov = dict(rec.provenance)
    prov["validated"] = {"at": iso, "by": by, "method": ev["method"]}
    _write(rec, prov)


def _self_test() -> int:
    today = dt.date(2026, 11, 18)
    code = "abc123XYZ"
    ds = netindex._parse(None, {
        "id": "discord_123456789012345678", "kind": "discord", "title": "Seeds",
        "url": f"https://discord.gg/{code}", "listing": {"guild": "123456789012345678"},
        "provenance": {"added_by": "github:aithernet-bot", "sources": [f"https://discord.gg/{code}"],
                       "validated": {"at": "2026-11-17", "by": "aithernet-bot",
                                     "method": "discord-bot", "guild": "123456789012345678",
                                     "requested_by": "discord:987654321098765432"}}})
    world = {"guild": "123456789012345678", "data": True}
    calls = []

    def fetch(url: str) -> "Tuple[int, Optional[dict]]":
        calls.append(url)
        if not world["data"]:
            return 404, None
        return 200, {"guild": {"id": world["guild"]}, "approximate_member_count": 140}

    checks = {}
    checks["an invite code is read from discord.gg and discord.com/invite"] = (
        invite_code(f"https://discord.gg/{code}") == code
        and invite_code(f"https://discord.com/invite/{code}") == code)
    checks["a non-invite url yields no code"] = not invite_code("https://example.com/x")
    checks["the public invite API is used, with no token"] = (
        discord_evidence(ds, fetch)["method"] == "discord-bot"
        and calls and calls[0].startswith(DISCORD_API) and calls[0].endswith("?with_counts=true"))
    world["guild"] = "999999999999999999"
    checks["an invite that names another server is not evidence"] = (
        discord_evidence(ds, fetch)["method"] is None)
    world["guild"], world["data"] = "123456789012345678", False
    checks["an invite that no longer resolves is not evidence"] = (
        discord_evidence(ds, fetch)["method"] is None)
    world["data"] = True

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = Path(d, "discord_123456789012345678.json")
        path.write_text(json.dumps({"provenance": ds.provenance, "id": ds.id,
                                    "kind": "discord", "title": "Seeds",
                                    "url": ds.url, "listing": ds.listing}), encoding="utf-8")
        rec = netindex._parse(path, json.loads(path.read_text(encoding="utf-8")))
        stamp(rec, discord_evidence(rec, fetch), "aithernet-bot", today)
        raw = json.loads(path.read_text(encoding="utf-8"))
        checks["a live invite refreshes the date and keeps the attestation"] = (
            raw["provenance"]["validated"]["at"] == today.isoformat()
            and raw["provenance"]["validated"]["requested_by"] == "discord:987654321098765432"
            and "stale" not in raw["provenance"])
        world["data"] = False
        rec = netindex._parse(path, json.loads(path.read_text(encoding="utf-8")))
        stamp(rec, discord_evidence(rec, fetch), "aithernet-bot", today)
        raw = json.loads(path.read_text(encoding="utf-8"))
        checks["a dead invite marks the record stale and keeps the proof"] = (
            raw["provenance"]["stale"]["at"] == today.isoformat()
            and raw["provenance"]["validated"]["method"] == "discord-bot")
        # A public GET must never manufacture a discord-bot stamp.
        world["data"] = True
        bare = netindex._parse(None, {"id": ds.id, "kind": "discord", "title": "Seeds",
                                      "url": ds.url, "listing": ds.listing,
                                      "provenance": {"added_by": "x", "sources": [ds.url],
                                                     "validated": {"at": "2026-11-01", "by": "x",
                                                                   "method": "submitted"}}})
        before = json.dumps(bare.provenance, sort_keys=True)
        stamp_path = Path(d, "bare.json")
        stamp_path.write_text(json.dumps({"id": bare.id, "kind": "discord", "title": "Seeds",
                                          "url": bare.url, "listing": bare.listing,
                                          "provenance": bare.provenance}), encoding="utf-8")
        bare = netindex._parse(stamp_path, json.loads(stamp_path.read_text(encoding="utf-8")))
        stamp(bare, discord_evidence(bare, fetch), "aithernet-bot", today)
        after = json.loads(stamp_path.read_text(encoding="utf-8"))["provenance"]
        checks["resolving an invite never upgrades submitted to discord-bot"] = (
            json.dumps(after, sort_keys=True) == before)
    for name, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'} {name}")
    return 0 if all(checks.values()) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--stamp", action="store_true")
    ap.add_argument("--by", default="aithernet-bot")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    records, _ = netindex.load(a.root)
    if a.ids:
        wanted = set(a.ids)
        records = [r for r in records if r.id in wanted]
    records = [r for r in records if r.url]
    if not records:
        print("nothing to check")
        return 2
    down = 0
    today = dt.date.today()
    for rec in records:
        ev = evidence(rec)
        print(json.dumps(ev))
        if a.stamp:
            stamp(rec, ev, a.by, today)
        if ev["method"] is None:
            down += 1
    print(f"verify: {len(records)} checked, {down} unreachable")
    return 1 if down else 0


if __name__ == "__main__":
    sys.exit(main())
