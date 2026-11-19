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
That public GET proves only that the invite is alive: it exposes no requester, no
permissions and no bot membership, so it NEVER moves the ``validated`` attestation
(it records liveness under ``provenance.checked`` instead) and it never manufactures
the ``discord-bot`` stamp.

``--discord-attest`` is the check that CAN establish the proof, and it needs the bot:
with DISCORD_BOT_TOKEN in the environment (never on the command line) it asks Discord
whether the bot is in the guild and whether ``requested_by`` holds Manage Server
there. Only that observation writes the stamp; a manager who no longer holds it marks
the entry ``stale``. Stdlib only. Exit 0 all reachable, 1 any unreachable, 2 nothing
to check (or no token for --discord-attest).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
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
            # The invite is alive, so the address is still good. That says nothing
            # about who controls the server, so the attestation date does NOT move:
            # liveness is recorded on its own and trust() ignores it.
            prov["checked"] = {"at": iso, "guild": ev.get("guild", ""),
                              "status": ev.get("status")}
            if (prov.get("stale") or {}).get("kind", "invite") == "invite":
                prov.pop("stale", None)     # the invite is back; keep any other reason
        elif ev["method"] is None:
            # Gone: say so. The record keeps who proved it and what they proved.
            prov["stale"] = {"at": iso, "kind": "invite",
                             "reason": ev.get("note") or "invite did not resolve"}
        else:
            return
        _write(rec, prov)
        return
    # An unreachable site proves nothing: never overwrite a record's evidence with a
    # null method (the intake gate runs this before check.py and would reject it).
    if ev.get("method") is None:
        return
    # The operator's own assertion is not something a live fetch can improve on.
    if (rec.provenance.get("validated") or {}).get("method") == "owner-asserted":
        return
    prov = dict(rec.provenance)
    prov["validated"] = {"at": iso, "by": by, "method": ev["method"]}
    _write(rec, prov)


# -- the bot's attestation (the only proof of Manage Server) ------------------------------

DISCORD_API_BOT = "https://discord.com/api/v10"
MANAGE_GUILD = 1 << 5
ADMINISTRATOR = 1 << 3


def _discord_get(path: str, token: str,
                 fetch: JsonFetcher = None) -> "tuple[int, Optional[dict]]":
    """GET a bot endpoint with an Authorization header. (0, None) if unreadable."""
    if fetch is not None:
        return fetch(DISCORD_API_BOT + path)
    req = urllib.request.Request(DISCORD_API_BOT + path,
                                 headers={"User-Agent": UA,
                                          "Authorization": f"Bot {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (fixed host)
            return resp.status, json.loads(resp.read(65536).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def discord_attest(guild: str, user: str, token: str,
                   fetch: "Callable[[str], Tuple[int, Optional[dict]]]" = None) -> dict:
    """Ask Discord the question the public invite API cannot: does ``user`` hold
    Manage Server in ``guild``, and is the bot actually in that guild?

    Returns ``{"ok": bool, "reason": str}``. ``ok`` only on a positive observation:
    the bot's own membership is proven by the guild read succeeding, and the manager's
    permission is computed from the member's roles. Anything else is a refusal.
    """
    code, g = _discord_get(f"/guilds/{guild}", token, fetch)
    if not isinstance(g, dict):
        return {"ok": False, "reason": f"the bot is not in guild {guild} (HTTP {code})"}
    if str(g.get("id") or "") != guild:
        return {"ok": False, "reason": "Discord returned another guild"}
    code, member = _discord_get(f"/guilds/{guild}/members/{user}", token, fetch)
    if not isinstance(member, dict):
        return {"ok": False, "reason": f"{user} is not a member of {guild} (HTTP {code})"}
    if str(g.get("owner_id") or "") == user:
        return {"ok": True, "reason": "the requester owns the server"}
    code, roles = _discord_get(f"/guilds/{guild}/roles", token, fetch)
    if not isinstance(roles, list):
        return {"ok": False, "reason": f"roles could not be read (HTTP {code})"}
    perms = {}
    for role in roles:
        if isinstance(role, dict) and role.get("id"):
            try:
                perms[str(role["id"])] = int(role.get("permissions") or 0)
            except (TypeError, ValueError):
                perms[str(role["id"])] = 0
    held = {str(r) for r in member.get("roles") or []} | {guild}   # + @everyone
    got = 0
    for rid in held:
        got |= perms.get(rid, 0)
    if got & (ADMINISTRATOR | MANAGE_GUILD):
        return {"ok": True, "reason": "the requester holds Manage Server"}
    return {"ok": False, "reason": "the requester does not hold Manage Server"}


def attest_discord(rec: netindex.Record, token: str, today: dt.date,
                   fetch: "Callable[[str], Tuple[int, Optional[dict]]]" = None) -> dict:
    """Write the ``discord-bot`` stamp from a live permission check, or mark it stale.

    The stamp is only ever minted here (or by the intake, for the bot's own issue).
    A failed check DOWNGRADES a claim: a record whose requester never held Manage
    Server cannot keep tier 2 on a bot's authority.
    """
    val = rec.provenance.get("validated") or {}
    guild = str((rec.listing or {}).get("guild") or "")
    who = str(val.get("requested_by") or "")
    m = netindex.DISCORD_REQUESTER_RE.match(who)
    if not (guild and m):
        return {"ok": False, "reason": "the record has no guild or requested_by to check"}
    user = who.split(":", 1)[1]
    verdict = discord_attest(guild, user, token, fetch)
    if rec.path is None:
        return verdict
    prov = dict(rec.provenance)
    iso = today.isoformat()
    if verdict["ok"]:
        prov["validated"] = {"at": iso, "by": "aithernet-bot", "method": "discord-bot",
                             "guild": guild, "requested_by": who}
        if (prov.get("stale") or {}).get("kind") == "permission":
            prov.pop("stale", None)         # a liveness failure still stands
    else:
        prov["stale"] = {"at": iso, "kind": "permission", "reason": verdict["reason"]}
    _write(rec, prov)
    return verdict


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
        checks["a live invite records liveness, not a new attestation"] = (
            raw["provenance"]["validated"]["at"] == "2026-11-17"
            and raw["provenance"]["validated"]["requested_by"] == "discord:987654321098765432"
            and raw["provenance"]["checked"]["at"] == today.isoformat()
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

        # -- the bot's attestation is the only writer of the stamp --------------------
        guild, mgr = ds.listing["guild"], "987654321098765432"
        bot = {"in_guild": True, "owner": "1",
               "roles": [{"id": "555", "permissions": str(MANAGE_GUILD)}],
               "member": {"roles": ["555"]}}

        def bfetch(url: str) -> "Tuple[int, Optional[dict]]":
            if url.endswith(f"/guilds/{guild}"):
                return (200, {"id": guild, "owner_id": bot["owner"]}) if bot["in_guild"] \
                    else (404, None)
            if f"/members/{mgr}" in url:
                return 200, bot["member"]
            if url.endswith("/roles"):
                return 200, bot["roles"]
            return 0, None

        att = Path(d, "attest.json")
        att.write_text(json.dumps({"id": ds.id, "kind": "discord", "title": "Seeds",
                                   "url": ds.url, "listing": {"guild": guild},
                                   "provenance": {"added_by": "github:aither-wzns",
                                                  "sources": [ds.url],
                                                  "validated": {"at": "2026-11-01",
                                                                "by": "aithernet-bot",
                                                                "method": "discord-bot",
                                                                "guild": guild,
                                                                "requested_by": "discord:" + mgr}}}),
                       encoding="utf-8")
        got = netindex._parse(att, json.loads(att.read_text(encoding="utf-8")))
        ok = attest_discord(got, "token", today, bfetch)
        raw = json.loads(att.read_text(encoding="utf-8"))
        checks["attest writes the stamp when the requester holds Manage Server"] = (
            ok["ok"] and raw["provenance"]["validated"]["at"] == today.isoformat()
            and raw["provenance"]["validated"]["requested_by"] == "discord:" + mgr)
        bot["member"] = {"roles": []}
        got = netindex._parse(att, json.loads(att.read_text(encoding="utf-8")))
        ok = attest_discord(got, "token", today, bfetch)
        raw = json.loads(att.read_text(encoding="utf-8"))
        checks["a requester without Manage Server is refused and marked stale"] = (
            not ok["ok"] and "Manage Server" in raw["provenance"]["stale"]["reason"])
        bot["in_guild"] = False
        got = netindex._parse(att, json.loads(att.read_text(encoding="utf-8")))
        ok = attest_discord(got, "token", today, bfetch)
        checks["a guild the bot is not in is not evidence"] = (
            not ok["ok"] and "not in guild" in ok["reason"])
        bot["in_guild"], bot["owner"] = True, mgr
        got = netindex._parse(att, json.loads(att.read_text(encoding="utf-8")))
        checks["the server owner holds Manage Server"] = (
            attest_discord(got, "token", today, bfetch)["ok"])
        # A live permission check must not undo a dead-invite verdict.
        body = json.loads(att.read_text(encoding="utf-8"))
        body["provenance"]["stale"] = {"at": "2026-11-02", "kind": "invite",
                                       "reason": "the invite did not resolve"}
        att.write_text(json.dumps(body), encoding="utf-8")
        got = netindex._parse(att, json.loads(att.read_text(encoding="utf-8")))
        checks["a permission check keeps a dead-invite verdict"] = (
            attest_discord(got, "token", today, bfetch)["ok"]
            and (json.loads(att.read_text(encoding="utf-8"))["provenance"].get("stale") or {}
                 ).get("kind") == "invite")

        # -- verify --stamp must not corrupt an unreachable site (PR #30 regression) ----
        site = {"id": "dead.example", "kind": "site", "title": "Dead",
                "url": "https://dead.invalid.example/",
                "provenance": {"added_by": "github:x", "sources": ["https://dead.invalid.example/"],
                               "validated": {"at": "2026-11-01", "by": "github:x",
                                             "method": "submitted"}}}
        sp = Path(d, "dead.example.json")
        sp.write_text(json.dumps(site), encoding="utf-8")
        rec = netindex._parse(sp, json.loads(sp.read_text(encoding="utf-8")))
        stamp(rec, {"id": rec.id, "status": 0, "method": None}, "aithernet-bot", today)
        checks["an unreachable site's evidence is left alone by --stamp"] = (
            json.loads(sp.read_text(encoding="utf-8"))["provenance"] == site["provenance"])
        oa = {"id": "op.example", "kind": "site", "title": "Op", "url": "https://op.example/",
              "provenance": {"added_by": "aither", "sources": ["https://op.example/"],
                             "validated": {"at": "2026-11-01", "by": "aither",
                                           "method": "owner-asserted"}}}
        op = Path(d, "op.example.json")
        op.write_text(json.dumps(oa), encoding="utf-8")
        rec = netindex._parse(op, json.loads(op.read_text(encoding="utf-8")))
        stamp(rec, {"id": rec.id, "status": 200, "method": "http-200"},
              "aithernet-bot", today)
        checks["an operator assertion is not downgraded by a live fetch"] = (
            json.loads(op.read_text(encoding="utf-8"))["provenance"] == oa["provenance"])
    for name, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'} {name}")
    return 0 if all(checks.values()) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--stamp", action="store_true")
    ap.add_argument("--discord-attest", action="store_true",
                    help="re-derive Manage Server with DISCORD_BOT_TOKEN (env, not argv)")
    ap.add_argument("--by", default="aithernet-bot")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    if a.discord_attest and not token:
        print("no DISCORD_BOT_TOKEN in the environment: cannot attest", file=sys.stderr)
        return 2
    records, _ = netindex.load(a.root)
    if a.ids:
        wanted = set(a.ids)
        records = [r for r in records if r.id in wanted]
    records = [r for r in records if r.url]
    if not records:
        print("nothing to check")
        return 2
    down = refused = 0
    today = dt.date.today()
    for rec in records:
        ev = evidence(rec)
        print(json.dumps(ev))
        if a.stamp:
            stamp(rec, ev, a.by, today)
        if a.discord_attest and rec.kind == netindex.DISCORD_KIND:
            verdict = attest_discord(rec, token, today)
            print(json.dumps({"id": rec.id, "attested": verdict["ok"],
                              "reason": verdict["reason"]}))
            if not verdict["ok"]:
                refused += 1
        if ev["method"] is None:
            down += 1
    print(f"verify: {len(records)} checked, {down} unreachable")
    return 1 if down or refused else 0


if __name__ == "__main__":
    sys.exit(main())
