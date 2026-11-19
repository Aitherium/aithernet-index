#!/usr/bin/env python3
"""Re-check every listed site, every day, and act on what changed.

A listing is an approval of a page at a moment. This is the thing that keeps that
approval honest after the moment has passed: it re-visits every record, asks whether
the required backlink artifact is still there and whether the page still *is* the page
that was approved (fingerprint, see ``fingerprint.py``), and moves the entry through a
state machine kept in ``state/health.json`` — never in the records themselves, so a
record stays exactly what a human last reviewed.

    active --(first failure)--> warn
    warn --(3 failures inside 7 days, or the final host changed)--> suspended
    suspended --(14 days)--> delisted
    anything --(a clean check, and a window that is not still dirty)--> active

Failures are: the URL does not answer, the required backlink is gone (after the grace
period, and only for records listed before this shipped), the page now redirects to a
different host (HTTP or client-side), the page serves a different body to the checker
than to a browser, or the visible text changed beyond the similarity threshold.

Failures are counted over a rolling window, not reset by a single good day: a site
that is down two days in three is suspended on the fourth day, and does not return to
``active`` until the window is no longer mostly failures. ``warn`` is hidden from the
published listing too, so a permanently flapping entry stops being shown at all.

``delisted`` does not delete anything. ``build_site.py`` hides the entry from the
listing, the published ``index.json`` says ``status: delisted``, and the record page
still explains why. Nothing here ever writes to ``records/``.

    python recheck.py --dry-run                       # local status table, writes nothing
    python recheck.py --root records --state state/health.json
    python recheck.py --plan-issues run.json issues.json
    python recheck.py --apply-issues actions.json
    python recheck.py --self-test
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifact  # noqa: E402
import fingerprint  # noqa: E402
import netindex  # noqa: E402

DEFAULT_STATE = Path(__file__).resolve().parent / "state" / "health.json"
STATUSES = ("active", "warn", "suspended", "delisted")
STATE_VERSION = 2

# Rule numbers for the two checks that live here. NI000-NI010 are the record rules in
# awindex/netindex.py; NI011/NI012 belong to the parallel feat/discord-owner-proof
# branch (Discord record/url and its stamp), so the re-check starts at NI020 to keep
# the two PRs from claiming the same number for different rules.
STATE_RULE = "NI020"        # state/health.json shape and integrity
BASELINE_RULE = "NI021"     # a baseline fingerprint that was edited without a re-seed
ARTIFACT_RULE = "NI022"     # a post-grace listing with no backlink artifact

# The day this mechanism ships. Records listed before it get GRACE_DAYS to grow a
# backlink before the artifact rule starts counting against them. A record validated
# ON OR AFTER this date is a *new* listing: it must carry the artifact from day one.
GRACE_STARTS = "2026-11-18"
GRACE_DAYS = 30
SUSPEND_AFTER = 3          # failures inside the window that suspend an entry
SUSPEND_WINDOW_DAYS = 7    # the window failures are counted over
DELIST_AFTER_DAYS = 14     # days suspended before the listing is hidden
HISTORY_DAYS = 30          # how much daily history the state keeps per entry

# Failure codes. NEEDS_REVIEW ones mean "a human must look before this is trusted again".
UNREACHABLE = "unreachable"
ARTIFACT_MISSING = "artifact-missing"
HOST_CHANGED = "host-changed"
CONTENT_CHANGED = "content-changed"
CLOAKING = "cloaking"
BASELINE_MISSING = "baseline-missing"
# Two fetches of the same page differ a little on any dynamic site (rotating
# testimonials, nonces), so cloaking is only claimed for a page that is *largely*
# different, not merely below the content-drift threshold.
CLOAK_SIMILARITY = 0.30
NEEDS_REVIEW = {HOST_CHANGED, CONTENT_CHANGED, CLOAKING, BASELINE_MISSING}
# Which codes open an issue. A host change is also hard-suspending on day one.
ISSUE_CODES = NEEDS_REVIEW | {ARTIFACT_MISSING}

ISSUE_LABEL = "recheck"
ISSUE_PREFIX = "[recheck]"
ISSUE_SEP = " :: "   # ids never contain a space, so this parses unambiguously


# --------------------------------------------------------------------------- state

def _today(value: Optional[str]) -> dt.date:
    return dt.date.fromisoformat(value) if value else dt.date.today()


def load_state(path: Path = DEFAULT_STATE) -> dict:
    """Read state/health.json, or an empty-but-valid state when there is none yet."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    state = {
        "version": STATE_VERSION,
        "grace_starts": raw.get("grace_starts") or GRACE_STARTS,
        "grace_days": raw.get("grace_days", GRACE_DAYS),
        "updated": raw.get("updated"),
        "entries": raw.get("entries") if isinstance(raw.get("entries"), dict) else {},
    }
    if not isinstance(state["grace_days"], int) or state["grace_days"] < 0:
        state["grace_days"] = GRACE_DAYS
    return state


def save_state(state: dict, path: Path = DEFAULT_STATE) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    state = copy.deepcopy(state)
    for e in state.get("entries", {}).values():
        if isinstance(e, dict):
            e.pop("_note", None)
    Path(path).write_text(json.dumps(state, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def new_entry() -> dict:
    return {"status": "active", "since": None, "last_checked": None, "last_ok": None,
            "consecutive_failures": 0, "artifact_missing_days": 0, "suspended_since": None,
            "artifact": None, "artifact_reason": "", "failures": [], "recent": [],
            "baseline": None, "baseline_source": None, "seeded_at": None,
            "accepted_at": None, "validated_at": None, "baseline_expected": True,
            "ever_ok": False,
            "current": None, "redirect_host": None, "cloaked": False}


def artifact_findings(records: Iterable[netindex.Record],
                      grace_starts: str = GRACE_STARTS) -> "list[netindex.Finding]":
    """NI022: a listing approved after the rule shipped must carry the artifact.

    Offline, so it can only read what ``verify.py --stamp`` wrote into the record: the
    well-known method, or ``provenance.fingerprint.artifact`` (which names the form
    that was seen). A record validated before ``grace_starts`` is a pre-existing listing
    and is covered by the re-check's grace period instead, not by this rule.
    """
    out: "list[netindex.Finding]" = []
    try:
        start = dt.date.fromisoformat(grace_starts)
    except ValueError:
        return out
    for r in records:
        if artifact.exempt_reason(r.kind, r.url):
            continue
        val = r.provenance.get("validated") or {}
        try:
            approved = dt.date.fromisoformat(str(val.get("at") or "")[:10])
        except ValueError:
            continue
        if approved < start:
            continue
        fp = r.provenance.get("fingerprint") or {}
        if val.get("method") == "well-known" or fp.get("artifact"):
            continue
        out.append(netindex.Finding(
            ARTIFACT_RULE, r.id,
            "approved without a backlink artifact: serve "
            "/.well-known/aithernet.json or put a link back, then verify --stamp"))
    return out


def state_findings(state: dict, records: Iterable[netindex.Record]) -> "list[netindex.Finding]":
    """NI020/NI021: the health state is machine-written, but a bad commit must be caught.

    An entry for a record that is gone is *not* a finding: the daily job prunes it, and
    a delist PR must not turn main red before that run. A baseline that no longer
    matches the approved fingerprint on the record (and was not explicitly accepted) is
    a finding, so a state-only commit cannot quietly re-seed content drift.
    """
    out: "list[netindex.Finding]" = []
    known = {r.id: r for r in records}
    entries = state.get("entries")
    if not isinstance(entries, dict):
        return [netindex.Finding(STATE_RULE, "state/health.json", "entries must be an object")]
    if state.get("version") not in (1, STATE_VERSION):
        out.append(netindex.Finding(STATE_RULE, "state/health.json",
                                    f"version must be {STATE_VERSION}"))
    try:
        dt.date.fromisoformat(str(state.get("grace_starts")))
    except ValueError:
        out.append(netindex.Finding(STATE_RULE, "state/health.json",
                                    "grace_starts must be YYYY-MM-DD"))
    gd = state.get("grace_days")
    if not isinstance(gd, int) or isinstance(gd, bool) or gd < 0:
        out.append(netindex.Finding(STATE_RULE, "state/health.json",
                                    "grace_days must be a non-negative integer"))
    for rid, entry in entries.items():
        if rid not in known:
            continue                       # pruned by the next run; never a red build
        if not isinstance(entry, dict):
            out.append(netindex.Finding(STATE_RULE, rid, "state entry must be an object"))
            continue
        if entry.get("status") not in STATUSES:
            out.append(netindex.Finding(STATE_RULE, rid,
                                        f"status {entry.get('status')!r} not in {list(STATUSES)}"))
        for key in ("consecutive_failures", "artifact_missing_days"):
            val = entry.get(key, 0)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                out.append(netindex.Finding(STATE_RULE, rid,
                                            f"{key} must be a non-negative integer"))
        if entry.get("failures") is not None and not isinstance(entry["failures"], list):
            out.append(netindex.Finding(STATE_RULE, rid, "failures must be a list"))
        recent = entry.get("recent")
        if recent is not None and not isinstance(recent, list):
            out.append(netindex.Finding(STATE_RULE, rid, "recent must be a list"))
        base = entry.get("baseline")
        if base is not None:
            if not isinstance(base, dict) or not isinstance(base.get("signature"), list):
                out.append(netindex.Finding(STATE_RULE, rid, "baseline must carry a signature"))
                continue
            out.extend(_baseline_findings(rid, entry, base, known[rid]))
        elif entry.get("last_checked") and entry.get("baseline_expected", True):
            out.append(netindex.Finding(STATE_RULE, rid,
                                        "checked entry has no baseline fingerprint"))
    return out


def _baseline_findings(rid: str, entry: dict, base: dict,
                       rec: netindex.Record) -> "list[netindex.Finding]":
    """NI021: is this baseline the one the record was approved with?"""
    out: "list[netindex.Finding]" = []
    source = entry.get("baseline_source")
    if source not in (None, "record", "seeded", "accepted"):
        out.append(netindex.Finding(BASELINE_RULE, rid,
                                    f"baseline_source {source!r} is not a known origin"))
    if source == "accepted" and not entry.get("accepted_at"):
        out.append(netindex.Finding(BASELINE_RULE, rid,
                                    "an accepted baseline must carry accepted_at"))
    stamp = (rec.provenance.get("fingerprint") or {})
    if isinstance(stamp.get("signature"), list) and source != "accepted":
        if base.get("signature") != stamp["signature"]:
            out.append(netindex.Finding(
                BASELINE_RULE, rid,
                "baseline does not match the fingerprint recorded when the entry was "
                "approved; a maintainer must re-seed it with --accept"))
    return out


# --------------------------------------------------------------------- observation

def in_grace(entry: dict, cfg: dict) -> bool:
    """True while a pre-existing record may still be growing its first backlink.

    Grace is for listings that were approved *before* this mechanism shipped. A record
    validated on or after ``grace_starts`` — and any listing whose approval date is
    unknown — gets no grace: a new listing without its artifact is not approved.
    """
    if entry.get("artifact"):
        return False
    approved = entry.get("validated_at")
    if not approved:
        return False
    try:
        approved_at = dt.date.fromisoformat(str(approved)[:10])
        start = dt.date.fromisoformat(str(cfg.get("grace_starts") or GRACE_STARTS))
    except ValueError:
        return False
    if approved_at >= start:
        return False
    return cfg["today"] <= grace_end(cfg)


def grace_end(cfg: dict) -> dt.date:
    start = dt.date.fromisoformat(str(cfg.get("grace_starts") or GRACE_STARTS))
    return start + dt.timedelta(days=int(cfg.get("grace_days", GRACE_DAYS)))


def observe(rec: netindex.Record, *, timeout: float = 15, at: Optional[dt.date] = None,
            fetch_fn: Optional[Callable] = None) -> dict:
    """One network look at one record. Never raises; a broken site is data.

    The page is fetched twice, once as a browser and once as the checker. A site that
    serves the approved page and its backlink only to the checker (UA-keyed cloaking)
    is a listed page nobody else sees, so a material difference is a failure.
    """
    fetch_fn = fetch_fn or artifact.fetch
    at = at or dt.date.today()
    exempt = artifact.exempt_reason(rec.kind, rec.url)
    obs = {"id": rec.id, "at": at.isoformat(), "reachable": False, "status_code": 0,
           "final_host": "", "artifact": None, "artifact_reason": "",
           "fingerprint": None, "redirect_host": "", "cloaked": False,
           "error": "", "exempt": bool(exempt), "exempt_reason": exempt, "skip": ""}
    if obs["exempt"]:
        obs["artifact_reason"] = exempt
        return obs
    if not rec.url:
        obs["skip"] = "no url"
        return obs
    if not rec.url.startswith("https://"):
        obs["error"] = "url is not https"
        return obs
    page = fetch_fn(rec.url, timeout=timeout)           # browser User-Agent
    obs["status_code"] = page.status
    obs["final_host"] = artifact.host_of(page.final_url or rec.url)
    obs["reachable"] = page.ok
    if not page.ok:
        obs["error"] = page.error or f"HTTP {page.status}"
        return obs
    claimed: "list[str]" = []
    if obs["final_host"]:
        wk = fetch_fn(f"https://{obs['final_host']}/.well-known/aithernet.json",
                      timeout=timeout, limit=65536)
        if wk.ok:
            claimed = artifact.claimed_ids(wk.body)
    art = artifact.detect(rec.id, page.body, claimed)
    obs["artifact"], obs["artifact_reason"] = art.form, art.reason
    fp = fingerprint.page(page.body, obs["final_host"])
    obs["fingerprint"] = fp
    obs["redirect_host"] = fp.get("redirect_host") or ""
    # Same URL, the checker's own User-Agent. Only a material difference is cloaking:
    # exact hashes differ on any dynamic page (nonces, "posted 3 minutes ago"), so this
    # compares the artifact form and content similarity instead.
    try:
        alt = fetch_fn(rec.url, timeout=timeout, ua=artifact.CHECKER_UA)
    except TypeError:       # an injected fetcher that predates the ua argument
        alt = None
    if alt is not None and alt.ok:
        alt_host = artifact.host_of(alt.final_url or rec.url)
        alt_fp = fingerprint.page(alt.body, alt_host)
        alt_art = artifact.detect(rec.id, alt.body, claimed)
        if alt_art.form != art.form:
            obs["cloaked"] = True
        elif (fp.get("tokens", 0) == 0) != (alt_fp.get("tokens", 0) == 0):
            obs["cloaked"] = True
        elif fp.get("tokens", 0) and alt_fp.get("tokens", 0):
            sim = fingerprint.jaccard(fp.get("signature") or [],
                                      alt_fp.get("signature") or [])
            if sim < CLOAK_SIMILARITY:
                obs["cloaked"] = True
        elif (fp.get("tokens", 0) == 0 and alt_fp.get("tokens", 0) == 0
              and fp.get("media_sha") != alt_fp.get("media_sha")):
            obs["cloaked"] = True
        if obs["cloaked"]:
            obs["artifact_reason"] = (obs["artifact_reason"]
                                      + "; page differs by User-Agent").strip("; ")
    return obs


# ------------------------------------------------------------------- state machine

def failures_for(entry: dict, obs: dict, cfg: dict) -> "list[dict]":
    """Every reason this observation fails, in a stable order. Empty = a clean check."""
    out: "list[dict]" = []
    if obs.get("exempt") or obs.get("skip"):
        return out
    if not obs.get("reachable"):
        out.append({"code": UNREACHABLE, "detail": obs.get("error") or "no answer"})
    elif not obs.get("artifact"):
        if not in_grace(entry, cfg):
            out.append({"code": ARTIFACT_MISSING,
                        "detail": obs.get("artifact_reason") or "no backlink found"})
    if obs.get("cloaked"):
        out.append({"code": CLOAKING,
                    "detail": "the page served to the checker differs from the browser view"})
    base, cur = entry.get("baseline"), obs.get("fingerprint")
    if obs.get("reachable") and cur:
        if base:
            kind, sim = fingerprint.drift(base, cur)
            if kind in NEEDS_REVIEW:
                out.append({"code": kind, "detail": f"similarity {sim:.2f}"})
        else:
            # No baseline yet. A client-side redirect to another host still fails now.
            redirect = (cur.get("redirect_host") or "").lower()
            host = (obs.get("final_host") or "").lower()
            if redirect and host and redirect != host:
                out.append({"code": HOST_CHANGED,
                            "detail": f"client-side redirect to {redirect}"})
        if (not base and (entry.get("ever_ok") or entry.get("last_ok"))
                and entry.get("baseline_expected", True)):
            out.append({"code": BASELINE_MISSING,
                        "detail": "the approved fingerprint is missing from the state file"})
    return out


def _as_date(value: object) -> Optional[dt.date]:
    try:
        return dt.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def advance(prev: dict, obs: dict, cfg: dict) -> dict:
    """The state machine. Pure: same inputs, same entry out.

    Rules
    -----
    * a clean check returns the entry to ``active`` from any status, provided the
      trailing window is no longer mostly failures (a flapping site cannot buy its way
      back with one good day);
    * the first failure of an active entry makes it ``warn``;
    * ``SUSPEND_AFTER`` failures within ``SUSPEND_WINDOW_DAYS``, or that many missing
      artifact days, or a final host change / UA cloaking (immediately) suspends it;
    * ``DELIST_AFTER_DAYS`` days suspended makes it ``delisted``;
    * ``suspended``/``delisted`` never recover on a failing check;
    * failures are remembered in ``recent`` and never reset by a single clean day.
    """
    prev = prev or {}
    e = copy.deepcopy(new_entry())
    e.update(copy.deepcopy(prev))
    today = cfg["today"]

    if obs.get("exempt"):
        e["last_checked"] = obs.get("at") or today.isoformat()
        e["exempt"] = True
        e["failures"] = []
        e["artifact"] = e.get("artifact")
        e["current"] = obs.get("fingerprint") or e.get("current")
        e["_note"] = f"{obs.get('exempt_reason') or 'exempt'}, not by the backlink rule"
        return e
    e.pop("exempt", None)

    if obs.get("skip"):
        e["last_checked"] = obs.get("at") or today.isoformat()
        e["_note"] = f"not checkable: {obs['skip']}"
        e["current"] = obs.get("fingerprint") or e.get("current")
        return e

    # failures_for reads last_checked to tell "a baseline was removed from a checked
    # entry" apart from "this entry has never been checked", so it runs before we
    # stamp the new date.
    failures = failures_for(e, obs, cfg)
    e["last_checked"] = obs.get("at") or today.isoformat()
    codes = [f["code"] for f in failures]
    e["failures"] = failures
    if obs.get("artifact"):
        e["artifact"] = obs["artifact"]
    if obs.get("artifact_reason"):
        e["artifact_reason"] = obs["artifact_reason"]
    e["cloaked"] = bool(obs.get("cloaked"))

    # A rolling record of daily outcomes, bounded by date. The counters the state file
    # publishes are derived from it, so one clean day cannot erase yesterday's failure.
    recent = [r for r in (e.get("recent") or [])
              if isinstance(r, dict) and _as_date(r.get("at")) is not None]
    recent.append({"at": today.isoformat(), "failed": bool(failures),
                   "codes": sorted(set(codes))})
    cutoff = today - dt.timedelta(days=HISTORY_DAYS)
    recent = [r for r in recent if _as_date(r["at"]) >= cutoff][-120:]
    e["recent"] = recent
    window_start = today - dt.timedelta(days=SUSPEND_WINDOW_DAYS - 1)
    in_window = [r for r in recent if _as_date(r["at"]) >= window_start]
    consecutive = 0
    for r in reversed(recent):
        if not r.get("failed"):
            break
        consecutive += 1
    window_fails = sum(1 for r in in_window if r.get("failed"))
    missing_in_window = sum(1 for r in in_window
                            if ARTIFACT_MISSING in (r.get("codes") or []))
    e["consecutive_failures"] = consecutive
    e["artifact_missing_days"] = sum(
        1 for r in recent if ARTIFACT_MISSING in (r.get("codes") or []))

    if obs.get("fingerprint"):
        e["current"] = obs["fingerprint"]
        e["redirect_host"] = obs.get("redirect_host") or e.get("redirect_host")
        # Seed only on the first *successful* look. A baseline that disappeared from an
        # entry that was trusted before is a baseline-missing failure, never an
        # invitation to trust whatever the live page says today.
        if not e.get("baseline") and not e.get("ever_ok") and obs.get("reachable"):
            e["baseline"] = obs["fingerprint"]
            e["baseline_source"] = "seeded"
            e["seeded_at"] = today.isoformat()
        if obs.get("reachable"):
            e["ever_ok"] = True
    if obs.get("reachable") and not failures:
        e["last_ok"] = e["last_checked"]

    prev_status = e.get("status") or "active"
    if not failures:
        if prev_status in ("suspended", "delisted") and window_fails >= SUSPEND_AFTER:
            status = prev_status          # still flapping: one good day is not recovery
        else:
            status, e["suspended_since"] = "active", None
    elif prev_status in ("suspended", "delisted"):
        status = prev_status
    elif (HOST_CHANGED in codes or CLOAKING in codes or consecutive >= SUSPEND_AFTER
          or window_fails >= SUSPEND_AFTER or missing_in_window >= SUSPEND_AFTER):
        status = "suspended"
    else:
        status = "warn"

    if status == "suspended":
        if not e.get("suspended_since"):
            e["suspended_since"] = today.isoformat()
        elif (today - dt.date.fromisoformat(str(e["suspended_since"]))).days >= DELIST_AFTER_DAYS:
            status = "delisted"

    if status != prev_status or not e.get("since"):
        e["since"] = today.isoformat()
    e["status"] = status
    if (not obs.get("artifact") and not obs.get("exempt") and obs.get("reachable")
            and not failures and in_grace(e, cfg)):
        e["_note"] = f"no backlink yet (grace until {grace_end(cfg)})"
    return e


# ------------------------------------------------------------------------- issues

def plan_issues(transitions: "list[dict]", open_issues: "list[dict]") -> "list[dict]":
    """Decide which entries need an issue opened, updated or closed. Pure function.

    One issue per entry: a transition to suspended/delisted, or a needs-review change,
    wants an issue; an entry that passed again wants its issue closed. Everything else
    does nothing, so a stable warn on an unreachable site does not spam the tracker.
    """
    by_id = {}
    for issue in open_issues or []:
        title = str(issue.get("title", ""))
        if not title.startswith(ISSUE_PREFIX):
            continue
        rest = title[len(ISSUE_PREFIX):].strip()
        rid = rest.split(ISSUE_SEP, 1)[0].strip()
        if rid:
            by_id[rid] = issue
    out: "list[dict]" = []
    for t in transitions or []:
        rid = t.get("id")
        if not rid:
            continue
        codes = set(t.get("codes") or [])
        to = t.get("to")
        wants = to in ("suspended", "delisted") or bool(codes & ISSUE_CODES)
        existing = by_id.get(rid)
        if wants:
            out.append({"id": rid, "action": "update" if existing else "open",
                        "number": (existing or {}).get("number"), "to": to,
                        "codes": sorted(codes), "reasons": t.get("reasons") or []})
        elif to == "active" and existing:
            out.append({"id": rid, "action": "close",
                        "number": existing.get("number"), "to": to,
                        "codes": sorted(codes), "reasons": t.get("reasons") or []})
    return out


def issue_body(entry: dict) -> str:
    e = entry or {}
    reasons = "\n".join(f"- `{f.get('code')}`: {f.get('detail')}" for f in
                        (e.get("failures") or [])) or "- (none recorded)"
    art = e.get("artifact") or "none"
    return (
        f"**Status:** `{e.get('status')}` since `{e.get('since')}`\n"
        f"**Last checked:** `{e.get('last_checked')}` (last clean: `{e.get('last_ok')}`)\n"
        f"**Backlink artifact:** `{art}` — {e.get('artifact_reason') or 'n/a'}\n\n"
        f"### Why this was raised\n{reasons}\n\n"
        "### What the owner can do\n"
        "1. Serve the artifact: `https://<host>/.well-known/aithernet.json` containing "
        "`{\"records\": [\"<id>\"]}` (owner proof, keeps the owner-proven tier), **or** add a "
        "link back on the listed page: "
        "`<link rel=\"aithernet\" href=\"https://index.aitherium.com/r/<id>\">`, "
        "`<meta name=\"aithernet\" content=\"<id>\">`, or a visible link to "
        "`https://index.aitherium.com/r/<id>`.\n"
        "2. If the page simply moved or was rebuilt, open a PR that updates `url` "
        "(a maintainer re-seeds the fingerprint with `python recheck.py --accept <id>`).\n\n"
        "The entry returns to `active` on a clean daily check once the trailing week is "
        "no longer mostly failures, and this issue is closed automatically. Nothing is "
        "deleted; a delisted entry keeps its record and its page, with the reason."
    )


def run_gh(args: "list[str]") -> "tuple[int, str]":
    """Thin wrapper so the issue plumbing is one call site, and injectable in tests."""
    proc = subprocess.run(["gh", *args], capture_output=True, text=True,
                          encoding="utf-8", timeout=120)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def apply_issues(actions: "list[dict]", entries: dict, repo: str = "",
                 gh: Callable = run_gh) -> int:
    """Carry out plan_issues' decisions through the gh CLI. Returns an exit code."""
    failed = 0
    actions = list(actions or [])
    if any(a.get("action") == "open" for a in actions):
        # gh issue create fails if the label does not exist yet. Creating it once is
        # idempotent in practice: an existing label returns non-zero and is ignored.
        gh(["label", "create", ISSUE_LABEL, "--color", "B60205",
            "--description", "Daily re-check: the entry needs a human"])
    for a in actions:
        rid, action = a.get("id"), a.get("action")
        title = f"{ISSUE_PREFIX} {rid}{ISSUE_SEP}{a.get('to')}"
        body = issue_body(entries.get(rid) or a)
        if action == "open":
            code, out = gh(["issue", "create", "--title", title, "--body", body,
                            "--label", ISSUE_LABEL])
        elif action == "update":
            num = str(a.get("number") or "")
            code, out = gh(["issue", "comment", num, "--body", body])
            if code == 0:
                code, out = gh(["issue", "edit", num, "--title", title])
        elif action == "close":
            num = str(a.get("number") or "")
            code, out = gh(["issue", "comment", num, "--body",
                            "Back to `active`: the daily re-check passed. Closing."])
            if code == 0:
                code, out = gh(["issue", "close", num])
        else:
            continue
        if code != 0:
            failed += 1
            print(f"issue {action} failed for {rid}: {out.strip()[:300]}", file=sys.stderr)
        else:
            print(f"issue {action}: {rid}")
    return 1 if failed else 0


# ---------------------------------------------------------------------------- run

def _table(entries: dict, records: dict) -> str:
    head = ("ID", "KIND", "STATUS", "ARTIFACT", "HOST", "CHECKED", "NOTE")
    rows = []
    order = {"delisted": 0, "suspended": 1, "warn": 2, "active": 3}
    for rid in sorted(entries, key=lambda i: (order.get(entries[i].get("status"), 9), i)):
        e, rec = entries[rid], records.get(rid)
        note = "; ".join(f"{f['code']}: {f['detail']}" for f in e.get("failures") or [])
        if not note:
            note = e.get("_note") or "-"
        rows.append((rid, rec.kind if rec else "?", e.get("status") or "?",
                     e.get("artifact") or ("exempt" if e.get("exempt") else "-"),
                     (e.get("current") or {}).get("host") or "-",
                     e.get("last_checked") or "-", note))
    widths = [max(len(str(r[i])) for r in [head] + rows) for i in range(len(head))]
    widths[-1] = max(widths[-1], 4)

    def line(r):  # noqa: E306
        return "  ".join(str(c)[:widths[i]].ljust(widths[i]) for i, c in enumerate(r)).rstrip()

    return "\n".join([line(head), line(tuple("-" * w for w in widths))] +
                     [line(r) for r in rows])


def run(root: Path = netindex.DEFAULT_ROOT, state_path: Path = DEFAULT_STATE, *,
        workers: int = 6, timeout: float = 15, today: Optional[dt.date] = None,
        ids: Optional["list[str]"] = None, limit: Optional[int] = None,
        write: bool = True, fetch_fn: Optional[Callable] = None,
        accept: "tuple[str, ...]" = ()) -> dict:
    """Re-check every record. Returns the run summary; writes state unless disabled."""
    today = today or dt.date.today()
    records, _ = netindex.load(root)
    if ids:
        wanted = set(ids)
        records = [r for r in records if r.id in wanted]
    if limit:
        records = records[:limit]
    if not records:
        return {"records": 0, "entries": {}, "transitions": [], "error": "no records"}
    by_id = {r.id: r for r in records}
    state = load_state(state_path)
    entries = state["entries"]
    cfg = {"today": today, "grace_days": state["grace_days"],
           "grace_starts": state["grace_starts"]}
    observations: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(observe, rec, timeout=timeout, at=today,
                               fetch_fn=fetch_fn): rec.id for rec in records}
        for fut in concurrent.futures.as_completed(futures):
            obs = fut.result()
            observations[obs["id"]] = obs
    transitions = []
    for rec in records:
        prev = entries.get(rec.id) or new_entry()
        validated_at = (rec.provenance.get("validated") or {}).get("at")
        if validated_at:
            prev["validated_at"] = str(validated_at)[:10]
        prev["baseline_expected"] = bool(rec.url) and not artifact.exempt_reason(
            rec.kind, rec.url)
        if not prev.get("baseline"):
            # A fingerprint stamped at listing time (verify.py --stamp) is the baseline:
            # the page cannot be swapped between approval and the first daily check.
            stamped = (rec.provenance or {}).get("fingerprint")
            if isinstance(stamped, dict) and isinstance(stamped.get("signature"), list):
                prev["baseline"] = {k: stamped.get(k) for k in
                                    ("title", "description", "host", "signature",
                                     "tokens", "bloom", "assets_sha", "redirect_host")}
                prev["baseline_source"] = "record"
        before = prev.get("status") or "active"
        e = advance(prev, observations[rec.id], cfg)
        if rec.id in accept and observations[rec.id].get("fingerprint"):
            # A maintainer accepted the new page: re-seed the baseline, and clear a
            # needs-review state that existed only because the page had changed.
            e["baseline"] = observations[rec.id]["fingerprint"]
            e["baseline_source"] = "accepted"
            e["accepted_at"] = today.isoformat()
            e["seeded_at"] = today.isoformat()
            e["failures"] = [f for f in e.get("failures", [])
                             if f["code"] not in NEEDS_REVIEW]
            if not e["failures"]:
                e.update(status="active", consecutive_failures=0, suspended_since=None)
        entries[rec.id] = e
        previous_codes = {f.get("code") for f in prev.get("failures") or []}
        if e.get("status") != before:
            transitions.append({
                "id": rec.id, "from": before, "to": e.get("status"),
                "codes": [f["code"] for f in e.get("failures") or []],
                "reasons": [f"{f['code']}: {f['detail']}" for f in e.get("failures") or []]})
        elif e.get("failures") and not previous_codes & ISSUE_CODES:
            # First time this standing failure becomes issue-worthy (e.g. a host change
            # while already warned): record it, but only when the signal is new.
            new_codes = {f["code"] for f in e["failures"]} & ISSUE_CODES
            if new_codes:
                transitions.append({
                    "id": rec.id, "from": before, "to": e.get("status"),
                    "codes": sorted(new_codes),
                    "reasons": [f"{f['code']}: {f['detail']}" for f in e["failures"]
                                if f["code"] in new_codes]})
    # A record removed from git (a delist PR) must not keep main red until someone
    # hand-edits the state: prune its entry here. The state file only describes the
    # records this checkout has.
    orphans = sorted(set(entries) - set(by_id))
    for rid in orphans:
        entries.pop(rid, None)
    if write:
        state["updated"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_state(state, state_path)
    return {"records": len(records), "entries": entries, "transitions": transitions,
            "table": _table({r.id: entries[r.id] for r in records}, by_id),
            "orphans": orphans}


def _summary(entries: dict) -> str:
    counts = {s: 0 for s in STATUSES}
    exempt = skipped = 0
    for e in entries.values():
        counts[e.get("status", "active")] = counts.get(e.get("status", "active"), 0) + 1
        exempt += 1 if e.get("exempt") else 0
        skipped += 1 if str(e.get("_note", "")).startswith("not checkable") else 0
    parts = " ".join(f"{k} {v}" for k, v in counts.items())
    return f"recheck: {len(entries)} entries ({parts}; exempt {exempt}, not-checkable {skipped})"


def main(argv: Optional["list[str]"] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--state", type=Path, default=DEFAULT_STATE)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--today", help="YYYY-MM-DD, for a reproducible run")
    ap.add_argument("--dry-run", action="store_true", help="print the table, write nothing")
    ap.add_argument("--accept", nargs="*", default=[], help="re-seed these fingerprints")
    ap.add_argument("--json-out", type=Path, help="write the run summary here")
    ap.add_argument("--plan-issues", nargs=2, metavar=("RUN_JSON", "OPEN_ISSUES_JSON"))
    ap.add_argument("--apply-issues", type=Path, metavar="ACTIONS_JSON")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)

    if a.self_test:
        return self_test()
    if a.plan_issues:
        run_json, issues_json = a.plan_issues
        summary = json.loads(Path(run_json).read_text(encoding="utf-8"))
        issues = json.loads(Path(issues_json).read_text(encoding="utf-8"))
        plan = plan_issues(summary.get("transitions") or [], issues or [])
        print(json.dumps(plan, indent=1))
        return 0
    if a.apply_issues:
        actions = json.loads(Path(a.apply_issues).read_text(encoding="utf-8"))
        entries = load_state(a.state)["entries"]
        return apply_issues(actions, entries)

    result = run(a.root, a.state, workers=a.workers, timeout=a.timeout,
                 today=_today(a.today) if a.today else None, ids=a.ids, limit=a.limit,
                 write=not a.dry_run, accept=tuple(a.accept or ()))
    if result.get("error"):
        print(f"could not re-check: {result['error']}")
        return 2
    print(result["table"])
    print(_summary(result["entries"]))
    if result["transitions"]:
        print("\ntransitions:")
        for t in result["transitions"]:
            print(f"  {t['id']}: {t['from']} -> {t['to']}"
                  + (f" ({'; '.join(t['reasons'])})" if t.get("reasons") else ""))
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(
            {"records": result["records"], "transitions": result["transitions"]},
            indent=1) + "\n", encoding="utf-8")
    if a.dry_run:
        print("\n(dry run: state not written)")
    return 0


# ------------------------------------------------------------------------ self-test

def self_test() -> int:
    ok = True

    def check(label, got, want):
        nonlocal ok
        passed = got == want
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'} {label}: want {want} got {got}")

    day = dt.date(2026, 11, 18)
    cfg = {"today": day, "grace_days": GRACE_DAYS, "grace_starts": GRACE_STARTS}
    sig_a = fingerprint.signature(fingerprint.tokens("alpha beta gamma delta epsilon zeta"))
    sig_b = fingerprint.signature(fingerprint.tokens("one two three four five six seven eight"))
    fp_a = {"title": "a", "description": "", "host": "a.example", "signature": sig_a,
            "tokens": 6, "bloom": fingerprint.bloom(fingerprint.tokens("alpha beta gamma delta epsilon zeta"))}
    fp_b = {"title": "b", "description": "", "host": "a.example", "signature": sig_b,
            "tokens": 8, "bloom": fingerprint.bloom(fingerprint.tokens("one two three four five six seven eight"))}
    normal = {"reachable": True, "artifact": "well-known", "artifact_reason": "",
              "fingerprint": fp_a, "error": ""}
    old_listing = {**new_entry(), "validated_at": "2026-11-01"}

    # every transition, incl. grace and recovery
    e = advance(new_entry(), normal, cfg)
    check("clean -> active", e["status"], "active")
    warn = advance(e, {**normal, "reachable": False, "error": "HTTP 503"}, cfg)
    check("first failure -> warn", warn["status"], "warn")
    sus = advance(advance(warn, {**normal, "reachable": False}, cfg),
                  {**normal, "reachable": False}, cfg)
    check("third failure -> suspended", sus["status"], "suspended")
    check("suspended_since set", bool(sus["suspended_since"]), True)
    late = dict(cfg, today=day + dt.timedelta(days=DELIST_AFTER_DAYS))
    dl = advance(sus, {**normal, "reachable": False}, late)
    check("14 days suspended -> delisted", dl["status"], "delisted")
    back = advance(dl, normal, late)
    check("recovery -> active", back["status"], "active")
    check("recovery clears suspended_since", back["suspended_since"], None)

    # flapping: down, down, up, forever. Never 3 consecutive failures, but the window
    # must still suspend it, and one good day must not return it to the listing.
    flap = new_entry()
    seen = []
    for i in range(30):
        o = {**normal, "reachable": i % 3 != 2, "error": "", "fingerprint": fp_a if i % 3 == 2 else None}
        flap = advance(flap, o, {**cfg, "today": day + dt.timedelta(days=i)})
        seen.append(flap["status"])
    check("flapping reaches suspended", "suspended" in seen, True)
    check("flapping never leaves it active at the end", flap["status"] in ("suspended", "delisted"), True)
    # A genuine recovery, once the dirty window ages out, returns to active.
    fixed = flap
    for i in range(30, 40):
        fixed = advance(fixed, normal, {**cfg, "today": day + dt.timedelta(days=i)})
    check("a real recovery returns to active", fixed["status"], "active")

    # artifact missing: grace for a pre-existing record, none for a new listing
    no_art = {**normal, "artifact": None, "artifact_reason": "no backlink found"}
    g = advance(old_listing, no_art, cfg)
    check("missing artifact inside grace -> active", g["status"], "active")
    new_listing = {**new_entry(), "validated_at": "2026-11-18"}
    n = advance(new_listing, no_art, cfg)
    check("new listing without an artifact -> warn", n["status"], "warn")
    late2 = {"today": dt.date(2026, 12, 25), "grace_days": GRACE_DAYS,
             "grace_starts": GRACE_STARTS}
    post = advance(old_listing, no_art, late2)
    check("missing artifact after grace -> warn", post["status"], "warn")
    had = advance({**new_entry(), "artifact": "meta", "validated_at": "2026-11-01"},
                  no_art, cfg)
    check("lost a known artifact -> warn", had["status"], "warn")

    # fingerprint drift and host change
    drift = advance({**new_entry(), "baseline": fp_a}, {**normal, "fingerprint": fp_b}, cfg)
    check("big text change -> warn", drift["status"], "warn")
    check("big text change code", [f["code"] for f in drift["failures"]], ["content-changed"])
    moved = advance({**new_entry(), "baseline": fp_a},
                    {**normal, "fingerprint": {**fp_a, "host": "b.example"}}, cfg)
    check("final host change -> suspended", moved["status"], "suspended")
    tuned = advance({**new_entry(), "baseline": fp_a},
                    {**normal, "fingerprint": {**fp_a, "title": "renamed"}}, cfg)
    check("title-only edit -> active", tuned["status"], "active")
    redir = advance({**new_entry(), "baseline": fp_a},
                    {**normal, "fingerprint": {**fp_a, "redirect_host": "casino.example"}}, cfg)
    check("client-side redirect to another host -> suspended", redir["status"], "suspended")

    # a cleared baseline on a checked entry is a needs-review failure, not a re-seed
    cleared = advance({**new_entry(), "last_checked": "2026-11-17", "ever_ok": True,
                       "last_ok": "2026-11-17", "baseline_source": "seeded"}, normal, cfg)
    check("cleared baseline -> needs review", [f["code"] for f in cleared["failures"]],
          ["baseline-missing"])
    check("cleared baseline is not silently re-seeded", cleared["baseline"], None)

    # cloaking by User-Agent
    cloak = advance(new_entry(), {**normal, "cloaked": True}, cfg)
    check("UA cloaking -> suspended", cloak["status"], "suspended")

    # exempt and not-checkable records never fail
    exc = advance(new_entry(), {"exempt": True, "at": day.isoformat()}, cfg)
    check("exempt stays active", exc["status"], "active")
    nk = advance(new_entry(), {"skip": "no url", "at": day.isoformat()}, cfg)
    check("no-url stays active", nk["status"], "active")

    # the issue decision
    tr = [{"id": "a", "from": "active", "to": "warn", "codes": ["host-changed"]},
          {"id": "b", "from": "active", "to": "warn", "codes": [UNREACHABLE]},
          {"id": "c", "from": "active", "to": "suspended", "codes": [UNREACHABLE]},
          {"id": "d", "from": "suspended", "to": "active", "codes": []}]
    opened = plan_issues(tr, [])
    check("issues planned", [(x["id"], x["action"]) for x in opened],
          [("a", "open"), ("c", "open")])
    upd = plan_issues(tr, [{"number": 7, "title": f"{ISSUE_PREFIX} a{ISSUE_SEP}warn"}])
    check("existing issue updated", [(x["id"], x["action"], x["number"]) for x in upd],
          [("a", "update", 7), ("c", "open", None)])
    closed = plan_issues(tr, [{"number": 9, "title": f"{ISSUE_PREFIX} d{ISSUE_SEP}suspended"}])
    check("recovered closes", [(x["id"], x["action"]) for x in closed],
          [("a", "open"), ("c", "open"), ("d", "close")])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
