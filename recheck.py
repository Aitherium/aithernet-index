#!/usr/bin/env python3
"""Re-check every listed site, every day, and act on what changed.

A listing is an approval of a page at a moment. This is the thing that keeps that
approval honest after the moment has passed: it re-visits every record, asks whether
the required backlink artifact is still there and whether the page still *is* the page
that was approved (fingerprint, see ``fingerprint.py``), and moves the entry through a
state machine kept in ``state/health.json`` — never in the records themselves, so a
record stays exactly what a human last reviewed.

    active --(first failure)--> warn
    warn --(3 consecutive failures, or the final host changed)--> suspended
    suspended --(14 days)--> delisted
    anything --(a clean check)--> active

Failures are: the URL does not answer, the required backlink is gone (after the grace
period for pre-existing records), the page now redirects to a different host, or the
visible text changed beyond the similarity threshold.

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
STATE_VERSION = 1

# The day this mechanism ships. Records listed before it get GRACE_DAYS to grow a
# backlink before the artifact rule starts counting against them.
GRACE_STARTS = "2026-11-18"
GRACE_DAYS = 30
SUSPEND_AFTER = 3          # consecutive failing daily checks
DELIST_AFTER_DAYS = 14     # days suspended before the listing is hidden

# Failure codes. NEEDS_REVIEW ones mean "a human must look before this is trusted again".
UNREACHABLE = "unreachable"
ARTIFACT_MISSING = "artifact-missing"
HOST_CHANGED = "host-changed"
CONTENT_CHANGED = "content-changed"
NEEDS_REVIEW = {HOST_CHANGED, CONTENT_CHANGED}
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
            "artifact": None, "artifact_reason": "", "failures": [],
            "baseline": None, "current": None}


def state_findings(state: dict, records: Iterable[netindex.Record]) -> "list[netindex.Finding]":
    """NI011: the health state is machine-written, but a bad commit must still be caught."""
    out: "list[netindex.Finding]" = []
    known = {r.id for r in records}
    entries = state.get("entries")
    if not isinstance(entries, dict):
        return [netindex.Finding("NI011", "state/health.json", "entries must be an object")]
    if state.get("version") != STATE_VERSION:
        out.append(netindex.Finding("NI011", "state/health.json",
                                    f"version must be {STATE_VERSION}"))
    try:
        dt.date.fromisoformat(str(state.get("grace_starts")))
    except ValueError:
        out.append(netindex.Finding("NI011", "state/health.json",
                                    "grace_starts must be YYYY-MM-DD"))
    gd = state.get("grace_days")
    if not isinstance(gd, int) or isinstance(gd, bool) or gd < 0:
        out.append(netindex.Finding("NI011", "state/health.json",
                                    "grace_days must be a non-negative integer"))
    for rid, entry in entries.items():
        if rid not in known:
            out.append(netindex.Finding("NI011", rid,
                                        "state entry for a record that does not exist"))
            continue
        if not isinstance(entry, dict):
            out.append(netindex.Finding("NI011", rid, "state entry must be an object"))
            continue
        if entry.get("status") not in STATUSES:
            out.append(netindex.Finding("NI011", rid,
                                        f"status {entry.get('status')!r} not in {list(STATUSES)}"))
        for key in ("consecutive_failures", "artifact_missing_days"):
            val = entry.get(key, 0)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                out.append(netindex.Finding("NI011", rid, f"{key} must be a non-negative integer"))
        if entry.get("failures") is not None and not isinstance(entry["failures"], list):
            out.append(netindex.Finding("NI011", rid, "failures must be a list"))
        base = entry.get("baseline")
        if base is not None and (not isinstance(base, dict)
                                 or not isinstance(base.get("signature"), list)):
            out.append(netindex.Finding("NI011", rid, "baseline must carry a signature"))
    return out


# --------------------------------------------------------------------- observation

def in_grace(entry: dict, cfg: dict) -> bool:
    """True while a pre-existing record may still be growing its first backlink."""
    if entry.get("artifact"):
        return False
    return cfg["today"] <= grace_end(cfg)


def grace_end(cfg: dict) -> dt.date:
    start = dt.date.fromisoformat(str(cfg.get("grace_starts") or GRACE_STARTS))
    return start + dt.timedelta(days=int(cfg.get("grace_days", GRACE_DAYS)))


def observe(rec: netindex.Record, *, timeout: float = 15, at: Optional[dt.date] = None,
            fetch_fn: Optional[Callable] = None) -> dict:
    """One network look at one record. Never raises; a broken site is data."""
    fetch_fn = fetch_fn or artifact.fetch
    at = at or dt.date.today()
    obs = {"id": rec.id, "at": at.isoformat(), "reachable": False, "status_code": 0,
           "final_host": "", "artifact": None, "artifact_reason": "",
           "fingerprint": None, "error": "", "exempt": rec.kind in artifact.EXEMPT_KINDS,
           "skip": ""}
    if obs["exempt"]:
        obs["artifact_reason"] = "exempt: verified by its own bot"
        return obs
    if not rec.url:
        obs["skip"] = "no url"
        return obs
    if not rec.url.startswith("https://"):
        obs["error"] = "url is not https"
        return obs
    page = fetch_fn(rec.url, timeout=timeout)
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
    obs["fingerprint"] = fingerprint.page(page.body, obs["final_host"])
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
        if in_grace(entry, cfg):
            out.append({"code": "grace", "detail": obs.get("artifact_reason", "")})
        else:
            out.append({"code": ARTIFACT_MISSING,
                        "detail": obs.get("artifact_reason") or "no backlink found"})
    base, cur = entry.get("baseline"), obs.get("fingerprint")
    if obs.get("reachable") and base and cur:
        kind, sim = fingerprint.drift(base, cur)
        if kind in (HOST_CHANGED, CONTENT_CHANGED):
            out.append({"code": kind, "detail": f"similarity {sim:.2f}"})
    return [f for f in out if f["code"] != "grace"]


def advance(prev: dict, obs: dict, cfg: dict) -> dict:
    """The state machine. Pure: same inputs, same entry out.

    Rules
    -----
    * a clean check returns the entry to ``active`` from any status;
    * the first failure of an active entry makes it ``warn``;
    * ``SUSPEND_AFTER`` consecutive failures, or an artifact missing for
      ``SUSPEND_AFTER`` days, or a final host change (immediately) suspends it;
    * ``DELIST_AFTER_DAYS`` days suspended makes it ``delisted``;
    * ``suspended``/``delisted`` never recover on a failing check.
    """
    e = copy.deepcopy(new_entry())
    e.update(copy.deepcopy(prev or {}))
    today = cfg["today"]
    e["last_checked"] = obs.get("at") or today.isoformat()

    if obs.get("exempt"):
        e["exempt"] = True
        e["failures"] = []
        e["artifact"] = e.get("artifact")
        e["current"] = obs.get("fingerprint") or e.get("current")
        e["_note"] = "exempt: re-verified by its own bot, not by the backlink rule"
        return e
    e.pop("exempt", None)

    if obs.get("skip"):
        e["_note"] = f"not checkable: {obs['skip']}"
        e["current"] = obs.get("fingerprint") or e.get("current")
        return e

    failures = failures_for(e, obs, cfg)
    codes = [f["code"] for f in failures]
    e["failures"] = failures
    if obs.get("artifact"):
        e["artifact"] = obs["artifact"]
    if obs.get("artifact_reason"):
        e["artifact_reason"] = obs["artifact_reason"]
    if obs.get("fingerprint"):
        e["current"] = obs["fingerprint"]
    if not e.get("baseline") and obs.get("fingerprint"):
        e["baseline"] = obs["fingerprint"]
    if obs.get("reachable") and not failures:
        e["last_ok"] = e["last_checked"]

    prev_status = e.get("status") or "active"
    consecutive = (e.get("consecutive_failures") or 0) + 1 if failures else 0
    missing = (e.get("artifact_missing_days") or 0) + 1 if ARTIFACT_MISSING in codes else 0
    e["consecutive_failures"], e["artifact_missing_days"] = consecutive, missing

    if not failures:
        status, e["suspended_since"] = "active", None
    elif prev_status in ("suspended", "delisted"):
        status = prev_status
    elif HOST_CHANGED in codes or consecutive >= SUSPEND_AFTER or missing >= SUSPEND_AFTER:
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
        "The entry returns to `active` on the first clean daily check and this issue "
        "is closed automatically. Nothing is deleted; a delisted entry keeps its "
        "record and its page, with the reason."
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
        if not prev.get("baseline"):
            # A fingerprint stamped at listing time (verify.py --stamp) is the baseline:
            # the page cannot be swapped between approval and the first daily check.
            stamped = (rec.provenance or {}).get("fingerprint")
            if isinstance(stamped, dict) and isinstance(stamped.get("signature"), list):
                prev["baseline"] = {k: stamped.get(k) for k in
                                    ("title", "description", "host", "signature")}
        before = prev.get("status") or "active"
        e = advance(prev, observations[rec.id], cfg)
        if rec.id in accept and observations[rec.id].get("fingerprint"):
            # A maintainer accepted the new page: re-seed the baseline, and clear a
            # needs-review state that existed only because the page had changed.
            e["baseline"] = observations[rec.id]["fingerprint"]
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
    # An entry whose record was removed from git is reported, never silently dropped.
    orphans = sorted(set(entries) - set(by_id))
    for rid in orphans:
        transitions.append({"id": rid, "from": entries[rid].get("status"), "to": "orphan",
                            "codes": [], "reasons": ["record no longer in records/"]})
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
    fp_a = {"title": "a", "description": "", "host": "a.example", "signature": sig_a}
    fp_b = {"title": "b", "description": "", "host": "a.example", "signature": sig_b}
    normal = {"reachable": True, "artifact": "well-known", "artifact_reason": "",
              "fingerprint": fp_a, "error": ""}

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

    # artifact missing: grace for an old record, failure after it
    no_art = {**normal, "artifact": None, "artifact_reason": "no backlink found"}
    g = advance(new_entry(), no_art, cfg)
    check("missing artifact inside grace -> active", g["status"], "active")
    late2 = {"today": dt.date(2026, 12, 25), "grace_days": GRACE_DAYS,
             "grace_starts": GRACE_STARTS}
    post = advance(new_entry(), no_art, late2)
    check("missing artifact after grace -> warn", post["status"], "warn")
    had = advance({**new_entry(), "artifact": "meta"}, no_art, cfg)
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
