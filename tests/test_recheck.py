#!/usr/bin/env python3
"""Tests for the backlink artifact, the fingerprint, the state machine and the job.

    python -m unittest discover -s tests -v
    python tests/test_recheck.py            # same tests, plain

Stdlib only, like the rest of the repo. The network is never touched: ``recheck.run``
takes an injected fetcher, so every case is deterministic.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import artifact  # noqa: E402
import fingerprint  # noqa: E402
import recheck  # noqa: E402

RID = "example.com_garden"
HOST = artifact.INDEX_HOST


def sig(*words: str) -> "list[int]":
    return fingerprint.signature(fingerprint.tokens(" ".join(words)))


def fp(host: str = "a.example", words: str = "alpha beta gamma delta epsilon",
       title: str = "A") -> dict:
    return {"title": title, "description": "", "host": host,
            "signature": sig(*words.split())}


def obs(**kw) -> dict:
    base = {"id": RID, "at": "2026-11-18", "reachable": True, "status_code": 200,
            "final_host": "a.example", "artifact": "well-known", "artifact_reason": "",
            "fingerprint": fp(), "error": "", "exempt": False, "skip": ""}
    base.update(kw)
    return base


CFG = {"today": dt.date(2026, 11, 18), "grace_days": 30,
       "grace_starts": "2026-11-18"}


class ArtifactDetection(unittest.TestCase):
    """Every form counts; every look-alike does not."""

    def test_well_known(self):
        self.assertEqual(artifact.detect(RID, "<p>x</p>", [RID]).form, "well-known")

    def test_link_rel(self):
        html = f'<html><head><link rel="aithernet" href="https://{HOST}/r/{RID}">' \
               "</head><body>x</body></html>"
        self.assertEqual(artifact.detect(RID, html, []).form, "link-rel")

    def test_meta(self):
        html = f'<html><head><meta name="aithernet" content="{RID}"></head><body></body></html>'
        self.assertEqual(artifact.detect(RID, html, []).form, "meta")

    def test_visible_link(self):
        html = f'<p><a href="https://{HOST}/r/{RID}">Listed on AitherNet</a></p>'
        self.assertEqual(artifact.detect(RID, html, []).form, "visible-link")

    def test_entry_page_path_counts(self):
        html = f'<a href="https://{HOST}/e/{RID}/">see it</a>'
        self.assertEqual(artifact.detect(RID, html, []).form, "visible-link")

    def test_other_domain_does_not_count(self):
        html = f'<a href="https://evil.example/r/{RID}">x</a>'
        self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_lookalike_host_does_not_count(self):
        for href in (f"https://{HOST}.evil.example/r/{RID}",
                     f"https://not{HOST}/r/{RID}",
                     f"https://{HOST}@evil.example/r/{RID}",
                     f"http://{HOST}/r/{RID}"):
            with self.subTest(href=href):
                self.assertIsNone(artifact.detect(RID, f'<a href="{href}">x</a>', []).form)

    def test_different_id_does_not_count(self):
        html = f'<a href="https://{HOST}/r/other.example">x</a>' \
               f'<meta name="aithernet" content="other.example">'
        self.assertIsNone(artifact.detect(RID, html, ["other.example"]).form)
        self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_substring_id_does_not_count(self):
        html = f'<a href="https://{HOST}/r/{RID}-extra">x</a>'
        self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_hidden_anchor_does_not_count(self):
        html = f'<a href="https://{HOST}/r/{RID}"></a>'
        self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_hidden_markup_does_not_count(self):
        link = f'<a href="https://{HOST}/r/{RID}">Listed</a>'
        cases = [
            f'<div style="display:none">{link}</div>',
            f'<div hidden>{link}</div>',
            f'<div aria-hidden="true">{link}</div>',
            f'<div style="position:absolute;left:-9999px">{link}</div>',
            f'<div style="font-size:0">{link}</div>',
            f'<div style="opacity:0">{link}</div>',
            f'<div style="visibility:hidden">{link}</div>',
            f"<style>.ghost{{display:none}}</style><div class=\"ghost\">{link}</div>",
            f'<a href="https://{HOST}/r/{RID}">&#x200b;</a>',
        ]
        for html in cases:
            with self.subTest(html=html):
                self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_inert_markup_does_not_count(self):
        link = f'<link rel="aithernet" href="https://{HOST}/r/{RID}">'
        meta = f'<meta name="aithernet" content="{RID}">'
        for html in (f"<template>{link}</template>",
                     f"<html><head><template>{meta}</template></head></html>",
                     f"<noscript>{link}</noscript>",
                     f"<svg>{link}</svg>",
                     f"<!-- {link} -->"):
            with self.subTest(html=html):
                self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_exempt_by_host_not_only_kind(self):
        self.assertTrue(artifact.is_exempt("world", "https://discord.gg/xMv9hHKkkh"))
        self.assertTrue(artifact.is_exempt("room", "https://relay.aitherium.com/room/x"))
        self.assertTrue(artifact.is_exempt("discord", "https://example.com"))
        self.assertFalse(artifact.is_exempt("garden", "https://garden.example"))

    def test_wrong_rel_does_not_count(self):
        html = f'<html><head><link rel="stylesheet" href="https://{HOST}/r/{RID}">' \
               "</head><body></body></html>"
        self.assertIsNone(artifact.detect(RID, html, []).form)

    def test_reason_names_what_was_seen(self):
        html = f'<a href="https://{HOST}/r/other.example">x</a>'
        a = artifact.detect(RID, html, [])
        self.assertFalse(a.ok)
        self.assertIn("not this entry", a.reason)


class FingerprintDrift(unittest.TestCase):
    def test_small_edit_is_same(self):
        old = fp(words="one two three four five six seven eight nine ten")
        new = fp(words="one two three four five six seven eight nine ELEVEN")
        self.assertEqual(fingerprint.drift(old, new)[0], "same")

    def test_large_text_change(self):
        old = fp(words="one two three four five six seven eight")
        new = fp(words="casino bonus free spins win jackpot now")
        self.assertEqual(fingerprint.drift(old, new)[0], "content-changed")

    def test_host_change_wins_over_text(self):
        old = fp(host="a.example", words="one two three")
        new = fp(host="b.example", words="one two three")
        self.assertEqual(fingerprint.drift(old, new)[0], "host-changed")

    def test_threshold_is_documented(self):
        self.assertEqual(fingerprint.SIMILARITY_THRESHOLD, 0.65)

    def test_title_only_change_is_not_a_swap(self):
        old = fp(title="Old")
        new = fp(title="New")
        self.assertEqual(fingerprint.drift(old, new)[0], "changed")

    def test_shared_template_does_not_hide_a_body_swap(self):
        # A complete body replacement behind an identical nav/footer must not pass.
        head = ("<html><head><title>My Notes</title></head><body>"
                "<nav>home about archive contact subscribe newsletter rss tags search "
                "privacy terms cookies follow mastodon twitter github source licence "
                "built with a static site generator running since twenty nineteen</nav>")
        tail = ("<footer>copyright two thousand twenty four all rights reserved "
                "powered by garden engine privacy policy contact me here</footer></body></html>")
        a = fingerprint.page(head + "<p>tomato basil clay soil compost seedlings watering "
                             "spring harvest beds mulch bees flowers seeds</p>" + tail,
                             "a.example")
        b = fingerprint.page(head + "<p>casino bonuses free spins jackpot roulette "
                             "blackjack poker deposit withdrawal vip wagering</p>" + tail,
                             "a.example")
        self.assertEqual(fingerprint.drift(a, b)[0], "content-changed")

    def test_opaque_pages_are_compared_by_assets(self):
        one = fingerprint.page('<html><head><title>P</title></head><body>'
                               '<img src="/a.jpg" alt="garden"></body></html>', "a.example")
        same = fingerprint.page('<html><head><title>P</title></head><body>'
                                '<img src="/a.jpg" alt="garden"></body></html>', "a.example")
        other = fingerprint.page('<html><head><title>P</title></head><body>'
                                 '<img src="/b.jpg" alt="casino"></body></html>', "a.example")
        self.assertEqual(one["tokens"], 0)
        self.assertEqual(fingerprint.drift(one, same)[0], "same")
        self.assertEqual(fingerprint.drift(one, other)[0], "content-changed")

    def test_different_js_shells_are_not_same(self):
        a = fingerprint.page('<div id="root"></div><script>render("notes")</script>',
                             "a.example")
        b = fingerprint.page('<div id="root"></div><script>casinoRender()</script>',
                             "a.example")
        self.assertEqual(fingerprint.drift(a, b)[0], "content-changed")

    def test_client_side_redirect_to_another_host(self):
        base = fingerprint.page("<html><body><p>notes here</p></body></html>", "a.example")
        moved = fingerprint.page(
            '<html><head><meta http-equiv="refresh" '
            'content="0;url=https://casino.example"></head>'
            "<body><p>notes here</p></body></html>", "a.example")
        self.assertEqual(fingerprint.drift(base, moved)[0], "host-changed")


class StateMachine(unittest.TestCase):
    def test_active_to_warn_to_suspended_to_delisted(self):
        e = recheck.advance(recheck.new_entry(), obs(), CFG)
        self.assertEqual(e["status"], "active")
        down = obs(reachable=False, error="HTTP 503", fingerprint=None)
        e = recheck.advance(e, down, CFG)
        self.assertEqual(e["status"], "warn")
        e = recheck.advance(e, down, CFG)
        self.assertEqual(e["status"], "warn")
        e = recheck.advance(e, down, CFG)
        self.assertEqual(e["status"], "suspended")
        self.assertEqual(e["suspended_since"], "2026-11-18")
        late = {**CFG, "today": dt.date(2026, 12, 2)}   # 14 days later
        e = recheck.advance(e, down, late)
        self.assertEqual(e["status"], "delisted")

    def test_recovery_from_every_state(self):
        for status in ("warn", "suspended", "delisted"):
            with self.subTest(status=status):
                prev = {**recheck.new_entry(), "status": status,
                        "consecutive_failures": 3, "suspended_since": "2026-11-01"}
                e = recheck.advance(prev, obs(), CFG)
                self.assertEqual(e["status"], "active")
                self.assertIsNone(e["suspended_since"])
                self.assertEqual(e["consecutive_failures"], 0)

    def test_grace_period_then_failure(self):
        no_art = obs(artifact=None, artifact_reason="no backlink found")
        old = {**recheck.new_entry(), "validated_at": "2026-11-01"}
        e = recheck.advance(old, no_art, CFG)
        self.assertEqual(e["status"], "active")          # inside the 30-day grace
        after = {**CFG, "today": dt.date(2026, 12, 25)}  # grace ended 2026-12-18
        e = recheck.advance(e, no_art, after)
        self.assertEqual(e["status"], "warn")
        self.assertIn("artifact-missing", [f["code"] for f in e["failures"]])

    def test_new_listing_without_an_artifact_is_not_approved(self):
        no_art = obs(artifact=None, artifact_reason="no backlink found")
        new = {**recheck.new_entry(), "validated_at": "2026-11-18"}
        e = recheck.advance(new, no_art, CFG)
        self.assertEqual(e["status"], "warn")
        self.assertIn("artifact-missing", [f["code"] for f in e["failures"]])
        unknown = recheck.advance(recheck.new_entry(), no_art, CFG)
        self.assertEqual(unknown["status"], "warn")      # no approval date -> no grace

    def test_flapping_does_not_evade_the_suspend_rule(self):
        # down, down, up, forever: never three consecutive failures, but the window
        # must still suspend it and a single good day must not restore the listing.
        e = recheck.new_entry()
        statuses = []
        for i in range(30):
            down = i % 3 != 2
            o = obs(reachable=not down, error="" if not down else "HTTP 503",
                    fingerprint=None if down else fp())
            e = recheck.advance(e, o, {**CFG, "today":
                                       dt.date(2026, 11, 18) + dt.timedelta(days=i)})
            statuses.append(e["status"])
        self.assertIn("suspended", statuses)
        self.assertIn(e["status"], ("suspended", "delisted"))

    def test_artifact_flapping_does_not_evade_the_rule(self):
        e = recheck.new_entry()
        for i in range(12):
            missing = i % 3 != 2
            o = obs(artifact=None if missing else "meta")
            e = recheck.advance(e, o, {**CFG, "today": dt.date(2026, 11, 18 + i)})
        self.assertIn(e["status"], ("suspended", "delisted"))

    def test_client_side_redirect_suspends(self):
        base = fp(host="a.example")
        moved = {**base, "redirect_host": "casino.example"}
        e = recheck.advance({**recheck.new_entry(), "baseline": base},
                            obs(fingerprint=moved), CFG)
        self.assertEqual(e["status"], "suspended")
        self.assertIn("host-changed", [f["code"] for f in e["failures"]])

    def test_ua_cloaking_is_needs_review(self):
        e = recheck.advance(recheck.new_entry(), obs(cloaked=True), CFG)
        self.assertEqual(e["status"], "suspended")
        self.assertIn("cloaking", [f["code"] for f in e["failures"]])

    def test_cleared_baseline_is_not_reseeded(self):
        prev = {**recheck.new_entry(), "last_checked": "2026-11-17",
                "last_ok": "2026-11-17", "ever_ok": True,
                "baseline_source": "seeded"}
        e = recheck.advance(prev, obs(), CFG)
        self.assertIsNone(e["baseline"])
        self.assertIn("baseline-missing", [f["code"] for f in e["failures"]])

    def test_losing_a_known_artifact_is_not_graced(self):
        e = {**recheck.new_entry(), "artifact": "meta"}
        e = recheck.advance(e, obs(artifact=None), CFG)
        self.assertEqual(e["status"], "warn")

    def test_artifact_missing_three_days_suspends(self):
        e = {**recheck.new_entry(), "artifact": "meta"}
        for day in range(3):
            e = recheck.advance(e, obs(artifact=None), {**CFG, "today":
                                                         dt.date(2026, 11, 18 + day)})
        self.assertEqual(e["status"], "suspended")

    def test_host_change_suspends_on_day_one(self):
        e = {**recheck.new_entry(), "baseline": fp(host="a.example")}
        e = recheck.advance(e, obs(fingerprint=fp(host="b.example")), CFG)
        self.assertEqual(e["status"], "suspended")
        self.assertIn("host-changed", [f["code"] for f in e["failures"]])

    def test_content_drift_warns(self):
        e = {**recheck.new_entry(), "baseline": fp(words="one two three four five")}
        e = recheck.advance(e, obs(fingerprint=fp(words="casino bonus free spins")), CFG)
        self.assertEqual(e["status"], "warn")
        self.assertIn("content-changed", [f["code"] for f in e["failures"]])

    def test_baseline_seeded_once_and_not_refreshed(self):
        e = recheck.advance(recheck.new_entry(), obs(), CFG)
        first = e["baseline"]
        e = recheck.advance(e, obs(fingerprint=fp(words="alpha beta gamma")), CFG)
        self.assertEqual(e["baseline"], first)

    def test_exempt_kind_never_fails(self):
        e = recheck.advance(recheck.new_entry(),
                            {"exempt": True, "at": "2026-11-18"}, CFG)
        self.assertEqual(e["status"], "active")
        self.assertEqual(e["failures"], [])

    def test_no_url_never_fails(self):
        e = recheck.advance(recheck.new_entry(), {"skip": "no url", "at": "2026-11-18"}, CFG)
        self.assertEqual(e["status"], "active")

    def test_accept_reseeds_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d, "records")
            root.mkdir()
            (root / "a.example.json").write_text(json.dumps({
                "id": "a.example", "kind": "site", "title": "A", "url": "https://a.example",
                "provenance": {"added_by": "t", "sources": ["x"],
                               "validated": {"at": "2026-01-01", "by": "t", "method": "m"}}}),
                encoding="utf-8")
            pages = {"https://a.example": artifact.Fetch(200, "<p>new page</p>",
                                                        "https://a.example")}
            res = recheck.run(root, Path(d, "state", "health.json"), today=CFG["today"],
                              write=True, fetch_fn=lambda url, **k: pages.get(
                                  url, artifact.Fetch(404, "", url, "404")),
                              accept=("a.example",))
            e = res["entries"]["a.example"]
            self.assertIsNotNone(e["baseline"])
            self.assertEqual([f for f in e["failures"] if f["code"] == "content-changed"], [])


class IssueDecision(unittest.TestCase):
    def test_suspended_opens(self):
        tr = [{"id": "a", "from": "warn", "to": "suspended", "codes": ["unreachable"]}]
        self.assertEqual([(x["id"], x["action"]) for x in recheck.plan_issues(tr, [])],
                         [("a", "open")])

    def test_needs_review_opens_but_plain_warn_does_not(self):
        tr = [{"id": "a", "from": "active", "to": "warn", "codes": ["host-changed"]},
              {"id": "b", "from": "active", "to": "warn", "codes": ["unreachable"]}]
        self.assertEqual([x["id"] for x in recheck.plan_issues(tr, [])], ["a"])

    def test_existing_issue_is_updated_not_duplicated(self):
        tr = [{"id": "a", "from": "warn", "to": "suspended", "codes": ["unreachable"]}]
        plan = recheck.plan_issues(tr, [{"number": 3, "title": "[recheck] a :: warn"}])
        self.assertEqual([(x["action"], x["number"]) for x in plan], [("update", 3)])

    def test_recovery_closes(self):
        tr = [{"id": "a", "from": "suspended", "to": "active", "codes": []}]
        plan = recheck.plan_issues(tr, [{"number": 3, "title": "[recheck] a :: suspended"}])
        self.assertEqual([(x["action"], x["number"]) for x in plan], [("close", 3)])

    def test_recovery_without_issue_does_nothing(self):
        tr = [{"id": "a", "from": "warn", "to": "active", "codes": []}]
        self.assertEqual(recheck.plan_issues(tr, []), [])

    def test_unrelated_issues_are_ignored(self):
        tr = [{"id": "a", "from": "warn", "to": "suspended", "codes": ["unreachable"]}]
        plan = recheck.plan_issues(tr, [{"number": 5, "title": "Something else"}])
        self.assertEqual(plan[0]["action"], "open")


class JobNeverEditsRecords(unittest.TestCase):
    """The re-check writes state/health.json and nothing else."""

    def _tree(self, d: Path) -> dict:
        return {p.relative_to(d).as_posix(): p.read_bytes()
                for p in sorted(d.rglob("*")) if p.is_file()}

    def test_records_and_root_are_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d, "records")
            root.mkdir()
            (root / "a.example.json").write_text(json.dumps({
                "id": "a.example", "kind": "site", "title": "A", "url": "https://a.example",
                "provenance": {"added_by": "t", "sources": ["x"],
                               "validated": {"at": "2026-01-01", "by": "t", "method": "m"}}}),
                encoding="utf-8")
            (root / "b.example.json").write_text(json.dumps({
                "id": "b.example", "kind": "site", "title": "B", "url": "https://b.example",
                "provenance": {"added_by": "t", "sources": ["x"],
                               "validated": {"at": "2026-01-01", "by": "t", "method": "m"}}}),
                encoding="utf-8")
            before = self._tree(root)
            pages = {
                "https://a.example": artifact.Fetch(200, "<p>alive</p>", "https://a.example"),
                f"https://a.example/.well-known/aithernet.json":
                    artifact.Fetch(200, json.dumps({"records": ["a.example"]}), "https://a.example/.well-known/aithernet.json"),
                "https://b.example": artifact.Fetch(503, "", "https://b.example", "http 503"),
            }
            state = Path(d, "state", "health.json")
            recheck.run(root, state, today=CFG["today"], write=True,
                        fetch_fn=lambda url, **k: pages.get(
                            url, artifact.Fetch(404, "", url, "404")))
            self.assertEqual(self._tree(root), before)     # records/ byte-identical
            self.assertTrue(state.exists())
            written = {p.relative_to(d).as_posix() for p in Path(d).rglob("*") if p.is_file()}
            self.assertEqual(written, {"records/a.example.json", "records/b.example.json",
                                       "state/health.json"})

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d, "records")
            root.mkdir()
            (root / "a.example.json").write_text(json.dumps({
                "id": "a.example", "kind": "site", "title": "A", "url": "https://a.example",
                "provenance": {"added_by": "t", "sources": ["x"],
                               "validated": {"at": "2026-01-01", "by": "t", "method": "m"}}}),
                encoding="utf-8")
            before = self._tree(Path(d))
            recheck.run(root, Path(d, "state", "health.json"), today=CFG["today"],
                        write=False, fetch_fn=lambda url, **k: artifact.Fetch(
                            200, "<p>alive</p>", "https://a.example"))
            self.assertEqual(self._tree(Path(d)), before)


class StateFile(unittest.TestCase):
    def test_roundtrip_and_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "health.json")
            state = recheck.load_state(p)
            self.assertEqual(state["version"], recheck.STATE_VERSION)
            self.assertEqual(state["grace_days"], recheck.GRACE_DAYS)
            state["entries"]["a.example"] = {**recheck.new_entry(), "status": "warn"}
            recheck.save_state(state, p)
            again = recheck.load_state(p)
            self.assertEqual(again["entries"]["a.example"]["status"], "warn")

    def test_findings_flag_unknown_ids_and_bad_status(self):
        import netindex
        rec = netindex._parse(None, {"id": "a.example", "kind": "site", "title": "A"})
        state = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                 "entries": {"a.example": {"status": "weird"},
                             "gone.example": {"status": "active"}}}
        codes = [f.code for f in recheck.state_findings(state, [rec])]
        # The orphan entry is pruned by the next run, not a finding; the bad status is.
        self.assertEqual(codes, [recheck.STATE_RULE])

    def test_baseline_must_match_the_approved_fingerprint(self):
        import netindex
        stamp = {"title": "t", "host": "a.example", "signature": sig("a", "b", "c")}
        rec = netindex._parse(None, {"id": "a.example", "kind": "site", "title": "A",
                                     "provenance": {"fingerprint": stamp}})
        tampered = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                    "entries": {"a.example": {
                        "status": "active", "baseline_source": "seeded",
                        "baseline": {**stamp, "signature": sig("x", "y", "z")}}}}
        codes = [f.code for f in recheck.state_findings(tampered, [rec])]
        self.assertEqual(codes, [recheck.BASELINE_RULE])
        accepted = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                    "entries": {"a.example": {
                        "status": "active", "baseline_source": "accepted",
                        "accepted_at": "2026-11-19",
                        "baseline": {**stamp, "signature": sig("x", "y", "z")}}}}
        self.assertEqual(recheck.state_findings(accepted, [rec]), [])
        no_accepted_date = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                            "entries": {"a.example": {
                                "status": "active", "baseline_source": "accepted",
                                "baseline": stamp}}}
        self.assertEqual([f.code for f in recheck.state_findings(no_accepted_date, [rec])],
                         [recheck.BASELINE_RULE])

    def test_cleared_baseline_on_a_checked_entry_is_a_finding(self):
        import netindex
        rec = netindex._parse(None, {"id": "a.example", "kind": "site", "title": "A"})
        state = {"version": 2, "grace_starts": "2026-11-18", "grace_days": 30,
                 "entries": {"a.example": {"status": "active",
                                           "last_checked": "2026-11-19",
                                           "baseline_expected": True}}}
        self.assertEqual([f.code for f in recheck.state_findings(state, [rec])],
                         [recheck.STATE_RULE])


class OrphanPruning(unittest.TestCase):
    def test_run_prunes_state_for_a_deleted_record(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d, "records")
            root.mkdir()
            (root / "a.example.json").write_text(json.dumps({
                "id": "a.example", "kind": "site", "title": "A", "url": "https://a.example",
                "provenance": {"added_by": "t", "sources": ["x"],
                               "validated": {"at": "2026-01-01", "by": "t", "method": "m"}}}),
                encoding="utf-8")
            state = Path(d, "state", "health.json")
            state.parent.mkdir()
            state.write_text(json.dumps({"version": 2, "grace_starts": "2026-11-18",
                                         "grace_days": 30, "entries": {
                                             "gone.example": {"status": "active"}}}),
                             encoding="utf-8")
            pages = {"https://a.example": artifact.Fetch(200, "<p>alive</p>",
                                                         "https://a.example"),
                     "https://a.example/.well-known/aithernet.json":
                         artifact.Fetch(200, '{"records": ["a.example"]}',
                                        "https://a.example/.well-known/aithernet.json")}
            res = recheck.run(root, state, today=CFG["today"], write=True,
                              fetch_fn=lambda url, **k: pages.get(
                                  url, artifact.Fetch(404, "", url, "404")))
            self.assertEqual(res["orphans"], ["gone.example"])
            self.assertNotIn("gone.example", recheck.load_state(state)["entries"])


class ApplyIssues(unittest.TestCase):
    def test_open_update_close_go_through_gh(self):
        calls = []

        def fake_gh(args):
            calls.append(args)
            return 0, "ok"

        entry = {"status": "suspended", "since": "2026-11-20", "last_checked": "2026-11-21",
                 "last_ok": "2026-11-01", "artifact": None, "artifact_reason": "no backlink",
                 "failures": [{"code": "unreachable", "detail": "HTTP 503"}]}
        actions = [{"id": "a", "action": "open", "to": "suspended"},
                   {"id": "b", "action": "update", "to": "warn", "number": 7},
                   {"id": "c", "action": "close", "to": "active", "number": 8}]
        code = recheck.apply_issues(actions, {"a": entry}, gh=fake_gh)
        self.assertEqual(code, 0)
        verbs = [c[0] + " " + c[1] for c in calls]
        self.assertIn("issue create", verbs)
        self.assertIn("issue comment", verbs)
        self.assertIn("issue close", verbs)
        create = next(c for c in calls if c[:2] == ["issue", "create"])
        body = create[create.index("--body") + 1]
        self.assertIn("index.aitherium.com/r/", body)
        self.assertIn(".well-known/aithernet.json", body)

    def test_a_failed_gh_call_is_reported(self):
        self.assertEqual(recheck.apply_issues(
            [{"id": "a", "action": "open", "to": "suspended"}], {},
            gh=lambda args: (1, "boom")), 1)


class Observation(unittest.TestCase):
    def test_ua_keyed_cloaking_is_detected(self):
        import netindex
        rec = netindex._parse(None, {"id": "a.example", "kind": "site", "title": "A",
                                     "url": "https://a.example"})
        approved = "<p>my garden notes about tomatoes</p>"
        casino = "<p>casino bonus free spins jackpot</p>"

        def fetcher(url, **kw):
            if url.endswith("/.well-known/aithernet.json"):
                return artifact.Fetch(404, "", url, "404")
            body = casino if kw.get("ua") == artifact.CHECKER_UA else approved
            return artifact.Fetch(200, body, url)

        o = recheck.observe(rec, fetch_fn=fetcher, at=CFG["today"])
        self.assertTrue(o["cloaked"])
        self.assertIn("cloaking", [f["code"] for f in recheck.failures_for({}, o, CFG)])

    def test_exempt_by_host(self):
        import netindex
        rec = netindex._parse(None, {"id": "world_x", "kind": "world", "title": "X",
                                     "url": "https://discord.gg/xMv9hHKkkh"})
        o = recheck.observe(rec, fetch_fn=lambda url, **k: artifact.Fetch(404, "", url, "dns"),
                            at=CFG["today"])
        self.assertTrue(o["exempt"])
        self.assertEqual(recheck.failures_for({}, o, CFG), [])


class CheckRoot(unittest.TestCase):
    def test_explicit_relative_records_root_judges_state(self):
        import check
        import netindex
        state = recheck.DEFAULT_STATE
        self.assertEqual(check.state_for_root(netindex.DEFAULT_ROOT, state), state)
        self.assertIsNone(check.state_for_root(Path(tempfile.gettempdir()), state))


class SiteVisibility(unittest.TestCase):
    def test_warn_is_hidden_from_the_listing(self):
        import build_site
        self.assertIn("warn", build_site.HIDDEN)
        import netindex
        r = netindex._parse(None, {"id": "a.example", "kind": "site", "title": "A"})
        self.assertEqual(build_site._visible([r], {"a.example": {"status": "warn"}}), [])
        self.assertEqual(build_site._visible([r], {"a.example": {"status": "active"}}), [r])


class SelfTests(unittest.TestCase):
    def test_module_self_tests_pass(self):
        self.assertEqual(artifact._self_test(), 0)
        self.assertEqual(fingerprint.self_test(), 0)
        self.assertEqual(recheck.self_test(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
