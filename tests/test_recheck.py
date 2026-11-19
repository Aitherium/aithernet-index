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
        self.assertEqual(fingerprint.SIMILARITY_THRESHOLD, 0.5)

    def test_title_only_change_is_not_a_swap(self):
        old = fp(title="Old")
        new = fp(title="New")
        self.assertEqual(fingerprint.drift(old, new)[0], "changed")


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
        e = recheck.advance(recheck.new_entry(), no_art, CFG)
        self.assertEqual(e["status"], "active")          # inside the 30-day grace
        after = {**CFG, "today": dt.date(2026, 12, 25)}  # grace ended 2026-12-18
        e = recheck.advance(e, no_art, after)
        self.assertEqual(e["status"], "warn")
        self.assertIn("artifact-missing", [f["code"] for f in e["failures"]])

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
        state = {"version": 1, "grace_starts": "2026-11-18", "grace_days": 30,
                 "entries": {"a.example": {"status": "active"},
                             "gone.example": {"status": "active"},
                             "b.example": {"status": "weird"}}}
        codes = [f.code for f in recheck.state_findings(state, [rec])]
        self.assertEqual(codes.count("NI011"), 2)


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


class SelfTests(unittest.TestCase):
    def test_module_self_tests_pass(self):
        self.assertEqual(artifact._self_test(), 0)
        self.assertEqual(fingerprint.self_test(), 0)
        self.assertEqual(recheck.self_test(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
