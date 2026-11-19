#!/usr/bin/env python3
"""Gate orchestration: diff parsing, health verdicts, exemption, output; no network."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import listing_gate as lg  # noqa: E402
from gate_net import Fetch, TLSResult  # noqa: E402

CONFIG = {"parked_markers": ["domain is for sale", "hugedomains.com"],
          "discord_exempt_kinds": ["discord", "community"]}


def tls_ok():
    return TLSResult(True, "verified TLSv1.3")


class DiffTests(unittest.TestCase):
    def test_parse_name_status_added_modified_renamed(self):
        text = ("A\trecords/a.json\n"
                "M\trecords/b.json\n"
                "R100\trecords/old.json\trecords/new.json\n"
                "D\trecords/gone.json\n")
        self.assertEqual(lg.parse_name_status(text), [
            ("A", "records/a.json"), ("M", "records/b.json"),
            ("R", "records/new.json"), ("D", "records/gone.json")])


class HealthTests(unittest.TestCase):
    def test_good_page_passes(self):
        page = Fetch(200, "<html><title>Puffer Party</title></html>",
                     "https://pufferparty.org/")
        status, why = lg.inspect_health("https://pufferparty.org/", page, tls_ok(), CONFIG)
        self.assertEqual(status, lg.PASS)
        self.assertIn("Puffer Party", why)

    def test_www_redirect_is_allowed(self):
        page = Fetch(200, "<title>ok</title>", "https://www.example.com/")
        self.assertEqual(lg.inspect_health("https://example.com/", page, tls_ok(),
                                           CONFIG)[0], lg.PASS)

    def test_expired_certificate_fails(self):
        page = Fetch(200, "<title>ok</title>", "https://example.com/")
        status, why = lg.inspect_health("https://example.com/", page,
                                        TLSResult(False, "certificate has expired"), CONFIG)
        self.assertEqual(status, lg.FAIL)
        self.assertIn("expired", why)

    def test_non_2xx_fails(self):
        page = Fetch(503, "", "https://example.com/")
        self.assertEqual(lg.inspect_health("https://example.com/", page, tls_ok(),
                                           CONFIG)[0], lg.FAIL)

    def test_redirect_off_host_fails(self):
        page = Fetch(200, "<title>blocked</title>",
                     "https://block.example.net/warn.html")
        status, why = lg.inspect_health("https://example.com/", page, tls_ok(), CONFIG)
        self.assertEqual(status, lg.FAIL)
        self.assertIn("redirected off", why)

    def test_missing_title_fails(self):
        page = Fetch(200, "<html><body>no title</body></html>", "https://example.com/")
        self.assertEqual(lg.inspect_health("https://example.com/", page, tls_ok(),
                                           CONFIG)[0], lg.FAIL)

    def test_parked_page_fails(self):
        page = Fetch(200, "<title>example.com</title> This domain is for sale",
                     "https://example.com/")
        status, why = lg.inspect_health("https://example.com/", page, tls_ok(), CONFIG)
        self.assertEqual(status, lg.FAIL)
        self.assertIn("parked", why)

    def test_http_url_fails(self):
        page = Fetch(200, "<title>ok</title>", "http://example.com/")
        self.assertEqual(lg.inspect_health("http://example.com/", page, tls_ok(),
                                           CONFIG)[0], lg.FAIL)


class RuleTests(unittest.TestCase):
    def record(self, **over):
        raw = {"id": "r1", "kind": "site", "url": "https://example.com/"}
        raw.update(over)
        return lg.parse_record("records/r1.json", raw)

    def ctx(self, **over):
        base = dict(config=CONFIG, existing_hosts=[], labels=[], offline=True)
        base.update(over)
        return lg.Context(**base)

    def test_artifact_exempt_kind_passes(self):
        result = lg.artifact_rule(self.record(kind="discord", url=""), self.ctx())
        self.assertEqual(result.status, lg.PASS)
        self.assertIn("own bot", result.reason)

    def test_artifact_without_url_fails(self):
        self.assertEqual(lg.artifact_rule(self.record(url=""), self.ctx()).status, lg.FAIL)

    def test_artifact_offline_is_skip(self):
        self.assertEqual(lg.artifact_rule(self.record(), self.ctx()).status, lg.SKIP)

    def test_health_without_url_fails(self):
        self.assertEqual(lg.health_rule(self.record(url=""), self.ctx()).status, lg.FAIL)

    def test_url_less_exempt_kind_is_skipped_not_failed(self):
        config = {"no_url_exempt_kinds": ["gate", "world"],
                  "discord_exempt_kinds": []}
        ctx = self.ctx(config=config)
        rec = self.record(kind="gate", url="")
        for rule in (lg.artifact_rule(rec, ctx), lg.health_rule(rec, ctx),
                     lg.lookalike_rule(rec, ctx)):
            self.assertEqual(rule.status, lg.SKIP, rule)
            self.assertIn("no_url_exempt_kinds", rule.reason)
        self.assertEqual(lg.reputation_rules(rec, ctx)[0].status, lg.SKIP)
        # A skipped rule is reported, not a pass, and never a failure.
        self.assertEqual(lg.overall([lg.artifact_rule(rec, ctx),
                                     lg.health_rule(rec, ctx)]), lg.PASS)

    def test_url_less_kind_not_in_the_exempt_list_still_fails(self):
        config = {"no_url_exempt_kinds": ["gate"], "discord_exempt_kinds": []}
        ctx = self.ctx(config=config)
        rec = self.record(kind="site", url="")
        self.assertEqual(lg.artifact_rule(rec, ctx).status, lg.FAIL)
        self.assertEqual(lg.health_rule(rec, ctx).status, lg.FAIL)
        self.assertEqual(lg.reputation_rules(rec, ctx)[0].status, lg.FAIL)
        self.assertEqual(lg.lookalike_rule(rec, ctx).status, lg.FAIL)

    def test_real_config_exempts_the_url_less_records_on_main(self):
        config = lg.rep.load_config(
            Path(__file__).resolve().parents[1] / "tools" / "gate_config.json")
        # records/gate_shadowbroker_infonet.json (kind gate) and both url-less
        # world records on main must not fail the gate merely for having no url.
        for kind in ("gate", "world"):
            self.assertTrue(lg.url_exempt(self.record(kind=kind, url=""), config),
                            kind)
        self.assertFalse(lg.url_exempt(self.record(kind="site", url=""), config))

    def test_lookalike_rule_fails_on_brand_typosquat(self):
        ctx = self.ctx(config=lg.rep.load_config(
            Path(__file__).resolve().parents[1] / "tools" / "gate_config.json"))
        result = lg.lookalike_rule(self.record(url="https://paypa1.com/"), ctx)
        self.assertEqual(result.status, lg.FAIL)

    def test_judge_offline_reports_skip_not_failure(self):
        results = lg.judge(self.record(), self.ctx())
        self.assertEqual(lg.overall(results), lg.PASS)
        self.assertTrue(any(r.status == lg.SKIP for r in results))


def _discord_raw(**over):
    """A Discord record whose stamp looks exactly like the intake bot's."""
    raw = {"id": "discord_123456789012345678", "kind": "discord",
           "url": "https://discord.gg/abcdef",
           "listing": {"guild": "123456789012345678"},
           "provenance": {"added_by": "github:aither-wzns",
                          "sources": ["https://discord.gg/abcdef"],
                          "validated": {"at": "2026-11-19", "by": "aithernet-bot",
                                        "method": "discord-bot",
                                        "guild": "123456789012345678",
                                        "requested_by": "discord:42"}}}
    raw.update(over)
    return raw


class ProvenanceTests(unittest.TestCase):
    """A Discord / bot-stamped record must come from the intake bot's own PR."""

    def ctx(self, author):
        config = lg.rep.load_config(
            Path(__file__).resolve().parents[1] / "tools" / "gate_config.json")
        return lg.Context(config=config, existing_hosts=[], labels=[], offline=True,
                          pr_author=author)

    def verdict(self, rec, author):
        results = lg.judge(rec, self.ctx(author))
        return lg.overall(results), [r for r in results if r.rule == "provenance"]

    def test_hand_written_pr_adding_a_bot_stamped_discord_record_fails(self):
        rec = lg.parse_record("records/d.json", _discord_raw())
        for human in ("aither-wzns", "randomstranger", "aithernet-bot"):
            verdict, proof = self.verdict(rec, human)
            self.assertEqual(verdict, lg.FAIL, human)
            self.assertEqual(proof[0].status, lg.FAIL)
            self.assertIn(human, proof[0].reason)

    def test_intake_bot_pr_adding_a_discord_record_passes(self):
        rec = lg.parse_record("records/d.json", _discord_raw())
        verdict, proof = self.verdict(rec, "github-actions[bot]")
        self.assertEqual(verdict, lg.PASS)
        self.assertEqual(proof[0].status, lg.PASS)

    def test_unknown_author_fails_closed(self):
        rec = lg.parse_record("records/d.json", _discord_raw())
        verdict, proof = self.verdict(rec, "")
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("unknown author", proof[0].reason)

    def test_bot_stamp_on_a_site_record_needs_the_bot(self):
        raw = {"id": "r1", "kind": "site", "url": "https://example.com/",
               "provenance": {"validated": {"method": "discord-bot"}}}
        verdict, proof = self.verdict(lg.parse_record("records/r1.json", raw), "someone")
        self.assertEqual(verdict, lg.FAIL)
        self.assertEqual(proof[0].status, lg.FAIL)

    def test_human_altering_an_existing_discord_stamp_fails(self):
        before = _discord_raw()
        after = _discord_raw()
        after["provenance"]["validated"]["at"] = "2026-12-01"
        rec = lg.parse_record("records/d.json", after, before)
        self.assertEqual(self.verdict(rec, "aither-wzns")[0], lg.FAIL)

    def test_human_rekinding_a_discord_record_to_site_fails(self):
        before = _discord_raw()
        after = {"id": before["id"], "kind": "site", "url": "https://example.com/"}
        rec = lg.parse_record("records/d.json", after, before)
        verdict, proof = self.verdict(rec, "aither-wzns")
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("changes a record", proof[0].reason)

    def test_plain_site_record_needs_no_bot(self):
        rec = lg.parse_record("records/r1.json",
                              {"id": "r1", "kind": "site", "url": "https://example.com/"})
        verdict, proof = self.verdict(rec, "aither-wzns")
        self.assertEqual(proof, [])
        self.assertEqual(verdict, lg.PASS)

    def test_name_status_paths_keep_the_renamed_from_path(self):
        self.assertEqual(lg.parse_name_status_paths(
            "A\trecords/a.json\nR090\trecords/old.json\trecords/new.json\n"),
            [("A", "records/a.json", "records/a.json"),
             ("R", "records/old.json", "records/new.json")])

    def test_load_targets_reads_the_base_record_from_git(self):
        import shutil
        import subprocess
        import tempfile
        from types import SimpleNamespace

        if not shutil.which("git"):
            self.skipTest("git not on PATH")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)

        def run(*args):
            subprocess.run(["git", "-C", tmp, *args], check=True, capture_output=True)

        run("init", "-q")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        run("config", "core.autocrlf", "false")
        records = Path(tmp) / "records"
        records.mkdir()
        target = records / "d.json"
        target.write_text(json.dumps(_discord_raw()), encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "base")
        run("tag", "base")
        moved = _discord_raw()
        moved["provenance"]["validated"]["requested_by"] = "discord:7"
        target.unlink()
        (records / "d2.json").write_text(json.dumps(moved), encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "head")
        args = SimpleNamespace(root=tmp, records=None, base="base", head="HEAD")
        targets, _hosts = lg.load_targets(args)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].base_raw, _discord_raw())
        self.assertEqual(self.verdict(targets[0], "aither-wzns")[0], lg.FAIL)
        self.assertEqual(self.verdict(targets[0], "github-actions[bot]")[0], lg.PASS)

    def test_workflow_runs_the_gate_from_the_base_commit_with_the_pr_author(self):
        wf = (Path(__file__).resolve().parents[1] / ".github" / "workflows"
              / "listing-gate.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.user.login", wf)
        self.assertIn('git worktree add --detach "$RUNNER_TEMP/gate-base" "$BASE_SHA"', wf)
        self.assertIn('python "$GATE"', wf)

    def test_intake_pr_author_is_the_github_token_identity(self):
        config = self.ctx("").config
        self.assertEqual(config["intake_pr_authors"], ["github-actions[bot]"])
        self.assertIn("discord-bot", config["bot_stamp_methods"])


class OutputTests(unittest.TestCase):
    def test_find_marker_comment(self):
        comments = [{"id": 1, "body": "hello"},
                    {"id": 2, "body": lg._COMMENT_MARKER + "\nhi"}]
        self.assertEqual(lg.find_marker_comment(comments, lg._COMMENT_MARKER)["id"], 2)
        self.assertIsNone(lg.find_marker_comment([{"id": 1, "body": "x"}], "<!-- m -->"))

    def test_summary_lists_every_rule_and_fix(self):
        rec = lg.parse_record("records/r1.json",
                              {"id": "r1", "kind": "site", "url": "https://example.com/"})
        results = [lg.RuleResult("r1", "artifact", lg.FAIL, "no backlink"),
                   lg.RuleResult("r1", "health", lg.PASS, "ok")]
        summary = lg.render_summary([rec], results)
        self.assertIn(lg._COMMENT_MARKER, summary)
        self.assertIn("**Verdict: FAIL**", summary)
        self.assertIn("no backlink", summary)
        self.assertIn("What to fix", summary)

    def test_table_prints_per_record_verdict(self):
        rec = lg.parse_record("records/r1.json",
                              {"id": "r1", "kind": "site", "url": "https://example.com/"})
        table = lg.render_table([rec], [lg.RuleResult("r1", "health", lg.PASS, "ok")])
        self.assertIn("r1", table)
        self.assertIn("-> PASS", table)
        self.assertIn("1 record(s)", table)


if __name__ == "__main__":
    unittest.main()
