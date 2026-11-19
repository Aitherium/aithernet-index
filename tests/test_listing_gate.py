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


BOT = "github-actions[bot]"
HUMAN = "aither-wzns"
DISCORD_ID = "discord_123456789012345678"
DISCORD_PATH = f"records/{DISCORD_ID}.json"
SHA = "a" * 40


def _discord_raw(**over):
    """A Discord record whose stamp looks exactly like the intake bot's."""
    raw = {"id": DISCORD_ID, "kind": "discord",
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


def _bot_commits(*shas):
    """The GitHub API's view of commits the intake bot made."""
    return {sha: {"author": BOT, "committer": BOT} for sha in shas}


class ProvenanceTests(unittest.TestCase):
    """A Discord / bot-stamped record must come from the intake bot's own PR.

    Being the PR author is not enough: a collaborator can push onto the intake
    branch without changing it. Every commit that touches the record must also
    be authored AND committed by the bot account, and the PR must carry exactly
    one record at ``records/<id>.json``.
    """

    def ctx(self, author, commits="bot", count=1):
        config = lg.rep.load_config(
            Path(__file__).resolve().parents[1] / "tools" / "gate_config.json")
        if commits == "bot":
            commits = _bot_commits(SHA)
        return lg.Context(config=config, existing_hosts=[], labels=[], offline=True,
                          pr_author=author, commits=commits,
                          changed_record_count=count)

    def verdict(self, rec, author, commits="bot", count=1):
        results = lg.judge(rec, self.ctx(author, commits, count))
        return lg.overall(results), [r for r in results if r.rule == "provenance"]

    def bot_rec(self, raw=None, base=None, path=DISCORD_PATH, touching=(SHA,)):
        rec = lg.parse_record(path, raw if raw is not None else _discord_raw(), base)
        rec.touching = list(touching)
        return rec

    # ── the PR author ────────────────────────────────────────────────────────

    def test_hand_written_pr_adding_a_bot_stamped_discord_record_fails(self):
        rec = self.bot_rec()
        for human in (HUMAN, "randomstranger", "aithernet-bot"):
            verdict, proof = self.verdict(rec, human)
            self.assertEqual(verdict, lg.FAIL, human)
            self.assertEqual(proof[0].status, lg.FAIL)
            self.assertIn(human, proof[0].reason)

    def test_intake_bot_pr_adding_a_discord_record_passes(self):
        verdict, proof = self.verdict(self.bot_rec(), BOT)
        self.assertEqual(verdict, lg.PASS)
        self.assertEqual(proof[0].status, lg.PASS)

    def test_unknown_author_fails_closed(self):
        verdict, proof = self.verdict(self.bot_rec(), "")
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("unknown author", proof[0].reason)

    def test_bot_stamp_on_a_site_record_needs_the_bot(self):
        raw = {"id": "r1", "kind": "site", "url": "https://example.com/",
               "provenance": {"validated": {"method": "discord-bot"}}}
        verdict, proof = self.verdict(
            self.bot_rec(raw=raw, path="records/r1.json"), "someone")
        self.assertEqual(verdict, lg.FAIL)
        self.assertEqual(proof[0].status, lg.FAIL)

    # ── Bypass: a collaborator pushes onto an intake branch ──────────────────

    def test_collaborator_push_onto_an_intake_branch_fails(self):
        """The PR author stays the bot, but the commit is the human's."""
        commits = {SHA: {"author": HUMAN, "committer": HUMAN}}
        verdict, proof = self.verdict(self.bot_rec(), BOT, commits=commits)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("not the bot account", proof[0].reason)
        self.assertIn(SHA[:10], proof[0].reason)

    def test_bot_authored_but_human_committed_fails(self):
        commits = {SHA: {"author": BOT, "committer": HUMAN}}
        verdict, proof = self.verdict(self.bot_rec(), BOT, commits=commits)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("committed by", proof[0].reason)

    def test_human_authored_but_bot_committed_fails(self):
        commits = {SHA: {"author": HUMAN, "committer": BOT}}
        verdict, proof = self.verdict(self.bot_rec(), BOT, commits=commits)
        self.assertEqual(verdict, lg.FAIL)

    def test_missing_commit_identities_fail_closed(self):
        verdict, proof = self.verdict(self.bot_rec(), BOT, commits=None)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("not supplied", proof[0].reason)

    def test_commit_not_in_the_api_list_fails(self):
        verdict, proof = self.verdict(self.bot_rec(), BOT, commits={})
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("not in this PR's commit list", proof[0].reason)

    def test_record_with_no_touching_commit_fails(self):
        verdict, proof = self.verdict(self.bot_rec(touching=()), BOT)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("no commit", proof[0].reason)

    def test_commits_touching_ignores_merges(self):
        import shutil
        import subprocess
        import tempfile

        if not shutil.which("git"):
            self.skipTest("git not on PATH")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)

        def run(*args):
            return subprocess.run(["git", "-C", tmp, *args], check=True,
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace").stdout

        run("init", "-q")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        Path(tmp, "records").mkdir()
        Path(tmp, "records", "x.json").write_text("{}", encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "base")
        bot_sha = run("rev-parse", "HEAD").strip()
        run("checkout", "-q", "-b", "side")
        Path(tmp, "side.txt").write_text("y", encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "side")
        run("checkout", "-q", "-")
        Path(tmp, "main.txt").write_text("z", encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "main")
        run("merge", "--no-ff", "-m", "merge side", "side")
        merge_sha = run("rev-parse", "HEAD").strip()
        self.assertNotEqual(bot_sha, merge_sha)
        # Neither the side/main commits nor the merge change records/x.json, so
        # the merge must not be reported as one of the record's commits.
        touching = lg.commits_touching(tmp, bot_sha, "HEAD", ["records/x.json"])
        self.assertEqual(touching, [])
        self.assertNotIn(merge_sha, touching)

    # ── one record, at records/<id>.json ─────────────────────────────────────

    def test_intake_pr_with_more_than_one_record_fails(self):
        verdict, proof = self.verdict(self.bot_rec(), BOT, count=2)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("exactly one record", proof[0].reason)

    def test_changed_record_count_counts_deletions(self):
        """Smuggling a deletion into an intake PR is two changes, not one."""
        import shutil
        import subprocess
        import tempfile

        if not shutil.which("git"):
            self.skipTest("git not on PATH")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)

        def run(*args):
            subprocess.run(["git", "-C", tmp, *args], check=True, capture_output=True)

        run("init", "-q")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        (Path(tmp) / "records").mkdir()
        (Path(tmp) / "records" / "other.json").write_text("{}", encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "base")
        (Path(tmp) / "records" / "other.json").unlink()
        (Path(tmp) / "records" / f"{DISCORD_ID}.json").write_text(
            json.dumps(_discord_raw()), encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "head")
        self.assertEqual(lg.changed_record_count(tmp, "HEAD~1", "HEAD"), 2)

    def test_intake_pr_must_use_the_records_id_path(self):
        verdict, proof = self.verdict(
            self.bot_rec(path="records/discord_999.json"), BOT)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn(f"records/{DISCORD_ID}.json", proof[0].reason)

    # ── editing an existing bot record ───────────────────────────────────────

    def test_human_altering_an_existing_discord_stamp_fails(self):
        before = _discord_raw()
        after = _discord_raw()
        after["provenance"]["validated"]["at"] = "2026-12-01"
        rec = self.bot_rec(raw=after, base=before)
        self.assertEqual(self.verdict(rec, HUMAN)[0], lg.FAIL)

    def test_human_rekinding_a_discord_record_to_site_fails(self):
        before = _discord_raw()
        after = {"id": before["id"], "kind": "site", "url": "https://example.com/"}
        rec = self.bot_rec(raw=after, base=before)
        verdict, proof = self.verdict(rec, HUMAN)
        self.assertEqual(verdict, lg.FAIL)
        self.assertIn("changes a record", proof[0].reason)

    def test_bot_editing_an_existing_discord_stamp_passes(self):
        before = _discord_raw()
        after = _discord_raw()
        after["provenance"]["validated"]["at"] = "2026-12-01"
        verdict, proof = self.verdict(self.bot_rec(raw=after, base=before), BOT)
        self.assertEqual(verdict, lg.PASS)
        self.assertEqual(proof[0].status, lg.PASS)

    def test_plain_site_record_needs_no_bot(self):
        rec = lg.parse_record("records/r1.json",
                              {"id": "r1", "kind": "site", "url": "https://example.com/"})
        verdict, proof = self.verdict(rec, HUMAN)
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
        (records / f"{DISCORD_ID}.json").write_text(json.dumps(moved),
                                                    encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "head")
        head_sha = subprocess.check_output(
            ["git", "-C", tmp, "rev-parse", "HEAD"], text=True).strip()
        args = SimpleNamespace(root=tmp, records=None, base="base", head="HEAD")
        targets, _hosts = lg.load_targets(args)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].base_raw, _discord_raw())
        self.assertEqual(targets[0].touching, [head_sha])
        commits = _bot_commits(head_sha)
        self.assertEqual(self.verdict(targets[0], HUMAN, commits)[0], lg.FAIL)
        self.assertEqual(self.verdict(targets[0], BOT, commits)[0], lg.PASS)

    # ── Bypass: the PR's own workflow copy ───────────────────────────────────

    def workflow(self):
        return (Path(__file__).resolve().parents[1] / ".github" / "workflows"
                / "listing-gate.yml").read_text(encoding="utf-8")

    def test_workflow_runs_on_pull_request_target_not_pull_request(self):
        import re
        wf = self.workflow()
        self.assertIn("pull_request_target:", wf)
        # A bare `pull_request:` trigger would run the PR's own copy of this file.
        self.assertIsNone(re.search(r"(?m)^\s*pull_request\s*:\s*$", wf))
        self.assertIn("github.event_name == 'pull_request_target'", wf)

    def test_workflow_checks_out_only_the_base_commit(self):
        wf = self.workflow()
        self.assertIn("ref: ${{ github.event.pull_request.base.sha", wf)
        # The head is fetched as data and never checked out into the job.
        self.assertIn('git fetch --no-tags --force origin "pull/${PR}/head', wf)
        self.assertNotIn("github.event.pull_request.head.sha'", wf)
        self.assertIn("--commits-json", wf)

    def test_workflow_reads_author_and_commits_from_github(self):
        wf = self.workflow()
        self.assertIn("PR_AUTHOR: ${{ github.event.pull_request.user.login }}", wf)
        self.assertIn("repos/${REPO}/pulls/${PR}/commits", wf)
        self.assertIn("--pr-author", wf)

    def test_workflow_fails_closed_when_the_base_has_no_gate(self):
        wf = self.workflow()
        # No bootstrap that would run the PR's own gate.
        self.assertNotIn("using the PR's (bootstrap)", wf)
        self.assertIn("base commit has no listing gate", wf)
        self.assertIn('python "$GATE"', wf)

    def test_intake_pr_author_is_the_github_token_identity(self):
        config = self.ctx("").config
        self.assertEqual(config["intake_pr_authors"], [BOT])
        self.assertEqual(config["bot_commit_logins"], [BOT])
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
