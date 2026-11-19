#!/usr/bin/env python3
"""Gate orchestration: diff parsing, health verdicts, exemption, output; no network."""

from __future__ import annotations

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

    def test_lookalike_rule_fails_on_brand_typosquat(self):
        ctx = self.ctx(config=lg.rep.load_config(
            Path(__file__).resolve().parents[1] / "tools" / "gate_config.json"))
        result = lg.lookalike_rule(self.record(url="https://paypa1.com/"), ctx)
        self.assertEqual(result.status, lg.FAIL)

    def test_judge_offline_reports_skip_not_failure(self):
        results = lg.judge(self.record(), self.ctx())
        self.assertEqual(lg.overall(results), lg.PASS)
        self.assertTrue(any(r.status == lg.SKIP for r in results))


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
