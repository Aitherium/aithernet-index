#!/usr/bin/env python3
"""Artifact rule: every backlink form counts, every look-alike does not.

No network: ``detect`` is pure and ``probe`` is driven by a fake fetcher.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import artifact_check  # noqa: E402
from gate_net import Fetch  # noqa: E402

RID = "example.com_garden"
HOST = artifact_check.INDEX_HOST


class DetectTests(unittest.TestCase):
    def test_well_known_counts(self):
        self.assertEqual(artifact_check.detect(RID, "<p>x</p>", [RID]).form, "well-known")

    def test_link_rel_counts(self):
        html = f'<html><head><link rel="aithernet" href="https://{HOST}/r/{RID}/"></head></html>'
        self.assertEqual(artifact_check.detect(RID, html, []).form, "link-rel")

    def test_meta_counts(self):
        html = f'<head><meta name="aithernet" content="{RID}"></head>'
        self.assertEqual(artifact_check.detect(RID, html, []).form, "meta")

    def test_visible_link_counts(self):
        html = f'<body><a href="https://{HOST}/r/{RID}">Listed on AitherNet</a></body>'
        self.assertEqual(artifact_check.detect(RID, html, []).form, "visible-link")

    def test_entry_page_path_counts(self):
        html = f'<body><a href="https://{HOST}/e/{RID}/">see</a></body>'
        self.assertEqual(artifact_check.detect(RID, html, []).form, "visible-link")

    def test_file_stem_spelling_counts(self):
        rid = "example.com:garden"
        html = f'<a href="https://{HOST}/r/example.com_garden">see</a>'
        self.assertEqual(artifact_check.detect(rid, html, []).form, "visible-link")

    def test_lookalikes_do_not_count(self):
        cases = {
            "other domain": f'<a href="https://evil.example/r/{RID}">x</a>',
            "suffix look-alike": f'<a href="https://{HOST}.evil.example/r/{RID}">x</a>',
            "prefix look-alike": f'<a href="https://not{HOST}/r/{RID}">x</a>',
            "http": f'<a href="http://{HOST}/r/{RID}">x</a>',
            "other id": f'<a href="https://{HOST}/r/other.example">x</a>',
            "hidden anchor": f'<a href="https://{HOST}/r/{RID}"></a>',
            "userinfo trick": f'<a href="https://{HOST}@evil.example/r/{RID}">x</a>',
            "id substring": f'<a href="https://{HOST}/r/{RID}-extra">x</a>',
            "port": f'<a href="https://{HOST}:8443/r/{RID}">x</a>',
            "wrong rel": f'<link rel="stylesheet" href="https://{HOST}/r/{RID}">',
        }
        for label, html in cases.items():
            with self.subTest(label):
                self.assertIsNone(artifact_check.detect(RID, html, []).form)

    def test_well_known_wrong_id_does_not_count(self):
        self.assertIsNone(artifact_check.detect(RID, "<p>x</p>", ["other.example"]).form)

    def test_meta_other_id_does_not_count(self):
        html = '<meta name="aithernet" content="other.example">'
        self.assertIsNone(artifact_check.detect(RID, html, []).form)

    def test_claimed_ids(self):
        self.assertEqual(artifact_check.claimed_ids(json.dumps({"records": [RID, "x"]})),
                         [RID, "x"])
        self.assertEqual(artifact_check.claimed_ids("<html>"), [])
        self.assertEqual(artifact_check.claimed_ids('{"records": "x"}'), [])


class ProbeTests(unittest.TestCase):
    def test_probe_reads_page_then_well_known(self):
        def fake_get(url, timeout=15, limit=262144):
            if url.endswith("/.well-known/aithernet.json"):
                return Fetch(200, json.dumps({"records": [RID]}), url)
            return Fetch(200, "<html><title>Garden</title></html>", url)

        page, art = artifact_check.probe(RID, "https://example.com/garden", get=fake_get)
        self.assertTrue(page.ok)
        self.assertEqual(art.form, "well-known")

    def test_probe_page_down_still_reports_reason(self):
        def fake_get(url, timeout=15, limit=262144):
            return Fetch(0, "", url, "connection refused")

        page, art = artifact_check.probe(RID, "https://example.com/", get=fake_get)
        self.assertFalse(page.ok)
        self.assertFalse(art.ok)
        self.assertIn("no backlink", art.reason)


if __name__ == "__main__":
    unittest.main()
