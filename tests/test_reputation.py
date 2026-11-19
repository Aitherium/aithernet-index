#!/usr/bin/env python3
"""Reputation and look-alike rules, each against a fixture; no network."""

from __future__ import annotations

import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import reputation as rep  # noqa: E402
from gate_net import DNSResult, Fetch  # noqa: E402

TODAY = dt.date(2026, 11, 19)
CONFIG = rep.load_config(Path(__file__).resolve().parents[1] / "tools" / "gate_config.json")

EXAMPLE_DOH = {
    "Status": 0,
    "Answer": [
        {"name": "example.com", "type": 1, "TTL": 225, "data": "104.20.23.154"},
        {"name": "example.com", "type": 1, "TTL": 225, "data": "172.66.147.243"},
    ],
}
MALWARE_FILTERED = {
    "Status": 0,
    "Answer": [{"name": "malware.wicar.org", "type": 1, "TTL": 60, "data": "0.0.0.0"}],
    "Comment": ["EDE(16): Censored"],
}
MALWARE_STANDARD = {
    "Status": 0,
    "Answer": [
        {"name": "malware.wicar.org", "type": 5, "TTL": 60, "data": "wicarmalware.nfshost.com"},
        {"name": "wicarmalware.nfshost.com", "type": 1, "TTL": 60, "data": "208.94.116.246"},
    ],
}
NXDOMAIN = {"Status": 3}
RDAP = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
}
RDAP_NEW = {
    "events": [
        {"eventAction": "registration", "eventDate": "2026-11-06T14:46:48.822Z"},
        {"eventAction": "expiration", "eventDate": "2027-11-06T14:46:48.822Z"},
    ],
}
OTX_HIGH = {"pulse_info": {"count": 6}, "validation": []}
OTX_MEDIUM = {"pulse_info": {"count": 3}, "validation": []}
OTX_WHITELIST = {"pulse_info": {"count": 4},
                 "validation": [{"source": "whitelist",
                                 "message": "Whitelisted domain example.com"}]}


class DnsTests(unittest.TestCase):
    def test_parse_doh(self):
        self.assertEqual(rep.parse_doh(EXAMPLE_DOH), (0, EXAMPLE_DOH["Answer"][0:0] or
                         ["104.20.23.154", "172.66.147.243"], False))

    def test_blocked_domain_fails(self):
        status, why = rep.dns_diff_verdict(MALWARE_FILTERED, MALWARE_STANDARD)
        self.assertEqual(status, rep.FAIL)
        self.assertIn("0.0.0.0", why)

    def test_nxdomain_filtered_fails(self):
        status, _ = rep.dns_diff_verdict(NXDOMAIN, EXAMPLE_DOH)
        self.assertEqual(status, rep.FAIL)

    def test_identical_answers_pass(self):
        status, _ = rep.dns_diff_verdict(EXAMPLE_DOH, EXAMPLE_DOH)
        self.assertEqual(status, rep.PASS)

    def test_standard_empty_is_skip(self):
        status, _ = rep.dns_diff_verdict(EXAMPLE_DOH, NXDOMAIN)
        self.assertEqual(status, rep.SKIP)

    def test_quad9_blocked_fails(self):
        status, _ = rep.quad9_verdict(DNSResult(0, ["0.0.0.0"]),
                                      DNSResult(0, ["104.20.23.154"]))
        self.assertEqual(status, rep.FAIL)

    def test_quad9_nxdomain_fails(self):
        status, _ = rep.quad9_verdict(DNSResult(3, []), DNSResult(0, ["1.2.3.4"]))
        self.assertEqual(status, rep.FAIL)

    def test_quad9_agreement_passes(self):
        status, _ = rep.quad9_verdict(DNSResult(0, ["1.2.3.4"]), DNSResult(0, ["1.2.3.4"]))
        self.assertEqual(status, rep.PASS)

    def test_quad9_network_down_is_skip(self):
        status, _ = rep.quad9_verdict(DNSResult(-1, [], "timeout"),
                                      DNSResult(-1, [], "timeout"))
        self.assertEqual(status, rep.SKIP)

    def test_check_dns_uses_injected_sources(self):
        def get_json(url, timeout=15, headers=None):
            return (MALWARE_FILTERED if "security." in url else MALWARE_STANDARD,
                    Fetch(200, "", url))

        status, _ = rep.check_dns("malware.wicar.org", get_json=get_json,
                                  dns_a=lambda name, server: DNSResult(0, ["1.2.3.4"]))
        self.assertEqual(status, rep.FAIL)


class RdapTests(unittest.TestCase):
    def test_old_domain_age(self):
        age, _ = rep.rdap_registration(RDAP, TODAY)
        self.assertEqual(age, (TODAY - dt.date(1995, 8, 14)).days)

    def test_missing_registration_is_none(self):
        age, why = rep.rdap_registration({"events": []}, TODAY)
        self.assertIsNone(age)
        self.assertIn("no registration", why)

    def test_young_domain_fails_without_label(self):
        age, _ = rep.rdap_registration(RDAP_NEW, TODAY)
        status, why = rep.rdap_age_verdict(age, 30, False)
        self.assertEqual(status, rep.FAIL)
        self.assertIn("maintainer label", why)

    def test_young_domain_passes_with_label(self):
        age, _ = rep.rdap_registration(RDAP_NEW, TODAY)
        self.assertEqual(rep.rdap_age_verdict(age, 30, True)[0], rep.PASS)

    def test_old_domain_passes(self):
        self.assertEqual(rep.rdap_age_verdict(4000, 30, False)[0], rep.PASS)

    def test_no_age_is_skip(self):
        self.assertEqual(rep.rdap_age_verdict(None, 30, False)[0], rep.SKIP)

    def test_future_registration_fails(self):
        self.assertEqual(rep.rdap_age_verdict(-5, 30, False)[0], rep.FAIL)


class OtxTests(unittest.TestCase):
    def test_high_pulses_fail(self):
        self.assertEqual(rep.otx_verdict(OTX_HIGH)[0], rep.FAIL)

    def test_medium_pulses_pass(self):
        self.assertEqual(rep.otx_verdict(OTX_MEDIUM)[0], rep.PASS)

    def test_zero_pulses_pass(self):
        self.assertEqual(rep.otx_verdict({"pulse_info": {"count": 0}})[0], rep.PASS)

    def test_whitelist_passes(self):
        status, why = rep.otx_verdict(OTX_WHITELIST)
        self.assertEqual(status, rep.PASS)
        self.assertIn("whitelist", why.lower())

    def test_no_answer_is_skip(self):
        self.assertEqual(rep.otx_verdict(None)[0], rep.SKIP)


class FeedTests(unittest.TestCase):
    def test_openphish_hit_fails(self):
        text = "https://pufferparty.org/login\nhttps://other.example/x\n"
        self.assertEqual(rep.feeds_verdict("pufferparty.org", text, "")[0], rep.FAIL)

    def test_domain_list_hit_fails(self):
        self.assertEqual(rep.feeds_verdict("evil.example", "# title\n", "evil.example\n")[0],
                         rep.FAIL)

    def test_clean_passes(self):
        self.assertEqual(rep.feeds_verdict("pufferparty.org", "https://other.example/", "x\n")[0],
                         rep.PASS)

    def test_both_unreachable_is_skip(self):
        self.assertEqual(rep.feeds_verdict("x.example", None, None)[0], rep.SKIP)


class UrlhausTests(unittest.TestCase):
    def test_keyless_401_is_skip(self):
        status, why = rep.urlhaus_verdict(401, {"error": "Unauthorized"})
        self.assertEqual(status, rep.SKIP)
        self.assertIn("Auth-Key", why)

    def test_host_hit_fails(self):
        self.assertEqual(rep.urlhaus_verdict(200, {"query_status": "is_host",
                                                   "urls_count": 2})[0], rep.FAIL)

    def test_no_results_passes(self):
        self.assertEqual(rep.urlhaus_verdict(200, {"query_status": "no_results"})[0],
                         rep.PASS)


class LookalikeTests(unittest.TestCase):
    EXISTING = ["pufferparty.org", "notes.andymatuschak.org", "bestdaily.games",
                "lyz-code.github.io"]

    def check(self, host, existing=None):
        return rep.lookalike_verdict(host, existing or self.EXISTING, CONFIG)

    def test_unrelated_hosts_pass(self):
        for host in ("pufferparty.org", "bestdaily.games", "tax.com", "newthing.dev"):
            with self.subTest(host):
                self.assertEqual(self.check(host)[0], rep.PASS)

    def test_typosquat_of_listed_host_fails(self):
        self.assertEqual(self.check("bestdai1y.games")[0], rep.FAIL)
        self.assertEqual(self.check("bestdailly.games")[0], rep.FAIL)

    def test_typosquat_of_protected_brand_fails(self):
        self.assertEqual(self.check("paypa1.com")[0], rep.FAIL)

    def test_homoglyph_fails(self):
        self.assertEqual(self.check("g00gle.com")[0], rep.FAIL)

    def test_brand_embedded_in_other_domain_fails(self):
        self.assertEqual(self.check("discord-nitro.com")[0], rep.FAIL)

    def test_protected_domain_embedded_fails(self):
        status, why = self.check("google.com.evil.io")
        self.assertEqual(status, rep.FAIL)
        self.assertIn("protected domain", why)

    def test_same_registrable_domain_passes(self):
        self.assertEqual(self.check("blog.aitherium.com")[0], rep.PASS)

    def test_github_pages_subdomain_passes(self):
        self.assertEqual(self.check("newperson.github.io")[0], rep.PASS)

    def test_idn_mixed_script_fails(self):
        # xn--80ak6aa92e decodes to "аррӏе" (Cyrillic homograph of apple)
        status, _ = self.check("xn--80ak6aa92e.com")
        self.assertEqual(status, rep.FAIL)

    def test_registrable_domain_multi_suffix(self):
        self.assertEqual(rep.registrable_domain("foo.example.co.uk", CONFIG["multi_suffixes"]),
                         "example.co.uk")
        self.assertEqual(rep.registrable_domain("a.b.example.com", CONFIG["multi_suffixes"]),
                         "example.com")

    def test_levenshtein(self):
        self.assertEqual(rep.levenshtein("kitten", "sitting"), 3)
        self.assertEqual(rep.levenshtein("paypal", "paypa1"), 1)

    def test_skeleton_normalises_homoglyphs(self):
        self.assertEqual(rep.skeleton("g00gle"), rep.skeleton("google"))


if __name__ == "__main__":
    unittest.main()
