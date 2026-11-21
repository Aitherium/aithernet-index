#!/usr/bin/env python3
"""Keyless reputation and look-alike rules for the listing gate.

The verdicts are PURE functions over the payload shapes that the keyless
sources return (documented in the constants below), so every rule has a test
with a fixture and no network. The ``check_*`` functions are thin fetchers that
produce those payloads; they take their fetcher as an argument for the same
reason.

Sources used (keyless, so they run in GitHub Actions with the default token):
  * Cloudflare DoH filtered (security.cloudflare-dns.com, 1.1.1.2) vs
    standard (cloudflare-dns.com, 1.1.1.1): filtered answers 0.0.0.0 /
    NXDOMAIN / EDE(16) Censored while standard answers records => blocked.
  * Quad9 filtered 9.9.9.9 vs unfiltered 9.9.9.10 over plain DNS.
  * RDAP (rdap.org -> registry) registration date for domain age.
  * AlienVault OTX general (pulse_info.count; the board's own rule:
    >5 HIGH, >0 MEDIUM, 0 LOW).
  * OpenPhish feed + malware-filter phishing domain list (exact host).
  * URLhaus: KEYED since 2026 (measured 401); kept so a keyless 200 would be
    honoured, and reported as "skip" otherwise. No new CI secret is created.

Disabled by owner rule: Google Safe Browsing, VirusTotal, PhishTank,
Spamhaus DQS, abuse.ch ThreatFox - all keyed.
"""

from __future__ import annotations

import datetime as _dt
import json
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import gate_net
from gate_net import DNSResult, Fetch, fetch, fetch_json

PASS, FAIL, SKIP = "pass", "fail", "skip"

DEFAULT_CONFIG = Path(__file__).resolve().parent / "gate_config.json"


def load_config(path: "Path | str" = DEFAULT_CONFIG) -> dict:
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


# ── DNS: filtered vs unfiltered ───────────────────────────────────────────────

def parse_doh(payload) -> "Tuple[Optional[int], List[str], bool]":
    """(status, A records, censored-comment) from a Cloudflare/Google DoH body."""
    if not isinstance(payload, dict):
        return None, [], False
    status = payload.get("Status")
    status = status if isinstance(status, int) else None
    ips: List[str] = []
    for answer in payload.get("Answer") or []:
        if isinstance(answer, dict) and answer.get("type") == 1 and answer.get("data"):
            ips.append(str(answer["data"]))
    comment = json.dumps(payload.get("Comment") or "")
    return status, ips, "EDE(16)" in comment or "censored" in comment.lower()


def dns_diff_verdict(filtered, standard) -> "Tuple[str, str]":
    """Cloudflare filtered (1.1.1.2) vs standard (1.1.1.1)."""
    f_status, f_ips, f_censored = parse_doh(filtered)
    s_status, s_ips, _ = parse_doh(standard)
    if f_status is None or s_status is None:
        return SKIP, "no Cloudflare DoH answer (network or filter unavailable)"
    real_standard = [ip for ip in s_ips if ip not in ("0.0.0.0", "::")]
    if not real_standard:
        return SKIP, "standard resolver returned no records; cannot diff"
    if f_status != 0:
        return FAIL, f"filtered resolver status {f_status} while standard answers {real_standard[:2]}"
    if f_ips and all(ip == "0.0.0.0" for ip in f_ips):
        return FAIL, f"filtered resolver answers 0.0.0.0 while standard answers {real_standard[:2]}"
    if f_censored and not f_ips:
        return FAIL, "filtered resolver censors the domain (EDE(16)) while standard answers"
    if set(f_ips) & set(real_standard):
        return PASS, "filtered and standard answers agree (no poisoned verdict)"
    return SKIP, "filtered answer differs without a block marker; no verdict"


def quad9_verdict(filtered: DNSResult, unfiltered: DNSResult) -> "Tuple[str, str]":
    """Quad9 filtered (9.9.9.9) vs unfiltered (9.9.9.10)."""
    if filtered.error or unfiltered.error:
        reason = filtered.error or unfiltered.error
        return SKIP, f"plain DNS unavailable: {reason}"
    if filtered.rcode != 0 or filtered.ips == ["0.0.0.0"] or not filtered.ips:
        if unfiltered.answered:
            return FAIL, (f"Quad9 filtered rcode={filtered.rcode} ips={filtered.ips or '(none)'} "
                          f"while unfiltered resolves {unfiltered.ips[:2]}")
        return SKIP, "both Quad9 resolvers fail; no verdict"
    if set(filtered.ips) & set(unfiltered.ips):
        return PASS, "Quad9 filtered and unfiltered agree"
    return SKIP, "Quad9 answers differ without a block marker; no verdict"


def check_dns(host: str, get_json=fetch_json, dns_a=gate_net.dns_query_a,
              timeout: float = 15) -> "Tuple[str, str]":
    quoted = gate_net.urlencode(host)
    filtered, f_fetch = get_json(
        f"https://security.cloudflare-dns.com/dns-query?name={quoted}&type=A",
        timeout=timeout, headers={"Accept": "application/dns-json"})
    standard, s_fetch = get_json(
        f"https://cloudflare-dns.com/dns-query?name={quoted}&type=A",
        timeout=timeout, headers={"Accept": "application/dns-json"})
    cf = dns_diff_verdict(filtered if f_fetch.ok else None,
                           standard if s_fetch.ok else None)
    q9 = quad9_verdict(dns_a(host, "9.9.9.9"), dns_a(host, "9.9.9.10"))
    if FAIL in (cf[0], q9[0]):
        winner = cf if cf[0] == FAIL else q9
        return FAIL, winner[1]
    if cf[0] == PASS or q9[0] == PASS:
        return PASS, f"cloudflare: {cf[1]}; quad9: {q9[1]}"
    return SKIP, f"cloudflare: {cf[1]}; quad9: {q9[1]}"


# ── RDAP domain age ───────────────────────────────────────────────────────────

def rdap_registration(rdap, today: _dt.date) -> "Tuple[Optional[int], str]":
    """(age in days, reason) from an RDAP domain object's registration event."""
    if not isinstance(rdap, dict):
        return None, "no RDAP object"
    when: "Optional[_dt.date]" = None
    for event in rdap.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            raw = str(event.get("eventDate") or "")
            try:
                when = _dt.date.fromisoformat(raw[:10])
            except ValueError:
                return None, f"unparsable registration date {raw!r}"
    if when is None:
        return None, "RDAP object has no registration event"
    return (today - when).days, f"registered {when.isoformat()}"


def rdap_age_verdict(age: "Optional[int]", max_age_days: int,
                     label_accepted: bool) -> "Tuple[str, str]":
    if age is None:
        return SKIP, "no RDAP age; no verdict (a missing answer is never a pass)"
    if age < 0:
        return FAIL, f"registration date is in the future ({age} days)"
    if age < max_age_days:
        if label_accepted:
            return PASS, f"domain is {age} days old; maintainer label accepts it"
        return FAIL, (f"domain is {age} days old (< {max_age_days}); a maintainer "
                      f"label is required to list a new domain")
    return PASS, f"domain is {age} days old"


def check_rdap(host: str, config: dict, get_json=fetch_json,
               today: "Optional[_dt.date]" = None, timeout: float = 15):
    domain = registrable_domain(host, config["multi_suffixes"])
    payload, got = get_json(f"https://rdap.org/domain/{gate_net.urlencode(domain)}",
                            timeout=timeout)
    age, reason = rdap_registration(payload if got.ok else None,
                                    today or _dt.date.today())
    return age, f"{reason} ({domain})", payload


# ── AlienVault OTX ────────────────────────────────────────────────────────────

def otx_verdict(otx) -> "Tuple[str, str]":
    if not isinstance(otx, dict):
        return SKIP, "no OTX answer"
    for row in otx.get("validation") or []:
        text = f"{row.get('source', '')} {row.get('name', '')} {row.get('message', '')}".lower()
        if "whitelist" in text:
            return PASS, f"OTX whitelist: {row.get('message', 'whitelisted')}"
    pulses = otx.get("pulse_info") or {}
    count = pulses.get("count")
    if not isinstance(count, int):
        return SKIP, "OTX answer has no pulse count"
    if count > 5:
        return FAIL, f"OTX reports {count} pulses (HIGH)"
    if count > 0:
        return PASS, f"OTX reports {count} pulse(s) (MEDIUM, not a block)"
    return PASS, "OTX reports 0 pulses (LOW)"


def check_otx(host: str, get_json=fetch_json, timeout: float = 15):
    payload, got = get_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{gate_net.urlencode(host)}/general",
        timeout=timeout)
    return otx_verdict(payload if got.ok else None)


# ── Phishing feeds ────────────────────────────────────────────────────────────

def feed_hosts(openphish_text: "Optional[str]") -> "set[str]":
    hosts = set()
    for line in (openphish_text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            host = (urllib.parse.urlsplit(line).hostname or "").lower()
        except ValueError:
            host = ""
        if host:
            hosts.add(host)
    return hosts


def domain_list(text: "Optional[str]") -> "set[str]":
    out = set()
    for line in (text or "").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def feeds_verdict(host: str, openphish_text: "Optional[str]",
                  domains_text: "Optional[str]") -> "Tuple[str, str]":
    host = host.lower()
    hits = []
    if openphish_text is not None and host in feed_hosts(openphish_text):
        hits.append("OpenPhish")
    if domains_text is not None and host in domain_list(domains_text):
        hits.append("malware-filter phishing list")
    if hits:
        return FAIL, f"listed as active phishing by {', '.join(hits)}"
    if openphish_text is None and domains_text is None:
        return SKIP, "phishing feeds unreachable"
    return PASS, "not on the OpenPhish or malware-filter phishing lists"


def fetch_text(url: str, timeout: float = 30) -> "Optional[str]":
    got = fetch(url, timeout=timeout, limit=4 * 1024 * 1024)
    return got.body if got.ok else None


def load_feeds(get_text=fetch_text) -> dict:
    return {
        "openphish": get_text("https://openphish.com/feed.txt"),
        "domains": get_text(
            "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt"),
    }


# ── URLhaus (keyed since 2026; reported, never invented a secret) ─────────────

def urlhaus_verdict(status: int, payload) -> "Tuple[str, str]":
    if status in (401, 403):
        return SKIP, ("URLhaus requires an Auth-Key (measured 401 keyless); "
                      "no keyless verdict, no new CI secret")
    if status != 200 or not isinstance(payload, dict):
        return SKIP, f"URLhaus answered {status}; no verdict"
    state = payload.get("query_status")
    if state == "is_host":
        return FAIL, f"URLhaus lists the host ({payload.get('urls_count', '?')} urls)"
    if state == "no_results":
        return PASS, "URLhaus has no entry for the host"
    return SKIP, f"URLhaus query_status={state!r}; no verdict"


def check_urlhaus(host: str, timeout: float = 15):
    body = b"host=" + urllib.parse.quote(host, safe="").encode()
    got = fetch("https://urlhaus-api.abuse.ch/v1/host/", timeout=timeout, data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        payload = json.loads(got.body) if got.body else None
    except ValueError:
        payload = None
    return urlhaus_verdict(got.status, payload)


# ── Look-alike / poisoned names ──────────────────────────────────────────────

_CONFUSE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                          "7": "t", "$": "s", "@": "a", "8": "b"})
_MIXED_HINTS = ("а", "е", "о", "р", "с", "у",
                "і", "һ", "ԁ")


def registrable_domain(host: str, multi_suffixes: Sequence[str]) -> str:
    """eTLD+1 using the configured multi-part suffix subset (no PSL download)."""
    labels = [x for x in host.lower().strip(".").split(".") if x]
    if not labels:
        return ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in set(multi_suffixes):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else labels[0]


def registrable_label(host: str, multi_suffixes: Sequence[str]) -> str:
    reg = registrable_domain(host, multi_suffixes)
    return reg.split(".")[0] if reg else ""


def idna_label(label: str) -> str:
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def skeleton(label: str) -> str:
    text = idna_label(label).lower().translate(_CONFUSE)
    text = text.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    text = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in text if not unicodedata.combining(ch) and ch.isprintable())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _targets(existing_hosts: Iterable[str], protected_domains: Iterable[str],
             multi_suffixes: Sequence[str]) -> "List[Tuple[str, str]]":
    out: "List[Tuple[str, str]]" = []
    seen = set()
    for host in list(existing_hosts) + list(protected_domains):
        if not host:
            continue
        reg = registrable_domain(host, multi_suffixes)
        if reg and reg not in seen:
            seen.add(reg)
            out.append((reg, reg.split(".")[0]))
    return out


def lookalike_verdict(host: str, existing_hosts: Iterable[str], config: dict) -> "Tuple[str, str]":
    """Typosquat, homoglyph, IDN confusable or embedded brand on another domain."""
    multi = config.get("multi_suffixes", [])
    host = host.lower().strip(".")
    if not host:
        return SKIP, "no host to compare"
    cand_reg = registrable_domain(host, multi)
    cand_label = registrable_label(host, multi)
    targets = _targets(existing_hosts, config.get("protected_domains", []), multi)
    protected_regs = {reg for reg, _ in targets}

    labels = host.split(".")
    for label in labels:
        if label.startswith("xn--"):
            decoded = idna_label(label)
            if any(skeleton(decoded) == skeleton(target) for _, target in targets):
                return FAIL, f"IDN label {label!r} is a homoglyph of a protected name"
            if any(ch in decoded.lower() for ch in _MIXED_HINTS):
                return FAIL, f"IDN label {label!r} mixes scripts (confusable)"

    if cand_reg in protected_regs:
        return PASS, f"{host} is inside an existing registrable domain ({cand_reg})"

    min_label = int(config.get("lookalike_min_label", 5))
    for reg, target in targets:
        if cand_reg == reg or len(target) < min_label:
            continue
        distance = levenshtein(cand_label, target)
        if distance <= 2:
            return FAIL, (f"{cand_label!r} is edit distance {distance} from the "
                          f"listed/protected name {target!r} ({reg})")
        if skeleton(cand_label) == skeleton(target):
            return FAIL, (f"{cand_label!r} is a homoglyph of the listed/protected "
                          f"name {target!r} ({reg})")
        if target in cand_label:
            return FAIL, (f"host embeds the name {target!r} but its registrable "
                          f"domain is {cand_reg}, not {reg}")

    for brand in config.get("brands", []):
        brand = brand.lower()
        if any(brand in label for label in labels) and cand_reg not in protected_regs:
            return FAIL, (f"host embeds the brand {brand!r} but its registrable "
                          f"domain is {cand_reg}")

    # A protected domain spelled inside another host: google.com.evil.example,
    # aitherium.com.login.example. The registrable domain must be that domain.
    padded = "." + host + "."
    for domain in config.get("protected_domains", []):
        domain = domain.lower()
        if ("." + domain + ".") in padded and cand_reg != registrable_domain(domain, multi):
            return FAIL, (f"host embeds the protected domain {domain!r} but its "
                          f"registrable domain is {cand_reg}")
    return PASS, f"{host} is not a look-alike of a listed or protected name"
