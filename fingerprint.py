#!/usr/bin/env python3
"""Content fingerprint for a listed page: what the entry looked like when it was trusted.

A listing is approved against a page. If that page is later swapped — the domain sold,
the garden replaced by a casino, the notes rewritten — the index should notice. This
module turns a page into a small, stable fingerprint:

    title            normalised <title>
    description      normalised <meta name="description">
    host             the host the URL ENDED on after redirects
    signature        a 64-slot MinHash of the visible text tokens
    tokens           how many distinct tokens the page had (for reporting)
    text_sha256      exact hash of the normalised text (equality shortcut)

Two fingerprints are compared with token-set Jaccard similarity, estimated from the
MinHash signatures. The estimator is unbiased, so the same threshold means the same
thing for a 200-word note and a 50k-word wiki. Stdlib only.

    fp = page(html, "example.com")
    similarity(fp, old) >= 0.5      # has the page essentially survived?
"""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Optional

# Slots in the MinHash signature. 64 puts the standard error of the Jaccard estimate
# near 1/sqrt(64) = 0.125, which is plenty for a 0.5 decision on a daily check.
SIGNATURE_SLOTS = 64

# Below this Jaccard similarity the page is not the page that was approved.
SIMILARITY_THRESHOLD = 0.5

_TOKEN = re.compile(r"[a-z0-9]+")
_WS = re.compile(r"\s+")
# Elements whose text is not visible prose and must never count toward similarity.
_SKIP = {"script", "style", "noscript", "svg", "template"}


def _norm(value: Optional[str]) -> str:
    """Collapse whitespace and lowercase. Never None, so comparisons are total."""
    return _WS.sub(" ", (value or "")).strip().lower()


def tokens(text: str) -> "list[str]":
    return _TOKEN.findall((text or "").lower())


def _h(token: str, slot: int) -> int:
    raw = hashlib.blake2b(f"{slot}\x00{token}".encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(raw, "big")


def signature(tok: "list[str]", slots: int = SIGNATURE_SLOTS) -> "list[int]":
    """MinHash signature: slot i = min hash of every distinct token under permutation i."""
    uniq = set(tok)
    if not uniq:
        return [0] * slots
    return [min(_h(t, i) for t in uniq) for i in range(slots)]


def jaccard(a: "list[int]", b: "list[int]") -> float:
    """Estimated Jaccard similarity of two token sets. Identical -> 1.0, disjoint -> 0.0."""
    if not a or not b:
        return 0.0 if (a or b) else 1.0
    if len(a) != len(b):
        raise ValueError("signatures have different lengths")
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


class _PageText(HTMLParser):
    """Collects <title>, meta description, and the visible text, skipping script/style."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: "list[str]" = []
        self.description: Optional[str] = None
        self.text_parts: "list[str]" = []
        self._in_title = 0
        self._in_head = 0
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: "list[tuple[str, Optional[str]]]") -> None:
        if tag == "title":
            self._in_title += 1
        elif tag == "head":
            self._in_head += 1
        elif tag in _SKIP:
            self._skip += 1
        elif tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            if a.get("name", "").strip().lower() == "description" and self.description is None:
                self.description = a.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self._in_title -= 1
        elif tag == "head" and self._in_head:
            self._in_head -= 1
        elif tag in _SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        elif not self._in_head and not self._skip:
            self.text_parts.append(data)


def page(html: str, final_host: str) -> dict:
    """The fingerprint stored at listing time and refreshed on every passing re-check."""
    p = _PageText()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML is data, not a crash
        pass
    text = _norm(" ".join(p.text_parts))
    tok = tokens(text)
    return {
        "title": _norm(" ".join(p.title_parts)),
        "description": _norm(p.description),
        "host": (final_host or "").strip().lower(),
        "tokens": len(set(tok)),
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "signature": signature(tok),
    }


def drift(old: dict, new: dict) -> "tuple[str, float]":
    """Compare a baseline with a fresh fingerprint.

    Returns (kind, similarity) where kind is one of "same", "host-changed",
    "content-changed", "changed". A host change is reported before content, because a
    domain that now redirects somewhere else is a different site whatever it says.
    """
    sim = jaccard(old.get("signature") or [], new.get("signature") or [])
    old_host = (old.get("host") or "").lower()
    new_host = (new.get("host") or "").lower()
    if old_host and new_host and old_host != new_host:
        return "host-changed", sim
    if sim < SIMILARITY_THRESHOLD:
        return "content-changed", sim
    if old.get("title") != new.get("title") or old.get("description") != new.get("description"):
        # A retitled page with the same text is a normal edit, not a swap: report it
        # so a maintainer can look, but it never reaches the threshold on its own.
        return "changed", sim
    return "same", sim


def self_test() -> int:
    body = ("one two three four five six seven eight nine ten "
            "eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen")
    base = ("<html><head><title>My  Garden</title><meta name='description' content='Notes on X'>"
            "</head><body><h1>Hello</h1><p>" + body + "</p>"
            "<script>var hidden = 'do not count me';</script></body></html>")
    a = page(base, "a.example")
    b = page(base.replace("one two", "one 2nd"), "a.example")
    c = page("<html><head><title>Casino</title></head><body><p>bet now win big</p></body></html>",
             "a.example")
    d = page(base, "b.example")
    ok = a["title"] == "my garden" and a["description"] == "notes on x"
    ok &= a["tokens"] == 19          # "hello" + eighteen body words; script text excluded
    ok &= jaccard(a["signature"], b["signature"]) > 0.8
    ok &= jaccard(a["signature"], c["signature"]) < 0.5
    ok &= drift(a, b)[0] == "same"
    ok &= drift(a, c)[0] == "content-changed"
    ok &= drift(a, d)[0] == "host-changed"
    ok &= jaccard(signature(tokens("alpha beta gamma")),
                  signature(tokens("alpha beta gamma"))) == 1.0
    ok &= jaccard(signature(tokens("alpha beta")), signature(tokens("gamma delta"))) == 0.0
    print("PASS fingerprint" if ok else "FAIL fingerprint")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(self_test())
