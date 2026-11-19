#!/usr/bin/env python3
"""Content fingerprint for a listed page: what the entry looked like when it was trusted.

A listing is approved against a page. If that page is later swapped — the domain sold,
the garden replaced by a casino, the notes rewritten — the index should notice. This
module turns a page into a small, stable fingerprint:

    title            normalised <title>
    description      normalised <meta name="description">
    host             the host the URL ENDED on after redirects
    redirect_host    host a client-side redirect (meta refresh / location=) points at
    signature        a 64-slot MinHash of the main visible text tokens
    tokens           how many distinct tokens the main text had (for reporting)
    bloom            a compact Bloom filter of the same tokens (containment checking)
    assets_sha       identity of a page with NO extractable text (images/scripts/DOM)
    text_sha256      exact hash of the normalised main text (equality shortcut)

Two fingerprints are compared with token-set Jaccard similarity, estimated from the
MinHash signatures. The estimator is unbiased, so the same threshold means the same
thing for a 200-word note and a 50k-word wiki.

Two things the first version of this module got wrong, and this one handles:

* **Boilerplate dilution.** A shared nav/footer used to be counted as "content", so a
  page whose entire body was replaced could still score above the threshold. The text
  now comes from the main region only: ``<main>``/``<article>`` when present, otherwise
  the body with ``nav``/``header``/``footer``/``aside`` removed. A Bloom containment
  guard additionally fails the entry when most of the *approved* page's words are gone.
* **Opaque pages.** A page with no extractable text (a photo portfolio, a JS shell)
  used to hand every page the same all-zero signature, so two unrelated pages compared
  1.0 ("same"). Empty token sets now compare 0.0, and a text-less page is identified by
  ``assets_sha`` (image alt/src, element ids/classes, inline script text, title). A
  different image-only page or a different JS shell therefore reports ``content-changed``
  instead of hiding behind a shared empty signature.

Stdlib only.

    fp = page(html, "example.com")
    similarity(fp, old)              # has the page essentially survived?
"""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Optional

# Slots in the MinHash signature. 64 puts the standard error of the Jaccard estimate
# near 1/sqrt(64) = 0.125, which is plenty for a 0.5 decision on a daily check.
SIGNATURE_SLOTS = 64

# Below this Jaccard similarity the page is not the page that was approved. Raised from
# 0.5: with a shared template, a fully replaced body can share half its words and still
# be a different site. Main-region extraction does most of the work; this is the guard
# for templates that are not semantic nav/footer elements.
SIMILARITY_THRESHOLD = 0.65

# How much of the approved page's word set must still appear anywhere on the new page.
# Otherwise a body swap hidden by a large shared template passes on Jaccard alone.
COVERAGE_THRESHOLD = 0.60

# A 2048-bit Bloom filter of the main-text tokens: 512 hex characters, enough to ask
# "is the old page's vocabulary still here?" without storing the tokens themselves.
BLOOM_BITS = 2048
BLOOM_K = 3

_TOKEN = re.compile(r"[a-z0-9]+")
_WS = re.compile(r"\s+")
_META_REFRESH = re.compile(r"url\s*=\s*(['\"]?)([^'\";]+)", re.IGNORECASE)
_JS_REDIRECT = re.compile(
    r"(?:window\.)?location(?:\.href)?\s*(?:=|\.replace\s*\()\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE)
# Elements whose text is not visible prose and must never count toward similarity.
_SKIP = {"script", "style", "noscript", "svg", "template"}
# Page chrome: repeated on every page of a site, therefore not evidence of *this* page.
_CHROME = {"nav", "header", "footer", "aside"}
_MAIN = {"main", "article"}


def _norm(value: Optional[str]) -> str:
    """Collapse whitespace and lowercase. Never None, so comparisons are total."""
    return _WS.sub(" ", (value or "")).strip().lower()


def _host(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def tokens(text: str) -> "list[str]":
    return _TOKEN.findall((text or "").lower())


def _h(token: str, slot: int) -> int:
    raw = hashlib.blake2b(f"{slot}\x00{token}".encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(raw, "big")


def signature(tok: "list[str]", slots: int = SIGNATURE_SLOTS) -> "list[int]":
    """MinHash signature: slot i = min hash of every distinct token under permutation i.

    An empty token set returns ``[]``, never a constant signature: two empty sets must
    not look identical (drift() handles the opaque case explicitly).
    """
    uniq = set(tok)
    if not uniq:
        return []
    return [min(_h(t, i) for t in uniq) for i in range(slots)]


def jaccard(a: "list[int]", b: "list[int]") -> float:
    """Estimated Jaccard similarity of two token sets. Disjoint or empty -> 0.0."""
    if not a or not b:
        return 0.0
    if len(a) != len(b):
        raise ValueError("signatures have different lengths")
    return sum(1 for x, y in zip(a, b) if x == y) / len(a)


def _bit(token: str) -> int:
    raw = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(raw, "big") % BLOOM_BITS


def bloom(tok: "list[str]") -> str:
    """A compact set of the tokens: 2048 bits as hex. Empty token set -> ''."""
    uniq = set(tok)
    if not uniq:
        return ""
    bits = 0
    for t in uniq:
        raw = int.from_bytes(hashlib.blake2b(t.encode("utf-8"), digest_size=8).digest(),
                             "big")
        for k in range(BLOOM_K):
            bits |= 1 << ((raw >> (k * 16)) % BLOOM_BITS)
    return format(bits, "x").zfill(BLOOM_BITS // 4)


def _bits(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def coverage(old: Optional[str], new: Optional[str]) -> Optional[float]:
    """Fraction of the *old* page's token bits that are also set in the new page."""
    a, b = _bits(old), _bits(new)
    if a is None or b is None or a.bit_count() == 0:
        return None
    return (a & b).bit_count() / a.bit_count()


class _PageText(HTMLParser):
    """Collects title, description, main/body text, assets and redirect targets."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: "list[str]" = []
        self.description: Optional[str] = None
        self.main_parts: "list[str]" = []
        self.body_parts: "list[str]" = []
        self.media_parts: "list[str]" = []
        self.opaque_parts: "list[str]" = []
        self.redirects: "list[str]" = []
        self._in_title = 0
        self._in_head = 0
        self._skip_tags: "list[str]" = []
        self._chrome_tags: "list[str]" = []
        self._main_tags: "list[str]" = []
        self._in_script = False
        self._script_buf: "list[str]" = []

    @staticmethod
    def _drop(tags: "list[str]", tag: str) -> None:
        for i in range(len(tags) - 1, -1, -1):
            if tags[i] == tag:
                del tags[i]
                return

    def handle_starttag(self, tag: str, attrs: "list[tuple[str, Optional[str]]]") -> None:
        tag = tag.lower()
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            self._skip_tags.append("script")
            self._in_script = True
            self._script_buf = []
            if a.get("src"):
                self.opaque_parts.append("script:" + a["src"])
            return
        if tag in _SKIP:
            self._skip_tags.append(tag)
            return
        if self._skip_tags:
            return
        if tag == "title":
            self._in_title += 1
        if tag == "head":
            self._in_head += 1
        if tag in _MAIN:
            self._main_tags.append(tag)
        elif tag in _CHROME:
            self._chrome_tags.append(tag)
        elif tag == "meta":
            if a.get("name", "").strip().lower() == "description" and self.description is None:
                self.description = a.get("content", "")
            if a.get("http-equiv", "").strip().lower() == "refresh":
                m = _META_REFRESH.search(a.get("content", ""))
                if m:
                    self.redirects.append(m.group(2).strip())
        elif tag == "img":
            media = " ".join([a.get("alt", ""), a.get("src", "")])
            self.media_parts.append(media)
            self.opaque_parts.append("img:" + _norm(media))
        # The opaque identity of a text-less page: what its DOM and assets are made of.
        self.opaque_parts.append("el:" + tag + ":" + a.get("id", "") + "."
                                 + ".".join(sorted(a.get("class", "").split())))

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script":
            if self._in_script:
                js = "".join(self._script_buf)
                self._script_buf = []
                self._in_script = False
                self.opaque_parts.append("js:" + hashlib.sha256(
                    js.encode("utf-8", "replace")).hexdigest())
                m = _JS_REDIRECT.search(js)
                if m:
                    self.redirects.append(m.group(1).strip())
            self._drop(self._skip_tags, "script")
            return
        if tag in _SKIP:
            self._drop(self._skip_tags, tag)
            return
        if tag == "title" and self._in_title:
            self._in_title -= 1
        elif tag == "head" and self._in_head:
            self._in_head -= 1
        elif tag in _MAIN and self._main_tags:
            self._drop(self._main_tags, tag)
        elif tag in _CHROME and self._chrome_tags:
            self._drop(self._chrome_tags, tag)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)
            return
        if self._in_title:
            self.title_parts.append(data)
        elif not self._in_head and not self._skip_tags and not self._chrome_tags:
            if self._main_tags:
                self.main_parts.append(data)
            else:
                self.body_parts.append(data)


def page(html: str, final_host: str) -> dict:
    """The fingerprint stored at listing time and refreshed on every passing re-check."""
    p = _PageText()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML is data, not a crash
        pass
    main_text = _norm(" ".join(p.main_parts))
    body_text = _norm(" ".join(p.body_parts))
    text = main_text if tokens(main_text) else body_text
    tok = tokens(text)
    title = _norm(" ".join(p.title_parts))
    asset_src = "|".join(p.opaque_parts + ["title:" + title])
    media_src = "|".join(sorted(set(p.media_parts)))
    redirect_hosts = sorted({h for h in (_host(r) for r in p.redirects) if h})
    return {
        "title": title,
        "description": _norm(p.description),
        "host": (final_host or "").strip().lower(),
        "redirect_host": redirect_hosts[0] if redirect_hosts else "",
        "tokens": len(set(tok)),
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "signature": signature(tok),
        "bloom": bloom(tok),
        "assets_sha": hashlib.sha256(asset_src.encode("utf-8", "replace")).hexdigest(),
        # Images only. Cheaper and steadier than assets_sha for comparing two fetches of
        # the same page (element ids and inline nonces change per request).
        "media_sha": hashlib.sha256(media_src.encode("utf-8", "replace")).hexdigest(),
    }


def drift(old: dict, new: dict) -> "tuple[str, float]":
    """Compare a baseline with a fresh fingerprint.

    Returns (kind, similarity) where kind is one of "same", "host-changed",
    "content-changed", "changed". A host change is reported before content, because a
    domain that now redirects somewhere else is a different site whatever it says.
    """
    old_host = (old.get("host") or "").lower()
    new_host = (new.get("host") or "").lower()
    redirect = (new.get("redirect_host") or "").lower()
    if redirect and ((old_host and redirect != old_host)
                     or (new_host and redirect != new_host)):
        return "host-changed", 0.0
    if old_host and new_host and old_host != new_host:
        return "host-changed", 0.0

    old_tok = old.get("tokens")
    new_tok = new.get("tokens")
    # Older state files carried a signature but not the token count: treat a non-empty
    # signature as a text page so those baselines keep working.
    if old_tok is None:
        old_tok = len(old.get("signature") or [])
    if new_tok is None:
        new_tok = len(new.get("signature") or [])
    old_tok, new_tok = int(old_tok or 0), int(new_tok or 0)
    if old_tok == 0 or new_tok == 0:
        if (old_tok == 0) != (new_tok == 0):
            return "content-changed", 0.0
        a, b = old.get("assets_sha"), new.get("assets_sha")
        if a and b:
            return ("same", 1.0) if a == b else ("content-changed", 0.0)
        return "same", 1.0

    sim = jaccard(old.get("signature") or [], new.get("signature") or [])
    cov = coverage(old.get("bloom"), new.get("bloom"))
    if sim < SIMILARITY_THRESHOLD or (cov is not None and cov < COVERAGE_THRESHOLD):
        return "content-changed", sim
    if old.get("title") != new.get("title") or old.get("description") != new.get("description"):
        # A retitled page with the same text is a normal edit, not a swap: report it
        # so a maintainer can look, but it never reaches the threshold on its own.
        return "changed", sim
    return "same", sim


def self_test() -> int:
    ok = True

    def check(label, got, want):
        nonlocal ok
        passed = got == want
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'} {label}: want {want} got {got}")

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
    check("title normalised", a["title"], "my garden")
    check("description normalised", a["description"], "notes on x")
    check("script text excluded", a["tokens"], 19)  # "hello" + eighteen body words
    check("small edit stays same", drift(a, b)[0], "same")
    check("whole-body swap is content-changed", drift(a, c)[0], "content-changed")
    check("host change wins", drift(a, d)[0], "host-changed")
    check("threshold documented", SIMILARITY_THRESHOLD, 0.65)

    # Shared template must not dilute a complete body replacement.
    tpl = ("<html><head><title>My Notes</title></head><body>"
           "<nav>home about archive contact subscribe newsletter rss tags search "
           "privacy terms cookies follow mastodon twitter github source licence "
           "built with a static site generator running since twenty nineteen</nav>")
    tpl2 = ("<footer>copyright two thousand twenty four all rights reserved "
            "powered by garden engine privacy policy contact me here</footer></body></html>")
    garden = page(tpl + "<p>tomato basil clay soil compost seedlings watering spring "
                        "harvest beds mulch bees flowers seeds</p>" + tpl2, "a.example")
    casino = page(tpl + "<p>casino bonus free spins jackpot roulette blackjack poker "
                        "deposit withdrawal vip promotion wagering</p>" + tpl2, "a.example")
    check("template + swapped body -> content-changed", drift(garden, casino)[0],
          "content-changed")

    # Image-only pages: no text, but different assets.
    img_a = page('<html><head><title>Portfolio</title></head><body>'
                 '<img src="/garden-tomato.jpg" alt="tomato seedlings"></body></html>',
                 "a.example")
    img_b = page('<html><head><title>Portfolio</title></head><body>'
                 '<img src="/casino-roulette.jpg" alt="roulette wheel"></body></html>',
                 "a.example")
    check("image-only pages are opaque", img_a["tokens"], 0)
    check("different image-only page -> content-changed", drift(img_a, img_b)[0],
          "content-changed")
    check("same image-only page -> same", drift(img_a, page(
        '<html><head><title>Portfolio</title></head><body>'
        '<img src="/garden-tomato.jpg" alt="tomato seedlings"></body></html>',
        "a.example"))[0], "same")

    # JS shells: identical static DOM, different inline script.
    shell_a = page('<div id="root"></div><script>renderApp("garden")</script>', "a.example")
    shell_b = page('<div id="root"></div><script>casinoRender()</script>', "a.example")
    check("different JS shell -> content-changed", drift(shell_a, shell_b)[0],
          "content-changed")

    # Client-side redirect to another host.
    red = page('<html><head><meta http-equiv="refresh" content="0;url=https://casino.example">'
               "</head><body><p>" + body + "</p></body></html>", "a.example")
    check("meta refresh host recorded", red["redirect_host"], "casino.example")
    check("meta refresh to another host -> host-changed", drift(a, red)[0], "host-changed")
    jsred = page("<script>window.location.href='https://evil.example/x'</script><p>hi there</p>",
                 "a.example")
    check("js redirect host recorded", jsred["redirect_host"], "evil.example")

    check("jaccard identical", jaccard(signature(tokens("alpha beta gamma")),
                                       signature(tokens("alpha beta gamma"))), 1.0)
    check("jaccard disjoint", jaccard(signature(tokens("alpha beta")),
                                      signature(tokens("gamma delta"))), 0.0)
    check("empty signatures do not compare equal",
          jaccard(signature([]), signature([])), 0.0)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(self_test())
