#!/usr/bin/env python3
"""The required backlink: proof that a listed page still points at its index entry.

The owner's rule (2026-11-18): an approved site has to carry an artifact that links
back to Aitherium, and a checker has to look for it. Otherwise "approved" is a
one-time stamp on a page that can be sold, parked or rewritten the next day.

A listing satisfies the rule with ONE of:

  a) https://<host>/.well-known/aithernet.json  ->  {"records": ["<id>", ...]}
     The owner proof. Only whoever controls the host can serve it. Keep the rank:
     this is what makes an entry *owner-proven*.

  b) a link back, in the page itself:
       <link rel="aithernet" href="https://index.aitherium.com/r/<id>">
       <meta name="aithernet" content="<id>">
       <a href="https://index.aitherium.com/r/<id>">listed in the AitherNet Index</a>
     This proves the page points at its entry, not who controls the domain. It is
     enough to stay listed, never enough to be owner-proven (see REPUTATION.md).

Every form is matched against the exact index host and the exact record id, so a link
to a look-alike domain (index-aitherium.example, index.aitherium.com.evil.example) or
to a different entry does not count. A form hidden by markup is not a link a person
(and therefore not a link an index) can see, so it does not count either: anchors
under ``display:none``, ``visibility:hidden``, ``opacity:0``, ``font-size:0``,
zero-size or off-screen positioning, the ``hidden`` attribute, ``aria-hidden=true``,
a hiding CSS class declared in a ``<style>`` block, or whose only text is zero-width
are rejected. So is any ``<link>``/``<meta>`` inside ``<template>``, ``<noscript>``,
``<svg>`` or a comment: inert markup is not a served backlink.

Stdlib only.

    python artifact.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

INDEX_HOST = "index.aitherium.com"
INDEX_BASE = f"https://{INDEX_HOST}"

# What a browser announces. Looking like the checker is exactly what lets a site serve
# us a different page than it serves everyone else, so the *page* fetch uses this.
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")
# How the checker identifies itself. Used for the second, comparison fetch so a
# UA-keyed response is visible instead of trusted (recheck.py).
CHECKER_UA = "aithernet-index-recheck/1 (+https://index.aitherium.com/llms.txt)"
# Backwards-compatible name: verify.py imports artifact.UA.
UA = BROWSER_UA

# The backlink rule does not apply to communities that prove themselves another way
# (the Discord bot is IN the server, see the parallel feat/discord-owner-proof branch),
# and hosts that cannot ever serve a file on the listed page are exempt by host, not by
# kind: a `world` record whose url is discord.gg must not be suspended for a backlink
# discord.com will never let it carry.
EXEMPT_KINDS = {"discord", "community"}
EXEMPT_HOSTS = {"discord.gg", "discord.com", "discordapp.com", "discord.media"}
# First-party services (Aitherium's own relay rooms/docs/blogs) are not asked to carry a
# backlink to themselves; they are covered by the integrity of our own deployment.
FIRST_PARTY_HOSTS = {"aitherium.com"}

FORMS = ("well-known", "link-rel", "meta", "visible-link")
_SKIP = {"script", "style", "noscript", "svg", "template"}
# One declaration that makes an element unreachable to a reader.
_HIDE_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0(?:\.0+)?(?:\s*[;!}]|$)"
    r"|font-size\s*:\s*0(?:px|em|rem|%|pt)?(?:\s*[;!}]|$)"
    r"|(?:width|height)\s*:\s*0(?:px|em|rem|%|pt)?(?:\s*[;!}]|$)"
    r"|text-indent\s*:\s*-\d{2,}"
    r"|(?:left|top)\s*:\s*-\d{3,}",
    re.IGNORECASE,
)
_CSS_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}", re.DOTALL)
_CSS_SELECTOR = re.compile(r"\.([A-Za-z0-9_-]+)|#([A-Za-z0-9_-]+)")
_ALNUM = re.compile(r"[0-9a-z]", re.IGNORECASE)


@dataclass
class Artifact:
    form: Optional[str]          # one of FORMS, or None
    reason: str                  # why it did or did not count, for the state file

    @property
    def ok(self) -> bool:
        return self.form is not None


@dataclass
class Fetch:
    status: int                  # HTTP status, 0 when the request never completed
    body: str
    final_url: str               # what we ended on after redirects
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200


def fetch(url: str, timeout: float = 15, limit: int = 262144,
          ua: Optional[str] = None) -> Fetch:
    """GET a page the way a browser would: follow redirects, browser UA, bounded read.

    ``ua`` overrides the User-Agent; the re-check uses that to compare what a browser
    sees with what the checker sees.
    """
    req = urllib.request.Request(url, headers={"User-Agent": ua or BROWSER_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only checked by caller)
            raw = resp.read(limit)
            return Fetch(resp.status, raw.decode("utf-8", "replace"),
                         resp.geturl() or url)
    except urllib.error.HTTPError as exc:
        return Fetch(exc.code, "", url, f"http {exc.code}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return Fetch(0, "", url, str(exc)[:200])


def host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def exempt_reason(kind: str, url: str) -> str:
    """Why this record is outside the backlink rule, or '' when it is inside it.

    Exemption is by *host* as well as kind: ``world_aitherium`` is kind ``world`` but
    lives on discord.gg, which can never serve a backlink on the listed page.
    """
    if (kind or "").strip().lower() in EXEMPT_KINDS:
        return "exempt: community kind, verified by its own bot"
    host = host_of(url or "")
    if not host:
        return ""
    if host in EXEMPT_HOSTS or any(host.endswith("." + h) for h in EXEMPT_HOSTS):
        return "exempt: Discord host, verified by its own bot"
    if host in FIRST_PARTY_HOSTS or any(host.endswith("." + h) for h in FIRST_PARTY_HOSTS):
        return "exempt: first-party Aitherium service"
    return ""


def is_exempt(kind: str, url: str) -> bool:
    return bool(exempt_reason(kind, url))


def claimed_ids(body: str) -> "list[str]":
    """Record ids named by a /.well-known/aithernet.json body. Anything else -> []."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    recs = data.get("records")
    if not isinstance(recs, list):
        return []
    return [r.strip() for r in recs if isinstance(r, str)]


def backlink_id(href: str, record_id: str) -> bool:
    """True when ``href`` is this entry's page on https://index.aitherium.com.

    Accepts /r/<id>, /r/<id>/, /e/<id>/ and the file-stem spelling of an id, and
    nothing else: exact https scheme, exact host, no credentials, no look-alike
    suffix, no different id.
    """
    try:
        parts = urllib.parse.urlsplit((href or "").strip())
    except ValueError:
        return False
    if parts.scheme != "https" or parts.netloc.lower() != INDEX_HOST:
        return False
    if parts.username or parts.password or parts.port:
        return False
    segs = [urllib.parse.unquote(s) for s in parts.path.split("/") if s]
    if len(segs) != 2 or segs[0] not in ("r", "e"):
        return False
    target = segs[1]
    return target in {record_id, record_id.replace(":", "_")}


def _attr_map(attrs: "list[tuple[str, Optional[str]]]") -> "dict[str, str]":
    return {k.lower(): (v if v is not None else "") for k, v in attrs}


def _inline_hidden(a: "dict[str, str]") -> bool:
    """Is this element itself hidden by markup or an inline style?"""
    if "hidden" in a:                       # bare ``hidden`` or hidden="anything"
        return True
    if a.get("aria-hidden", "").strip().lower() == "true":
        return True
    return bool(_HIDE_STYLE.search(a.get("style", "") or ""))


class _Page(HTMLParser):
    """The parts of a page the artifact rule looks at, plus visible anchor text.

    Tracks three independent states while walking the markup: inert regions
    (``<template>``/``<noscript>``/``<svg>``/``<script>``/``<style>``), hidden
    ancestors (markup or inline style), and the currently open anchor.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta_aithernet: "list[str]" = []
        self.link_rel: "list[str]" = []
        self.anchors: "list[dict]" = []
        self.hidden_classes: "set[str]" = set()
        self.hidden_ids: "set[str]" = set()
        self._anchor: Optional[dict] = None
        self._skip_tags: "list[str]" = []
        self._hidden_tags: "list[str]" = []
        self._in_style = False
        self._style_buf: "list[str]" = []

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _drop(tags: "list[str]", tag: str) -> None:
        for i in range(len(tags) - 1, -1, -1):
            if tags[i] == tag:
                del tags[i]
                return

    def _class_hidden(self, a: "dict[str, str]") -> bool:
        if not (self.hidden_classes or self.hidden_ids):
            return False
        if a.get("id", "").strip() in self.hidden_ids:
            return True
        return any(c in self.hidden_classes for c in a.get("class", "").split())

    def _read_style(self) -> None:
        """Remember classes/ids a ``<style>`` block declares as hidden."""
        for selectors, body in _CSS_RULE.findall("".join(self._style_buf)):
            if not _HIDE_STYLE.search(body):
                continue
            for sel in selectors.split(","):
                for m in _CSS_SELECTOR.finditer(sel):
                    if m.group(1):
                        self.hidden_classes.add(m.group(1))
                    elif m.group(2):
                        self.hidden_ids.add(m.group(2))

    # -- parser ----------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: "list[tuple[str, Optional[str]]]") -> None:
        tag = tag.lower()
        a = _attr_map(attrs)
        if tag == "style":
            self._in_style = True
            self._style_buf = []
            return
        if self._in_style:
            return                              # raw text of a <style> block
        if tag in _SKIP:
            self._skip_tags.append(tag)
            return
        if self._skip_tags:
            return                              # inert content, never a backlink
        hidden_here = (not self._hidden_tags
                       and (_inline_hidden(a) or self._class_hidden(a)))
        if hidden_here:
            self._hidden_tags.append(tag)
        if tag == "meta" and a.get("name", "").strip().lower() == "aithernet":
            self.meta_aithernet.append(a.get("content", "").strip())
        elif tag == "link" and "aithernet" in a.get("rel", "").lower().split():
            self.link_rel.append(a.get("href", "").strip())
        elif tag == "a" and self._anchor is None:
            self._anchor = {"href": a.get("href", "").strip(), "text": [],
                            "visible": not self._hidden_tags}

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "style":
            if self._in_style:
                self._read_style()
                self._in_style = False
                self._style_buf = []
            return
        if self._in_style:
            return
        if tag in _SKIP:
            self._drop(self._skip_tags, tag)
            return
        if self._hidden_tags:
            self._drop(self._hidden_tags, tag)
        if tag == "a" and self._anchor is not None:
            text = " ".join("".join(self._anchor["text"]).split())
            self.anchors.append({"href": self._anchor["href"], "text": text,
                                 "visible": self._anchor["visible"]})
            self._anchor = None

    def handle_data(self, data: str) -> None:
        if self._in_style:
            self._style_buf.append(data)
            return
        if (self._anchor is not None and not self._skip_tags
                and not self._hidden_tags):
            self._anchor["text"].append(data)


def page_parts(html: str) -> _Page:
    p = _Page()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # noqa: BLE001 - malformed markup is data, never a crash
        pass
    return p


def detect(record_id: str, html: str, well_known: "list[str]") -> Artifact:
    """Which backlink form, if any, this listing carries. Strongest form wins."""
    rid = (record_id or "").strip()
    if rid and rid in well_known:
        return Artifact("well-known",
                        f"/.well-known/aithernet.json names {rid!r}")
    parts = page_parts(html)
    for href in parts.link_rel:
        if backlink_id(href, rid):
            return Artifact("link-rel", f'<link rel="aithernet" href="{href}">')
    for content in parts.meta_aithernet:
        if content.strip() == rid:
            return Artifact("meta", '<meta name="aithernet"> names this record')
    for a in parts.anchors:
        if a["visible"] and _ALNUM.search(a["text"]) and backlink_id(a["href"], rid):
            return Artifact("visible-link", f'visible link to {a["href"]}')
    # Say what was seen, so the maintainer reading the issue knows what to fix.
    seen = []
    for href in parts.link_rel:
        seen.append(f'link rel=aithernet href={href!r} (not this entry)')
    for content in parts.meta_aithernet:
        if content.strip() != rid:
            seen.append(f"meta aithernet content={content!r} (not this record)")
    for a in parts.anchors:
        if backlink_id(a["href"], "__none__"):
            continue
        if "index.aitherium.com" in a["href"] or "aithernet" in (a["href"] + a["text"]).lower():
            if not a["visible"]:
                why = "not visible"
            elif not _ALNUM.search(a["text"]):
                why = "no visible text"
            else:
                why = "not this entry"
            seen.append(f"anchor {a['href']!r} ({why})")
    detail = ("; ".join(seen[:3])) if seen else "no backlink found"
    return Artifact(None, detail)


def probe(record_id: str, url: str, timeout: float = 15) -> "tuple[Fetch, Artifact]":
    """Fetch the listed page, then its host's well-known file, then decide."""
    page = fetch(url, timeout=timeout)
    claimed: "list[str]" = []
    host = host_of(page.final_url or url)
    if page.ok and host:
        wk = fetch(f"https://{host}/.well-known/aithernet.json", timeout=timeout, limit=65536)
        if wk.ok:
            claimed = claimed_ids(wk.body)
    return page, detect(record_id, page.body if page.ok else "", claimed)


def _self_test() -> int:
    rid = "example.com_garden"
    good_anchor = f'<a href="https://{INDEX_HOST}/r/{rid}">Listed on AitherNet</a>'
    good_link = f'<link rel="aithernet" href="https://{INDEX_HOST}/r/{rid}/">'
    good_meta = f'<meta name="aithernet" content="{rid}">'
    lk = f'<a href="https://{INDEX_HOST}/r/{rid}">x</a>'
    cases = [
        # (label, html, well_known_ids, expected form)
        ("well-known", "<p>anything</p>", [rid], "well-known"),
        ("link rel", f"<html><head>{good_link}</head><body>x</body></html>", [], "link-rel"),
        ("meta", f"<html><head>{good_meta}</head><body>x</body></html>", [], "meta"),
        ("visible link", f"<html><body><p>{good_anchor}</p></body></html>", [], "visible-link"),
        ("entry page path", f'<a href="https://{INDEX_HOST}/e/{rid}/">see</a>', [], "visible-link"),
        # lookalikes that must NOT count
        ("another domain", f'<a href="https://evil.example/r/{rid}">x</a>', [], None),
        ("look-alike host", f'<a href="https://{INDEX_HOST}.evil.example/r/{rid}">x</a>', [], None),
        ("prefix host", f'<a href="https://not{INDEX_HOST}/r/{rid}">x</a>', [], None),
        ("http not https", f'<a href="http://{INDEX_HOST}/r/{rid}">x</a>', [], None),
        ("different id", f'<a href="https://{INDEX_HOST}/r/other.example">x</a>', [], None),
        ("other id well-known", "<p>x</p>", ["other.example"], None),
        ("meta other id", f'<meta name="aithernet" content="other.example">', [], None),
        ("hidden anchor (no text)", f'<a href="https://{INDEX_HOST}/r/{rid}"></a>', [], None),
        ("zero-width text", f'<a href="https://{INDEX_HOST}/r/{rid}">&#x200b;</a>', [], None),
        ("userinfo trick", f'<a href="https://{INDEX_HOST}@evil.example/r/{rid}">x</a>', [], None),
        ("wrong rel", f'<html><head><link rel="stylesheet" href="https://{INDEX_HOST}/r/{rid}">'
                      f"</head><body>x</body></html>", [], None),
        ("id as substring", f'<a href="https://{INDEX_HOST}/r/{rid}-extra">x</a>', [], None),
        # hidden markup must NOT count
        ("display none", f'<div style="display:none">{lk}</div>', [], None),
        ("hidden attr", f'<div hidden>{lk}</div>', [], None),
        ("aria hidden", f'<div aria-hidden="true">{lk}</div>', [], None),
        ("offscreen", f'<div style="position:absolute;left:-9999px">{lk}</div>', [], None),
        ("font size 0", f'<div style="font-size:0">{lk}</div>', [], None),
        ("opacity 0", f'<div style="opacity:0">{lk}</div>', [], None),
        ("visibility hidden", f'<div style="visibility:hidden">{lk}</div>', [], None),
        ("css class hidden", f"<style>.ghost{{display:none}}</style>"
                             f'<div class="ghost">{lk}</div>', [], None),
        ("link in template", f"<template>{good_link}</template>", [], None),
        ("meta in template", f"<html><head><template>{good_meta}</template>"
                             "</head><body>x</body></html>", [], None),
        ("link in noscript", f"<noscript>{good_link}</noscript>", [], None),
        ("link in svg", f"<svg>{good_link}</svg>", [], None),
        ("link in comment", f"<!-- {good_link} -->", [], None),
    ]
    ok = True
    for label, html, wk, want in cases:
        got = detect(rid, html, wk).form
        passed = got == want
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'} {label}: want {want} got {got}")
    body = json.dumps({"records": [rid, "x"]})
    parsed = claimed_ids(body) == [rid, "x"] and claimed_ids("<html>") == []
    ok &= parsed
    print(f"{'PASS' if parsed else 'FAIL'} well-known parsing")
    ex = (is_exempt("world", "https://discord.gg/xMv9hHKkkh")
          and is_exempt("room", "https://relay.aitherium.com/room/x")
          and is_exempt("discord", "https://example.com")
          and not is_exempt("garden", "https://garden.example"))
    ok &= ex
    print(f"{'PASS' if ex else 'FAIL'} exemption by host and kind")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
