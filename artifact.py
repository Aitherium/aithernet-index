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
to a different entry does not count. Stdlib only.

    python artifact.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

INDEX_HOST = "index.aitherium.com"
INDEX_BASE = f"https://{INDEX_HOST}"
UA = "aithernet-index-recheck/1 (+https://index.aitherium.com/llms.txt)"
# Kinds the backlink rule does not cover: they have their own proof (the bot re-checks
# the Discord invite), so the re-check skips them rather than failing them.
EXEMPT_KINDS = {"discord", "community"}

FORMS = ("well-known", "link-rel", "meta", "visible-link")
_SKIP = {"script", "style", "noscript", "svg", "template"}


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


def fetch(url: str, timeout: float = 15, limit: int = 262144) -> Fetch:
    """GET a page the way a browser would: follow redirects, polite UA, bounded read."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
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


class _Page(HTMLParser):
    """The parts of a page the artifact rule looks at, plus the visible anchor text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta_aithernet: "list[str]" = []
        self.link_rel: "list[str]" = []
        self.anchors: "list[dict]" = []
        self._anchor: Optional[dict] = None
        self._skip = 0
        self._in_head = 0

    def handle_starttag(self, tag: str, attrs: "list[tuple[str, Optional[str]]]") -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "head":
            self._in_head += 1
        elif tag in _SKIP:
            self._skip += 1
        elif tag == "meta" and a.get("name", "").strip().lower() == "aithernet":
            self.meta_aithernet.append(a.get("content", "").strip())
        elif tag == "link" and "aithernet" in a.get("rel", "").lower().split():
            self.link_rel.append(a.get("href", "").strip())
        elif tag == "a" and self._anchor is None:
            self._anchor = {"href": a.get("href", "").strip(), "text": []}

    def handle_endtag(self, tag: str) -> None:
        if tag == "head" and self._in_head:
            self._in_head -= 1
        elif tag in _SKIP and self._skip:
            self._skip -= 1
        elif tag == "a" and self._anchor is not None:
            text = " ".join("".join(self._anchor["text"]).split())
            self.anchors.append({"href": self._anchor["href"], "text": text})
            self._anchor = None

    def handle_data(self, data: str) -> None:
        if self._anchor is not None and not self._skip:
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
        if a["text"] and backlink_id(a["href"], rid):
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
            seen.append(f"anchor {a['href']!r} (not this entry or not visible text)")
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
        ("userinfo trick", f'<a href="https://{INDEX_HOST}@evil.example/r/{rid}">x</a>', [], None),
        ("wrong rel", f'<html><head><link rel="stylesheet" href="https://{INDEX_HOST}/r/{rid}">'
                      f"</head><body>x</body></html>", [], None),
        ("id as substring", f'<a href="https://{INDEX_HOST}/r/{rid}-extra">x</a>', [], None),
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
