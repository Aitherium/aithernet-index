#!/usr/bin/env python3
"""The required backlink artifact: proof that a listed page points at its entry.

Owner rule, 2026-11-18: a listing is checked BEFORE its pull request can merge,
and one of the checks is a backlink artifact. A page can be approved once and be
sold, parked or rewritten the next day; the artifact is the part that has to
still be true when the check runs.

A listing passes with ONE of:

  a) https://<host>/.well-known/aithernet.json  ->  {"records": ["<id>", ...]}
     Owner proof: only whoever controls the host can serve it.
  b) <link rel="aithernet" href="https://index.aitherium.com/r/<id>">
  c) <meta name="aithernet" content="<id>">
  d) a VISIBLE <a href="https://index.aitherium.com/r/<id>">...</a> on the page

Every form is matched against the exact index host and the exact record id, so a
look-alike domain (index.aitherium.com.evil.example, notindex.aitherium.com) or
another entry's id does not count.

NOTE FOR REVIEWERS: ``detect()`` is deliberately shaped like the
``artifact.py`` that the parallel ``feat/continuous-recheck`` branch adds at the
repository root (same ``Artifact(form, reason)`` / ``detect(record_id, html,
well_known)`` contract). It lives in ``tools/`` so this gate needs no shared
file; when that branch lands, this module can be deleted and its import
re-pointed at the root ``artifact`` module without touching a rule.

    python tools/artifact_check.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_net import Fetch, fetch  # noqa: E402

INDEX_HOST = "index.aitherium.com"
INDEX_BASE = f"https://{INDEX_HOST}"
FORMS = ("well-known", "link-rel", "meta", "visible-link")
# Kinds whose proof is a bot check elsewhere (the Discord invite), not a page link.
EXEMPT_KINDS = frozenset({"discord", "community"})
_SKIP = {"script", "style", "noscript", "svg", "template"}


@dataclass(frozen=True)
class Artifact:
    form: Optional[str]      # one of FORMS, or None
    reason: str              # why it did or did not count

    @property
    def ok(self) -> bool:
        return self.form is not None


def host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def claimed_ids(body: str) -> "List[str]":
    """Record ids named by a /.well-known/aithernet.json body; anything else []."""
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
    """True when ``href`` is exactly this entry's page on index.aitherium.com.

    Accepts /r/<id>, /r/<id>/, /e/<id>/ and the file-stem spelling of an id.
    Rejects a different scheme, any other host (including look-alikes), embedded
    credentials/ports, a different path shape, and a different id.
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
    """Only the parts of a page the artifact rule looks at."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta_aithernet: "List[str]" = []
        self.link_rel: "List[str]" = []
        self.anchors: "List[dict]" = []
        self._anchor: "Optional[dict]" = None
        self._skip = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in _SKIP:
            self._skip += 1
        elif tag == "meta" and a.get("name", "").strip().lower() == "aithernet":
            self.meta_aithernet.append(a.get("content", "").strip())
        elif tag == "link" and "aithernet" in a.get("rel", "").lower().split():
            self.link_rel.append(a.get("href", "").strip())
        elif tag == "a" and self._anchor is None:
            self._anchor = {"href": a.get("href", "").strip(), "text": []}

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP and self._skip:
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


def detect(record_id: str, html: str, well_known: "List[str]") -> Artifact:
    """Which backlink form, if any, this listing carries. Strongest form wins."""
    rid = (record_id or "").strip()
    if rid and rid in well_known:
        return Artifact("well-known", f"/.well-known/aithernet.json names {rid!r}")
    parts = page_parts(html)
    for href in parts.link_rel:
        if backlink_id(href, rid):
            return Artifact("link-rel", f'<link rel="aithernet" href="{href}">')
    for content in parts.meta_aithernet:
        if content.strip() == rid:
            return Artifact("meta", '<meta name="aithernet"> names this record')
    for anchor in parts.anchors:
        if anchor["text"] and backlink_id(anchor["href"], rid):
            return Artifact("visible-link", f'visible link to {anchor["href"]}')
    seen: "List[str]" = []
    for href in parts.link_rel:
        seen.append(f"link rel=aithernet href={href!r} does not point at this entry")
    for content in parts.meta_aithernet:
        if content.strip() != rid:
            seen.append(f"meta aithernet content={content!r} is not this record")
    for anchor in parts.anchors:
        if "index.aitherium.com" in anchor["href"]:
            if not anchor["text"]:
                seen.append(f"anchor {anchor['href']!r} has no visible text")
            else:
                seen.append(f"anchor {anchor['href']!r} is not this entry")
    detail = "; ".join(seen[:3]) if seen else "no backlink found on the page"
    return Artifact(None, detail)


def probe(record_id: str, url: str, get=fetch, timeout: float = 15):
    """Fetch the listed page, then its host's well-known file, then decide."""
    page = get(url, timeout=timeout)
    claimed: "List[str]" = []
    hosts: "List[str]" = []
    for host in (host_of(url), host_of(page.final_url)):
        if host and host not in hosts:
            hosts.append(host)
    for host in hosts:
        if not page.ok and host != host_of(url):
            continue
        wk = get(f"https://{host}/.well-known/aithernet.json", timeout=timeout, limit=65536)
        if wk.ok:
            claimed = claimed_ids(wk.body)
            if claimed:
                break
    return page, detect(record_id, page.body if page.ok else "", claimed)


def _self_test() -> int:
    rid = "example.com_garden"
    good_anchor = f'<a href="https://{INDEX_HOST}/r/{rid}">Listed on AitherNet</a>'
    good_link = f'<link rel="aithernet" href="https://{INDEX_HOST}/r/{rid}/">'
    good_meta = f'<meta name="aithernet" content="{rid}">'
    cases = [
        ("well-known", "<p>anything</p>", [rid], "well-known"),
        ("link rel", f"<html><head>{good_link}</head><body>x</body></html>", [], "link-rel"),
        ("meta", f"<html><head>{good_meta}</head><body>x</body></html>", [], "meta"),
        ("visible link", f"<html><body><p>{good_anchor}</p></body></html>", [], "visible-link"),
        ("entry page path", f'<a href="https://{INDEX_HOST}/e/{rid}/">see</a>', [],
         "visible-link"),
        ("another domain", f'<a href="https://evil.example/r/{rid}">x</a>', [], None),
        ("look-alike host", f'<a href="https://{INDEX_HOST}.evil.example/r/{rid}">x</a>',
         [], None),
        ("prefix host", f'<a href="https://not{INDEX_HOST}/r/{rid}">x</a>', [], None),
        ("http not https", f'<a href="http://{INDEX_HOST}/r/{rid}">x</a>', [], None),
        ("different id", f'<a href="https://{INDEX_HOST}/r/other.example">x</a>', [], None),
        ("other id well-known", "<p>x</p>", ["other.example"], None),
        ("meta other id", '<meta name="aithernet" content="other.example">', [], None),
        ("hidden anchor (no text)", f'<a href="https://{INDEX_HOST}/r/{rid}"></a>',
         [], None),
        ("userinfo trick", f'<a href="https://{INDEX_HOST}@evil.example/r/{rid}">x</a>',
         [], None),
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
    parsed = claimed_ids(json.dumps({"records": [rid, "x"]})) == [rid, "x"]
    parsed &= claimed_ids("<html>") == [] and claimed_ids('{"records": "x"}') == []
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
