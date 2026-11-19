#!/usr/bin/env python3
"""Render the AitherNet Index as a static public site (target: index.aitherium.com).

Static on purpose: Pages/CDN serve it, nothing to keep alive, and the git SHA
of the records IS the version every answer came from.

    out/index.html          the directory (keyword list, kinds, tags, edges)
    out/index.json          every record + the source SHA + its re-check status
    out/n/<name>.json       the resolver: GET /n/docs.aither.json -> route
    out/e/<id>/index.html   one page per entry, with schema.org JSON-LD
    out/r/<id>/index.html   the stable shortlink a listing points back to
    out/claim/index.html    how a business lists or claims itself
    out/llms.txt, robots.txt, sitemap.xml   for agents and crawlers
    out/CNAME               index.aitherium.com

``state/health.json`` (written by recheck.py) decides visibility: an entry that the
daily re-check has suspended or delisted is hidden from the listing and the sitemap,
still has its page (with the reason), and says ``status`` in index.json. Nothing is
ever deleted here.

Refuses to build (exit 1) when check_netindex finds anything: a public index
is never published past a failing gate. Exit 2 when there are no records.

    python build_site.py --out <dir>
"""

from __future__ import annotations

import argparse
import html
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import netindex  # noqa: E402
import recheck  # noqa: E402

DOMAIN = "index.aitherium.com"
BASE = f"https://{DOMAIN}"
REPO = "https://github.com/Aitherium/aithernet-index"
HIDDEN = ("warn", "suspended", "delisted")


def _sha(root: Path) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(["git", "-C", str(root), "log", "-1", "--format=%H", "--", "."],
                           capture_output=True, text=True, encoding="utf-8",
                           timeout=30, creationflags=flags)
        return r.stdout.strip() or "uncommitted"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _record_dict(r: netindex.Record, health: "dict | None" = None) -> dict:
    e = (health or {}).get(r.id) or {}
    return {"id": r.id, "kind": r.kind, "title": r.title, "url": r.url, "tags": r.tags,
            "names": r.names, "route": r.route, "edges": r.edges,
            "validated": r.provenance.get("validated", {}),
            "trust": netindex.TIERS[netindex.trust(r)],
            # Where it lives, for explorers (BeadSpace, agents): the URL's host, and the
            # OSINT evidence (domain age, CT, sanctions, threat) that trust was judged on.
            "host": (urlsplit(r.url).hostname or "") if r.url else "",
            "evidence": r.provenance.get("evidence", {}),
            # The daily re-check (recheck.py). `status: delisted` and the artifact kind
            # are part of the public data, not a private note.
            "status": e.get("status") or "active",
            "last_checked": e.get("last_checked"),
            "artifact": e.get("artifact"),
            "status_reasons": [f.get("code") for f in e.get("failures") or []],
            "listing": r.listing,
            "download": r.download,
            "page": f"{BASE}/e/{_slug(r)}/"}


def _slug(r: netindex.Record) -> str:
    """Entry page path segment: the record's file stem (ids are host-like, url-safe)."""
    return r.id.replace(":", "_")


_SCHEMA_TYPE = {"business": "LocalBusiness", "org": "Organization", "dataset": "Dataset",
                "service": "WebApplication"}


def jsonld(r: netindex.Record) -> dict:
    """schema.org description of an entry: what search engines and AI agents read."""
    d: dict = {"@context": "https://schema.org", "@type": _SCHEMA_TYPE.get(r.kind, "WebSite"),
               "@id": f"{BASE}/e/{_slug(r)}/#entity", "name": r.title, "identifier": r.id}
    if r.url:
        d["url"] = r.url
    listing = r.listing or {}
    simple = {"description": "description", "phone": "telephone", "email": "email",
              "address": "address", "area_served": "areaServed"}
    for key, prop in simple.items():
        if isinstance(listing.get(key), str):
            d[prop] = listing[key]
    if listing.get("hours"):
        d["openingHours"] = list(listing["hours"])
    if listing.get("same_as"):
        d["sameAs"] = list(listing["same_as"])
    if isinstance(listing.get("geo"), dict):
        d["geo"] = {"@type": "GeoCoordinates", "latitude": listing["geo"].get("lat"),
                    "longitude": listing["geo"].get("lng")}
    if isinstance(listing.get("category"), str):
        d["keywords"] = listing["category"]
    elif r.tags:
        d["keywords"] = ", ".join(r.tags)
    return d


def _ld_script(obj: dict) -> str:
    # "<" is escaped so no value can close the script element early.
    body = json.dumps(obj, ensure_ascii=False).replace("<", "\u003c")
    return '<script type="application/ld+json">' + body + "</script>"


_STYLE = """<style>
:root{--bg:#fbfaf7;--fg:#1d1b18;--mute:#6b665d;--line:#e4e0d8;--acc:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#141311;--fg:#ece8e1;--mute:#9a948a;
--line:#2c2a26;--acc:#8ea2ff}}
body{background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,sans-serif;
margin:0 auto;max-width:760px;padding:24px 16px}
h1{margin:0 0 6px} h2{margin:28px 0 8px;font-size:18px}
.mute{color:var(--mute)} a{color:var(--acc)} code,pre{font-size:13px}
pre{background:rgba(127,127,127,.12);padding:10px;overflow-x:auto}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px} dt{color:var(--mute)}
dd{margin:0;overflow-wrap:anywhere} nav a{margin-right:14px;display:inline-block}
</style>"""

_NAV = ('<nav><a href="/">Index</a><a href="/claim/">List or claim your business</a>'
        '<a href="/llms.txt">llms.txt</a><a href="/index.json">index.json</a>'
        f'<a href="{REPO}">Source</a></nav>')


def _health_bits(entry: dict, esc=html.escape) -> str:
    """Status, last check and backlink kind, as one muted line. Empty if never checked."""
    if not entry:
        return ""
    bits = [f"status: <b>{esc(str(entry.get('status') or 'active'))}</b>"]
    if entry.get("last_checked"):
        bits.append(f"last re-checked {esc(str(entry['last_checked']))}")
    bits.append(f"backlink: {esc(str(entry.get('artifact') or 'none'))}")
    return " &middot; ".join(bits)


def _status_notice(r: netindex.Record, entry: dict) -> str:
    """The reason box a suspended or delisted entry keeps on its own page."""
    status = (entry or {}).get("status")
    if status not in HIDDEN:
        return ""
    e = html.escape
    reasons = "; ".join(f"{f.get('code')}: {f.get('detail')}"
                        for f in entry.get("failures") or []) or "no reason recorded"
    return (f'<h2>Why this entry is hidden</h2><p>This listing is '
            f"<b>{e(status)}</b>: the daily re-check found a problem — the page was "
            f"unreachable, lost the backlink that proves it belongs to this index, or "
            f"no longer looks like the page that was approved — so it is not shown in "
            f"the main listing. Nothing has been deleted. Reason: {e(reasons)}. It "
            f"returns on its own once the check passes again. If this is yours, see "
            f'<a href="/claim/">how to fix it</a>.</p>')


def _entry_page(r: netindex.Record, sha: str, health: "dict | None" = None) -> str:
    e = html.escape
    v = r.provenance.get("validated", {})
    tier = netindex.TIERS[netindex.trust(r)]
    entry = (health or {}).get(r.id) or {}
    listing = r.listing or {}
    facts = []
    labels = [("description", "About"), ("category", "Category"), ("address", "Address"),
              ("area_served", "Area served"), ("phone", "Phone"), ("email", "Email")]
    for key, label in labels:
        if isinstance(listing.get(key), str):
            facts.append(f"<dt>{label}</dt><dd>{e(listing[key])}</dd>")
    if listing.get("hours"):
        facts.append("<dt>Hours</dt><dd>" + "<br>".join(e(h) for h in listing["hours"]) + "</dd>")
    if listing.get("same_as"):
        links = "<br>".join(f'<a href="{e(u, quote=True)}" rel="nofollow">{e(u)}</a>'
                            for u in listing["same_as"])
        facts.append(f"<dt>Also at</dt><dd>{links}</dd>")
    site = f'<a href="{e(r.url, quote=True)}">{e(r.url)}</a>' if r.url else "none"
    dl = r.download or {}
    if dl.get("short"):
        facts.append(f'<dt>Short link</dt><dd><a href="{e(dl["short"], quote=True)}">'
                     f'{e(dl["short"])}</a></dd>')
    if dl.get("target"):
        facts.append(f'<dt>Goes to</dt><dd><a href="{e(dl["target"], quote=True)}" '
                     f'rel="nofollow">{e(dl["target"])}</a></dd>')
    if dl.get("sha256"):
        facts.append(f"<dt>SHA-256</dt><dd><code>{e(dl['sha256'])}</code>"
                     + (f" ({e(dl['asset'])})" if dl.get("asset") else "") + "</dd>")
    src = f"{REPO}/blob/main/records/{_slug(r)}.json"
    desc = str(listing.get("description") or r.title)
    robots = ("<meta name='robots' content='noindex'>"
              if entry.get("status") in HIDDEN else "")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(r.title)} | AitherNet Index</title>
<link rel="canonical" href="{BASE}/e/{e(_slug(r), quote=True)}/">{robots}
<meta name="description" content="{e(desc, quote=True)}">
{_ld_script(jsonld(r))}
{_STYLE}</head><body>{_NAV}
<h1>{e(r.title)}</h1>
<p class="mute">{e(r.kind)} &middot; trust: <b>{e(tier)}</b> &middot; checked {e(str(v.get('at', '')))}
by {e(str(v.get('by', '')))} ({e(str(v.get('method', '')))})</p>
<p class="mute">{_health_bits(entry, e)}</p>
{_status_notice(r, entry)}
<dl><dt>Website</dt><dd>{site}</dd>{''.join(facts)}</dl>
<h2>Where this comes from</h2>
<p>This listing is one file in a public git repository:
<a href="{e(src, quote=True)}">records/{e(_slug(r))}.json</a>. Every change to it is a
reviewed commit with an author. Built from <code>{e(sha[:12])}</code>.</p>
<p>Is this yours? <a href="/claim/">Claim it or correct it</a>. It costs nothing and
asks you to give up nothing.</p>
</body></html>
"""


_CLAIM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>List or claim your business | AitherNet Index</title>
<link rel="canonical" href="{base}/claim/">
<meta name="description" content="Put your business where people and AI agents look, without signing away any legal rights.">
{style}</head><body>{nav}
<h1>List or claim your business</h1>
<p>Being findable should not cost you your legal rights. Listing here asks for none of them.
Your listing is a small JSON file in a public git repository, and your listing page
publishes it as schema.org data, the format search engines and AI agents read.</p>

<h2>1. Submit it</h2>
<p>Open the <a href="{repo}/issues/new?template=submit-a-site.yml">Submit a site</a> form
and pick the kind <code>business</code>. A bot turns it into a pull request that adds
<code>records/&lt;your-host&gt;.json</code>. You can also open the pull request yourself.</p>

<h2>2. Prove it is yours</h2>
<p>Serve this file from your own site, at
<code>https://&lt;your-host&gt;/.well-known/aithernet.json</code>:</p>
<pre>{{"records": ["&lt;your-id&gt;"]}}</pre>
<p>Only whoever controls the site can put that file there. The verifier then marks the
listing <b>owner-proven</b>. That is the whole claim process. There is nothing to sign.</p>

<h2>3. Add the facts you want found</h2>
<pre>"listing": {{
  "description": "Neighbourhood bakery, sourdough and pastries",
  "category": "bakery",
  "address": "1 Main St, Springfield",
  "area_served": "Springfield",
  "phone": "+1 555 010 0000",
  "hours": ["Mo-Fr 07:00-15:00", "Sa,Su 08:00-12:00"],
  "same_as": ["https://social.example/yourbakery"]
}}</pre>
<p>Hours use the schema.org form shown. The index validator (rule NI010) rejects any
field it does not know, so a listing can only ever hold the facts you chose to publish.</p>

<h2>What you give, and what you keep</h2>
<ul>
<li>No account here and no terms to click. You need a GitHub account to open the issue
or pull request, and GitHub's own terms cover that account.</li>
<li>The facts in your listing file are published under
<a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>, like every record
here. That license covers that file and nothing else.</li>
<li>Listing asks you to release no legal claim: not about your website, not about
anything else you have published, not about past or future work, and not for any company
you own.</li>
<li>To leave, delete your file in a pull request, or open an issue and a maintainer
deletes it. Copies other people already made under CC BY stay valid; that is how open
data works.</li>
</ul>
<p class="mute">This page explains how the index works. It is not legal advice.</p>
</body></html>
"""


def _llms(records: list, sha: str, health: "dict | None" = None) -> str:
    biz = [r for r in records if r.kind in ("business", "org")
           and ((health or {}).get(r.id) or {}).get("status") not in HIDDEN]
    lines = [
        "# AitherNet Index",
        "",
        "> A hand-curated map of the internet, kept in git. Every entry records who checked it "
        "and how. Data is CC BY 4.0; code is MIT.",
        "",
        f"Built from commit {sha[:12]} of {REPO}.",
        "",
        "## Read it",
        f"- [Every record as JSON]({BASE}/index.json): each record, its trust tier, its "
        "re-check status and the source commit.",
        f"- Resolve a keyword: GET {BASE}/n/<name>.aither.json (404 means not in the index; "
        "the resolver never guesses).",
        f"- Entry pages: {BASE}/e/<id>/ carry schema.org JSON-LD (LocalBusiness, Organization, WebSite).",
        f"- [Sitemap]({BASE}/sitemap.xml)",
        "- Python and MCP: `pip install awindex`, then `awindex resolve <name>` or "
        "`awindex mcp` (an MCP server over stdio).",
        "",
        "## Trust tiers",
        "- submitted: someone proposed it.",
        "- reachable: a bot fetched the URL and got HTTP 200.",
        "- owner-proven: the site serves /.well-known/aithernet.json naming the record id.",
        "- vouched: reachable or better, and two people other than the submitter vouched.",
        "",
        "## Kept honest",
        "Every entry is re-checked daily. It must carry a backlink artifact — the "
        "well-known file above, or a link back to "
        f"{BASE}/r/<id> from the page — and its content must still match what was "
        "approved. Entries that fail move to warn, then suspended, then delisted; "
        "delisted entries are hidden from this index (their page stays, with the reason). "
        "`index.json` carries `status` and `last_checked` for each entry.",
        "",
        "## List or claim a business",
        f"- [How it works]({BASE}/claim/): submit, prove control of your own domain, add your facts. "
        "No terms to accept and no release of legal claims.",
        f"- [Contribution guide]({REPO}/blob/main/CONTRIBUTING.md)",
    ]
    if biz:
        lines += ["", "## Businesses and organisations"]
        for r in sorted(biz, key=lambda x: x.title.lower()):
            lines.append(f"- [{r.title}]({BASE}/e/{_slug(r)}/): {netindex.TIERS[netindex.trust(r)]}")
    return "\n".join(lines) + "\n"


_ROBOTS = """# The AitherNet Index is open data (CC BY 4.0). People, search engines and AI agents
# are all welcome to read it.
User-agent: *
Allow: /
Disallow: /go/

Sitemap: {base}/sitemap.xml
"""


def _sitemap(records: list) -> str:
    urls = [f"{BASE}/", f"{BASE}/claim/"] + [f"{BASE}/e/{_slug(r)}/" for r in records]
    body = "".join(f"<url><loc>{html.escape(u)}</loc></url>" for u in sorted(set(urls)))
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + body + "</urlset>\n")


def _write_agent_files(out: Path, records: list, sha: str, health: "dict | None" = None) -> None:
    for r in records:
        page = out / "e" / _slug(r)
        page.mkdir(parents=True, exist_ok=True)
        (page / "index.html").write_text(_entry_page(r, sha, health), encoding="utf-8")
    _write_shortlinks(out, records)
    (out / "claim").mkdir(parents=True, exist_ok=True)
    (out / "claim" / "index.html").write_text(
        _CLAIM.format(base=BASE, repo=REPO, style=_STYLE, nav=_NAV), encoding="utf-8")
    (out / "llms.txt").write_text(_llms(records, sha, health), encoding="utf-8")
    (out / "robots.txt").write_text(_ROBOTS.format(base=BASE), encoding="utf-8")
    (out / "sitemap.xml").write_text(_sitemap(_visible(records, health)), encoding="utf-8")


def _visible(records: list, health: "dict | None" = None) -> list:
    """Entries the main listing shows: everything the re-check has not suspended."""
    return [r for r in records
            if ((health or {}).get(r.id) or {}).get("status") not in HIDDEN]


def _write_shortlinks(out: Path, records: list) -> None:
    """``/r/<id>/`` — the stable backlink URL a listed page is asked to carry.

    A listing can point at ``/r/<id>`` and never change again, whatever an entry page
    is called. It redirects to the entry page, and is never hidden by the re-check
    (the artifact must keep working even while an entry is being fixed).
    """
    for r in records:
        dest = f"{BASE}/e/{_slug(r)}/"
        for seg in {r.id, _slug(r)}:
            page = out / "r" / seg
            page.mkdir(parents=True, exist_ok=True)
            (page / "index.html").write_text(
                _GO_PAGE.format(title=html.escape(r.title), href=dest), encoding="utf-8")


def _page(records: list, sha: str, health: "dict | None" = None) -> str:
    e = html.escape
    hidden = {r.id for r in records
              if ((health or {}).get(r.id) or {}).get("status") in HIDDEN}
    rows = []
    for r in sorted(_visible(records, health), key=lambda x: (x.kind, x.title.lower())):
        h = (health or {}).get(r.id) or {}
        link = f'<a href="/e/{e(_slug(r), quote=True)}/">{e(r.title)}</a>'
        names = " ".join(f"<code>{e(n)}</code>" for n in r.names)
        tags = " ".join(f'<span class="tag">{e(t)}</span>' for t in r.tags)
        edges = "; ".join(f"{e(x.get('rel', ''))} &rarr; {e(x.get('to', ''))}" for x in r.edges)
        v = r.provenance.get("validated", {})
        tier = netindex.TIERS[netindex.trust(r)]
        status = e(str(h.get("status") or "active"))
        checked = e(str(h.get("last_checked") or v.get("at", "")))
        rows.append(f"<tr id=\"{e(r.id, quote=True)}\"><td>{e(r.kind)}</td><td>{link}<div class='t'>{tags}</div></td>"
                    f"<td>{names}</td><td class='m'>{edges}</td>"
                    f"<td class='m'>{e(str(v.get('at', '')))} &middot; "
                    f"{e(str(v.get('method', '')))} &middot; <b>{e(tier)}</b></td>"
                    f"<td class='m'>{status} &middot; {checked}</td></tr>")
    note = ""
    if hidden:
        one = len(hidden) == 1
        note = (f'<p class="m" style="font-size:13px">{len(hidden)} '
                + ("entry is" if one else "entries are")
                + " hidden: the daily re-check found the page changed or went away. "
                + ("Its page still explains" if one else "Their pages still explain")
                + " why.</p>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AitherNet Index</title>
<link rel="search" type="application/opensearchdescription+xml" title="AitherNet"
 href="/opensearch.xml">
<style>
:root{{--bg:#fbfaf7;--fg:#1d1b18;--mute:#6b665d;--line:#e4e0d8;--acc:#3b5bdb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141311;--fg:#ece8e1;--mute:#9a948a;
--line:#2c2a26;--acc:#8ea2ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;
margin:0 auto;max-width:1100px;padding:24px 16px}}
h1{{margin:0 0 4px}} p{{color:var(--mute);margin:0 0 20px}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
a{{color:var(--acc)}} code{{font-size:13px}} .m{{color:var(--mute);font-size:13px}}
.tag{{border:1px solid var(--line);border-radius:9px;font-size:12px;margin-right:4px;padding:0 6px}}
</style></head><body>
<nav style="margin-bottom:12px"><a href="/claim/">List or claim your business</a> &middot;
<a href="/llms.txt">llms.txt</a> &middot; <a href="/index.json">index.json</a> &middot;
<a href="https://github.com/Aitherium/aithernet-index">source</a></nav>
<h1>AitherNet Index</h1>
<p>A hand-curated map of the internet, kept in git. Every entry records who checked it
and how. Go to a keyword at <code>/go/&lt;keyword&gt;</code>; look one up at
<code>/n/&lt;name&gt;.json</code>. Built from {e(sha[:12])}.</p>
{note}
<div class="wrap"><table><thead><tr><th>kind</th><th>entry</th><th>keywords</th>
<th>links</th><th>checked</th><th>re-check</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table></div></body></html>
"""


_GO_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="robots" content="noindex"><title>{title}</title>
<meta http-equiv="refresh" content="0; url={href}"><link rel="canonical" href="{href}">
</head><body><p>Going to <a href="{href}">{title}</a>&hellip;</p></body></html>
"""

# /go/?q=<keyword> is the browser-keyword entry point. The site is static, so the page
# resolves in the browser: fetch /n/<q>.aither.json and follow a web route; anything
# else lands on the directory. Only an https target is ever followed.
_GO_INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>AitherNet keyword</title></head>
<body style="font:15px system-ui;padding:24px"><p id="m">Resolving&hellip;</p><script>
(async () => {
  const m = document.getElementById("m");
  let q = (new URLSearchParams(location.search).get("q") || "").trim().toLowerCase();
  q = q.replace(/\\.aither$/, "");
  if (!/^[a-z0-9-]{2,40}$/.test(q)) { m.textContent = "Type a keyword, like neocities."; return; }
  try {
    const r = await fetch("/n/" + q + ".aither.json");
    if (!r.ok) { m.textContent = q + ".aither is not in the index yet."; return; }
    const hit = await r.json();
    if ((hit.type === "web" || hit.type === "space") && /^https:\\/\\//.test(hit.target)) {
      location.replace(hit.target); return; }
    location.replace("/#" + encodeURIComponent(hit.id));
  } catch (e) { m.textContent = "Could not reach the index."; }
})();
</script></body></html>
"""

_OPENSEARCH = """<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
<ShortName>AitherNet</ShortName><Description>Go to an .aither keyword</Description>
<InputEncoding>UTF-8</InputEncoding>
<Url type="text/html" template="https://{domain}/go/?q={{searchTerms}}"/>
</OpenSearchDescription>
"""


def _write_go(out: Path, idx: "netindex.Index") -> None:
    """/go/<keyword>/ redirects for every .aither name, plus /go/?q= and opensearch.xml."""
    (out / "go").mkdir(parents=True, exist_ok=True)
    (out / "go" / "index.html").write_text(_GO_INDEX, encoding="utf-8")
    (out / "opensearch.xml").write_text(_OPENSEARCH.format(domain=DOMAIN), encoding="utf-8")
    for name, rid in idx.names.items():
        rec = idx.records[rid]
        target = str(rec.route.get("target", ""))
        web = rec.route.get("type") in ("web", "space") and target.startswith("https://")
        href = target if web else f"/#{rid}"
        page = out / "go" / name[: -len(netindex.NAME_SUFFIX)]
        page.mkdir(parents=True, exist_ok=True)
        (page / "index.html").write_text(
            _GO_PAGE.format(title=html.escape(rec.title),
                            href=html.escape(href, quote=True)),
            encoding="utf-8")


def build(root: Path, out: Path, state: "Path | None" = None) -> int:
    records, findings = netindex.load(root)
    if not records:
        print(f"could not build: no records under {root}")
        return 2
    findings += netindex.validate(records)
    health_path = state if state is not None else recheck.DEFAULT_STATE
    health: dict = {}
    if Path(health_path).exists():
        st = recheck.load_state(health_path)
        health = st["entries"]
        findings += recheck.state_findings(st, records)
    if findings:
        for f in findings:
            print(f)
        print("refusing to publish a failing index")
        return 1
    sha = _sha(root)
    idx = netindex.Index(records)
    (out / "n").mkdir(parents=True, exist_ok=True)
    payload = {"source_sha": sha, "records": [_record_dict(r, health) for r in records]}
    (out / "index.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    for name in idx.names:
        hit = idx.resolve(name)
        hit["source_sha"] = sha
        hit["trust"] = netindex.TIERS[netindex.trust(idx.records[hit["id"]])]
        (out / "n" / f"{name}.json").write_text(json.dumps(hit, indent=1), encoding="utf-8")
    (out / "index.html").write_text(_page(records, sha, health), encoding="utf-8")
    _write_go(out, idx)
    _write_agent_files(out, records, sha, health)
    (out / "CNAME").write_text(DOMAIN + "\n", encoding="utf-8")
    hidden = sum(1 for r in records
                 if (health.get(r.id) or {}).get("status") in HIDDEN)
    print(f"built {out}: {len(records)} records ({hidden} hidden by the re-check), "
          f"{len(idx.names)} names, sha {sha[:12]}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--state", type=Path, default=recheck.DEFAULT_STATE,
                    help="re-check state (state/health.json) that decides visibility")
    a = ap.parse_args()
    return build(a.root, a.out, a.state)


if __name__ == "__main__":
    sys.exit(main())
