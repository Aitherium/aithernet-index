#!/usr/bin/env python3
"""Render the AitherNet Index as a static public site (target: index.aitherium.com).

Static on purpose: Pages/CDN serve it, nothing to keep alive, and the git SHA
of the records IS the version every answer came from.

    out/index.html          the directory (keyword list, kinds, tags, edges)
    out/index.json          every record + the source SHA
    out/n/<name>.json       the resolver: GET /n/docs.aither.json -> route
    out/CNAME               index.aitherium.com

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

DOMAIN = "index.aitherium.com"


def _sha(root: Path) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(["git", "-C", str(root), "log", "-1", "--format=%H", "--", "."],
                           capture_output=True, text=True, encoding="utf-8",
                           timeout=30, creationflags=flags)
        return r.stdout.strip() or "uncommitted"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _record_dict(r: netindex.Record) -> dict:
    return {"id": r.id, "kind": r.kind, "title": r.title, "url": r.url, "tags": r.tags,
            "names": r.names, "route": r.route, "edges": r.edges,
            "validated": r.provenance.get("validated", {}),
            "trust": netindex.TIERS[netindex.trust(r)],
            # Where it lives, for explorers (BeadSpace, agents): the URL's host, and the
            # OSINT evidence (domain age, CT, sanctions, threat) that trust was judged on.
            "host": (urlsplit(r.url).hostname or "") if r.url else "",
            "evidence": r.provenance.get("evidence", {})}


def _page(records: list, sha: str) -> str:
    e = html.escape
    rows = []
    for r in sorted(records, key=lambda x: (x.kind, x.title.lower())):
        link = f'<a href="{e(r.url)}">{e(r.title)}</a>' if r.url else e(r.title)
        names = " ".join(f"<code>{e(n)}</code>" for n in r.names)
        tags = " ".join(f'<span class="tag">{e(t)}</span>' for t in r.tags)
        edges = "; ".join(f"{e(x.get('rel', ''))} &rarr; {e(x.get('to', ''))}" for x in r.edges)
        v = r.provenance.get("validated", {})
        tier = netindex.TIERS[netindex.trust(r)]
        rows.append(f"<tr id=\"{e(r.id, quote=True)}\"><td>{e(r.kind)}</td><td>{link}<div class='t'>{tags}</div></td>"
                    f"<td>{names}</td><td class='m'>{edges}</td>"
                    f"<td class='m'>{e(str(v.get('at', '')))} &middot; "
                    f"{e(str(v.get('method', '')))} &middot; <b>{e(tier)}</b></td></tr>")
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
<h1>AitherNet Index</h1>
<p>A hand-curated map of the internet, kept in git. Every entry records who checked it
and how. Go to a keyword at <code>/go/&lt;keyword&gt;</code>; look one up at
<code>/n/&lt;name&gt;.json</code>. Built from {e(sha[:12])}.</p>
<div class="wrap"><table><thead><tr><th>kind</th><th>entry</th><th>keywords</th>
<th>links</th><th>checked</th></tr></thead><tbody>
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


def build(root: Path, out: Path) -> int:
    records, findings = netindex.load(root)
    if not records:
        print(f"could not build: no records under {root}")
        return 2
    findings += netindex.validate(records)
    if findings:
        for f in findings:
            print(f)
        print("refusing to publish a failing index")
        return 1
    sha = _sha(root)
    idx = netindex.Index(records)
    (out / "n").mkdir(parents=True, exist_ok=True)
    payload = {"source_sha": sha, "records": [_record_dict(r) for r in records]}
    (out / "index.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    for name in idx.names:
        hit = idx.resolve(name)
        hit["source_sha"] = sha
        hit["trust"] = netindex.TIERS[netindex.trust(idx.records[hit["id"]])]
        (out / "n" / f"{name}.json").write_text(json.dumps(hit, indent=1), encoding="utf-8")
    (out / "index.html").write_text(_page(records, sha), encoding="utf-8")
    _write_go(out, idx)
    (out / "CNAME").write_text(DOMAIN + "\n", encoding="utf-8")
    print(f"built {out}: {len(records)} records, {len(idx.names)} names, sha {sha[:12]}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=netindex.DEFAULT_ROOT)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    return build(a.root, a.out)


if __name__ == "__main__":
    sys.exit(main())
