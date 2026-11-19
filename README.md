# AitherNet Index

A hand-curated map of the internet, kept in git. Every entry is one JSON file
in `records/`, and every entry says who checked it, when and how.

Live at **https://index.aitherium.com**.

## Look up a keyword

Every entry can carry `.aither` keywords, like an old AOL keyword. To resolve
one, fetch its JSON file:

```
curl https://index.aitherium.com/n/docs.aither.json
```

An unknown name returns 404. The resolver never guesses.

## Use it from the shell: the awindex brick

```bash
pip install awindex
awindex resolve neocities          # route + trust tier; exit 1 = not indexed
awindex search "digital garden"
awindex show neocities.org
```

It reads a local checkout when there is one, and https://index.aitherium.com when there
isn't.

## Use it from the browser

Add **AitherNet** as a search engine (the site advertises `opensearch.xml`) with the
keyword `aither`, then type `aither neocities`. Or go straight to
`https://index.aitherium.com/go/<keyword>`.

## Add a site

Open an issue with **Submit a site**. A bot turns it into a pull request, checks that
the URL answers, and a maintainer reviews it. You can also open the PR yourself. See
[CONTRIBUTING.md](CONTRIBUTING.md).

A listing must carry **one** backlink artifact, and the site is re-checked every day:

**(a) owner proof** (keeps the `owner-proven` tier) — serve
`https://<your-host>/.well-known/aithernet.json`:

```json
{"records": ["<id>"]}
```

**(b) a link back from the listed page** (stays listed, not owner-proven) — any one of:

```html
<link rel="aithernet" href="https://index.aitherium.com/r/<id>">
<meta name="aithernet" content="<id>">
<a href="https://index.aitherium.com/r/<id>">Listed in the AitherNet Index</a>
```

`https://index.aitherium.com/r/<id>` is the stable shortlink for an entry, so you add it
once. A look-alike domain or a different id does not count.

## Kept honest: the daily re-check

`recheck.py` runs every day (`recheck.yml`). It re-fetches every listed page, requires
the artifact above, and compares each page with the fingerprint recorded when it was
approved (normalised title + meta description + a hash of the visible text, plus the
final host after redirects). A site that stops answering, drops its backlink, redirects
to another host, or has its text substantially replaced (token similarity < 0.5) moves
`active → warn → suspended → delisted`; a clean check brings it back to `active`.

Delisted does not mean deleted: the entry is hidden from the listing, `index.json` says
`status: delisted`, and its page stays up with the reason. State lives in
`state/health.json`, never in `records/`. See [REPUTATION.md](REPUTATION.md).

The site shows each entry's status, last-checked date and artifact kind, and hides
suspended/delisted entries from the main listing.

## List or claim a business

A business lists itself with the same form (kind `business`) and claims the entry by
serving `/.well-known/aithernet.json` from its own domain. No terms to accept, no legal
claims released. Its facts are published as schema.org data on `/e/<id>/`. How it works:
https://index.aitherium.com/claim/

## For agents

`/llms.txt`, `/robots.txt` (everyone welcome), `/sitemap.xml`, `/index.json` and one
JSON-LD page per entry under `/e/<id>/`.

## Trust

Every entry shows a trust tier computed from evidence:

| tier | meaning |
|---|---|
| submitted | someone suggested it |
| reachable | the bot fetched it |
| owner-proven | the owner serves `/.well-known/aithernet.json` naming it |
| vouched | two other people vouched for it |

Why it works this way, and what comes next: [REPUTATION.md](REPUTATION.md).

## Licence

Records: CC BY 4.0. Code: MIT. See `LICENSE`.

The digital-garden webring (`gardens.aither`) was seeded from
[MaggieAppleton/digital-gardeners](https://github.com/MaggieAppleton/digital-gardeners)
(MIT, Maggie Appleton); every imported garden was live-checked first.
