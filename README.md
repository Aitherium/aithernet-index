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
pip install git+https://github.com/Aitherium/aithernet-index
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
