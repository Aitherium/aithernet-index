# Contributing to the AitherNet Index

## The easy way: open an issue

Use **New issue → Submit a site**. The bot:

1. turns your issue into `records/<id>.json`, with the id taken from the URL;
2. checks that the URL answers, and stamps `http-200` or `well-known`;
3. runs `check.py`;
4. opens a pull request that a maintainer reviews.

The bot only processes submissions from GitHub accounts at least 30 days old. Younger
accounts are reviewed by hand.

## The direct way: a pull request

1. Copy a file in `records/` to `records/<id>.json`, where the file name equals the `id`.
2. Fill in `kind`, `title`, an https `url`, `tags`, and optionally `names` (`*.aither`)
   with a `route`, plus `edges`.
3. Run `python check.py` (it must report 0 findings) and `python verify.py --ids <id> --stamp`.
4. Open the PR.

## The required backlink artifact

A listing has to carry **one** artifact that links it back to the index. Without one it
is not approved (or, for entries listed before 2026-11-18, it drops to `warn` after a
30-day grace period). Pick whichever is easiest for your site.

**(a) Owner proof — strongest.** Serve this file from your own host:

`https://<your-host>/.well-known/aithernet.json`

```json
{"records": ["<id>"]}
```

Only whoever controls the domain can serve it, so it also marks the entry
**owner-proven**. Replace `<id>` with your record id (the file name in `records/`, e.g.
`example.com_garden`).

**(b) A link back from the page.** Any one of these, in the page you listed:

```html
<!-- in <head> -->
<link rel="aithernet" href="https://index.aitherium.com/r/example.com_garden">
<meta name="aithernet" content="example.com_garden">

<!-- or anywhere visible in <body> -->
<a href="https://index.aitherium.com/r/example.com_garden">Listed in the AitherNet Index</a>
```

This proves the page points at its entry, **not** who controls the domain, so it never
raises the entry to owner-proven (see `REPUTATION.md`). It is enough to stay listed.
`https://index.aitherium.com/r/<id>` is a stable shortlink (it redirects to the entry
page), so you only have to add it once.

The match is strict: the host must be exactly `index.aitherium.com`, the scheme
`https`, and the id must be exactly yours. A link to a look-alike domain
(`index.aitherium.com.evil.example`), to a different entry, or an anchor with no
visible text does not count.

## The daily re-check

Every listed site is re-checked once a day (`recheck.py`, `.github/workflows/recheck.yml`):

- the artifact above must still be there. A new listing is not approved without it: the
  30-day grace period applies only to entries listed before the rule shipped
  (2026-11-18);
- the page must still redirect to the same host (a server-side redirect *or* a
  `<meta http-equiv=refresh>` / `location=...` redirect) and still be substantially the
  same page (fingerprint of the main visible text; a large change is a token similarity
  below 0.65). A page that serves the checker a different body than it serves a browser
  is a failure too. Hidden markup does not count as the backlink;
- the URL must still answer.

Entries move `active → warn → suspended` (3 failures inside 7 days, or the final host
changed) `→ delisted` (14 days suspended). Failures are counted over a rolling week and
are not cleared by one good day, so a flapping site cannot stay listed. `warn`,
`suspended` and `delisted` are all hidden from the listing and sitemap; `index.json`
still carries `status`, and the entry page stays up with the reason. A clean check
returns it to `active` once the week is no longer mostly failures. Maintainers are told
by one GitHub issue per entry (label `recheck`), closed automatically when it recovers.
Nothing is ever deleted.

Delisting an entry is just deleting its `records/<id>.json` in a PR. The next daily run
prunes its `state/health.json` entry; you do not have to edit the state by hand.

A legitimate rebuild of your page shows up as a content change. A maintainer clears it
with `python recheck.py --accept <id>`, which re-seeds the fingerprint (and records the
acceptance, so the state change is auditable).

## Vouch for an entry

Add yourself to `provenance.vouches`:

```json
"vouches": [{"by": "github:<you>", "at": "2026-11-08", "note": "used it for years"}]
```

You cannot vouch for your own submission. Two vouches on a reachable entry raise it to
**vouched**. See `REPUTATION.md` for why.

## Prove you own a site

Serve this at `https://<your-host>/.well-known/aithernet.json`:

```json
{"records": ["<id>"]}
```

`verify.py` then marks the entry **owner-proven**.

## List or claim a business

Pick the kind `business` on the **Submit a site** form. Its optional fields (about,
category, address, area served, phone, public email, hours) become a `listing` block:

```json
"listing": {
  "description": "Neighbourhood bakery, sourdough and pastries",
  "category": "bakery",
  "area_served": "Springfield",
  "phone": "+1 555 010 0000",
  "hours": ["Mo-Fr 07:00-15:00", "Sa,Su 08:00-12:00"],
  "same_as": ["https://social.example/yourbakery"]
}
```

Rule NI010 rejects unknown fields, over-long text, malformed hours, phones, emails, geo
and non-https links. Each entry gets a page at `/e/<id>/` that publishes the listing as
schema.org JSON-LD (`LocalBusiness`), which search engines and AI agents read. Claiming it
is the owner proof above. Listing asks you to accept no terms and to release no legal
claims; the facts in your file are CC BY 4.0, like every record. Plain-language version:
https://index.aitherium.com/claim/

## Rules

- No paid placements unless the issue says so.
- No fake reviews, sock-puppet vouches, or impersonation. Confirmed cases are removed,
  and the vouchers lose weight.
- Agents may contribute, but must say so (`added_by: agent:<name>`).
