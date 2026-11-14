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
