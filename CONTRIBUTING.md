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
   with a `route`, plus `edges`. The `url` is required for page kinds (`garden`,
   `site`, `world` with a site, `org`, `business`, ...). Kinds that have no page of
   their own (`gate`, `discord`, `community`, and route-only `world` entries) may
   omit it; the gate reports their network rules as *not judged* instead of failing.
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

## The listing gate (required before a pull request can merge)

Every pull request that adds or changes a file in `records/` runs the
`listing-gate` check. It fails unless every record it touches passes. A second
required check, `aithernet/reputation`, is posted by the fleet from the
ShadowBroker OSINT board (it needs a secret, so it does not run in GitHub
Actions). **Both are required by branch protection: a listing PR cannot merge
until they are green.**

Run it yourself before pushing:

```bash
python -m unittest discover -s tests -v                  # the rules, no network
python tools/listing_gate.py --base origin/main --head HEAD
python tools/listing_gate.py --records records/<id>.json # one record
```

### 1. Backlink artifact (must be present *now*)

The listed page has to carry one of these, pointing at **this** entry. Exact host
`https://index.aitherium.com` and exact id only: a look-alike host
(`index.aitherium.com.evil.example`) or another entry's id does not count.

```html
<!-- strongest: only the host's owner can serve it -->
<!-- https://<your-host>/.well-known/aithernet.json -->
{"records": ["<id>"]}

<!-- in the page -->
<link rel="aithernet" href="https://index.aitherium.com/r/<id>">
<meta name="aithernet" content="<id>">
<a href="https://index.aitherium.com/r/<id>">Listed on AitherNet</a>
```

The visible link must have anchor text. Discord-kind records are exempt: their
invite is re-checked by the bot instead. **Failure means:** the page does not
point back at its entry. Add one of the snippets above (the `.well-known` file is
the one that also raises trust to *owner-proven*).

### 2. Health

The record's https URL must answer 2xx within 15 seconds, with a valid TLS
certificate (not expired, hostname matches), and the page a reader gets must
still be the record's host (or its `www`). It needs a `<title>` and must not be a
parked/for-sale page. **Failure means:** the site is down, mis-certificated,
redirecting somewhere else (including a network block page), title-less, or
parked. Fix the site; a redirect to another host is not the listing.

### 3. Reputation (keyless)

- **Poisoned DNS:** Cloudflare's filtering resolver (1.1.1.2) and Quad9's
  filtered resolver (9.9.9.9) are compared with their unfiltered counterparts.
  A domain blocked only by the filtered side (0.0.0.0, NXDOMAIN, EDE(16)
  "Censored") is a malicious verdict. A source that cannot be reached is reported
  as *not judged*, never as a pass.
- **Domain age:** an RDAP registration younger than 30 days fails unless a
  maintainer adds the **`listing-age-accepted`** label to the pull request.
- **OTX:** more than 5 pulses is HIGH and fails; 1-5 pulses and a whitelist row
  are recorded but do not block.
- **Phishing feeds:** an exact host match in OpenPhish or the malware-filter
  phishing domain list fails.
- **URLhaus:** requires an Auth-Key since 2026, so it reports *not judged* in CI
  (no new CI secret is created). The fleet's `aithernet/reputation` status covers
  the board's own verdict.

**Failure means:** the domain is on a block/phishing list or too new. Remove it,
or (for a new-but-legitimate domain) ask a maintainer for the label.

### Not judged: url-less kinds

The rules above need a `url`. A record of a kind listed in
`no_url_exempt_kinds` (`gate`, `discord`, `community`, route-only `world`) may have
none; the artifact, health, reputation and look-alike rules then report
**SKIP — not judged** and the record passes on the rules that *can* judge it
(schema and provenance). A url-less record of any other kind still fails: that is
usually a broken submission, not a route entry.

### 4. Poisoned / look-alike names

The host must not be a typosquat (edit distance <= 2 on the registrable label,
for labels of 5+ characters), a homoglyph (`g00gle.com`, `paypa1.com`), an IDN
confusable, or a brand on someone else's registrable domain
(`discord-nitro.com`, `google.com.evil.example`). It is compared against every
host already listed and the protected list in `tools/gate_config.json`.
Subdomains of a listed or protected domain (`blog.aitherium.com`, a GitHub Pages
site) are fine. **Failure means:** use the real domain; impersonation is removed,
not relabelled.

### Where the results appear

- The job summary table on the Actions run.
- One sticky pull request comment, updated on every push (never a new comment
  per push).
- Locally: `python tools/listing_gate.py ...` prints one line per rule, per
  record, and exits non-zero on any failure.

### Branch protection (applied by a maintainer, not by CI)

`tools/branch_protection.json` is the exact body for

```
PUT /repos/Aitherium/aithernet-index/branches/main/protection
```

It requires `listing-gate` **and** `aithernet/reputation` on every head. Both
checks run on every pull request (not path-filtered), so neither can sit at
"Expected" on a PR that changes no record. A maintainer applies it by hand after
both PRs are merged and one pull request has shown both checks green; **no
workflow applies it**, and it is not applied as part of these PRs.

Rules live in `tools/listing_gate.py`, `tools/reputation.py` and
`tools/artifact_check.py`; policy (age limit, label name, protected domains,
parked markers) lives in `tools/gate_config.json`. Every rule has a fixture
test under `tests/` and the tests never touch the network.
