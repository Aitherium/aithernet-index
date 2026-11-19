# Changelog

## 0.5.0 - 2026-11-18

- **A listing must carry a backlink artifact.** One of: the `/.well-known/aithernet.json`
  owner proof, a `<link rel="aithernet">`, a `<meta name="aithernet">`, or a visible link
  to `https://index.aitherium.com/r/<id>`. Matched against the exact host and id, so
  look-alikes do not count (`artifact.py`).
- **Content fingerprint** of every listed page (normalised title, meta description, a
  hash of the visible text, the final host after redirects), compared on re-check with
  token-set Jaccard similarity (`fingerprint.py`). A changed final host or similarity
  below 0.5 flags the entry.
- **Daily re-check** with a state machine in `state/health.json`:
  `active -> warn -> suspended -> delisted`, recovering to `active` on a clean check,
  with a 30-day artifact grace period for entries listed before this release
  (`recheck.py`, `.github/workflows/recheck.yml`). One GitHub issue per entry that
  needs a human, closed automatically on recovery. It never edits `records/`.
- **The site tells the truth about it**: status, last-checked date and artifact kind per
  entry in `index.json`; suspended/delisted entries hidden from the listing and sitemap
  but still reachable at `/e/<id>/` with the reason; `/r/<id>/` stable shortlinks.
- New rule **NI011** validates `state/health.json` in `check.py`.
- `verify.py --stamp` also records `provenance.fingerprint` at listing time.

## 0.4.0 - 2026-11-13

- New kind `business` with an optional `listing` block (description, category, address,
  area served, phone, email, hours, same_as, geo), validated by rule NI010.
- The submission form takes those fields, so a business owner never writes JSON.
- The site publishes one page per entry at `/e/<id>/` with schema.org JSON-LD, plus
  `/claim/` (how to list or claim a business), `/llms.txt`, `/robots.txt` and `/sitemap.xml`.

## 0.3.0 - 2026-11-08

- Trust reads OSINT evidence (`provenance.evidence`): a sanctions hit or a HIGH/CRITICAL
  threat level is tier 0, and a domain younger than 30 days stays at `reachable`.
  Evidence can only lower trust; shared hosts (github.io and kin) carry no domain verdict.

## 0.2.0 - 2026-11-08

- `awindex mcp`: an MCP server (`index_resolve`, `index_search`, `index_show`) so any
  agent harness can resolve .aither keywords and search the index. Read-only; the
  index location is fixed at start, never a tool argument. `pip install "awindex[mcp]"`.

## 0.1.0 - 2026-11-08

- First release. `awindex resolve | search | show | check` over the AitherNet Index.
- Reads a local checkout of Aitherium/aithernet-index, or https://index.aitherium.com
  when installed without one.
- Trust tiers computed from evidence (submitted, reachable, owner-proven, vouched).
