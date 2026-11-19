# Changelog

## 0.5.1 - 2026-11-18

Hardening of the daily re-check after review. Every entry point now fails closed.

- **Flapping no longer defeats the suspend rule.** Failures are counted over a rolling
  7-day window and are not reset by one good day; a site down two days in three is
  suspended on day four and does not return to `active` until the window is clean.
  `warn` is hidden from the published listing too (`build_site.HIDDEN`).
- **Grace is only for pre-existing listings.** A record validated on/after
  `grace_starts` (and any listing with no approval date) gets no grace: without the
  artifact it is not approved. `verify.py` no longer stamps `http-200` for a page with
  no artifact, and new rule **NI022** rejects such a record offline.
- **Fingerprint is template- and asset-aware.** Text comes from `<main>`/`<article>` (or
  the body without nav/header/footer/aside); a Bloom containment guard catches a body
  swap behind a shared template; threshold raised to 0.65. Text-less pages are compared
  by `assets_sha` (images, DOM ids/classes, inline scripts) instead of an all-zero
  signature, and empty signatures no longer compare equal.
- **Hidden markup is not a backlink.** Anchors under `display:none`, `hidden`,
  `aria-hidden`, off-screen/zero-size/font-size-0, `opacity:0`, a hiding CSS class, or
  only zero-width text are rejected, and `<link>`/`<meta>` inside
  `<template>`/`<noscript>`/`<svg>` no longer count.
- **Client-side redirects and UA cloaking are failures.** `<meta http-equiv=refresh>` and
  `location=...` redirects to another host are `host-changed`; the page is fetched as a
  browser *and* as the checker, and a material difference is `cloaking` (needs review).
- **The state baseline cannot be silently re-seeded.** NI021 requires a baseline to
  match the fingerprint stamped on the record unless a maintainer explicitly accepted a
  re-seed (`baseline_source: accepted` + `accepted_at`); a cleared baseline is a
  `baseline-missing` failure. The workflow now runs `check.py` before committing.
- **Delisting no longer breaks main.** A state entry for a deleted record is pruned by
  the next run and is not a finding, so a delist PR does not need to hand-edit state.
- **Exemptions are by host as well as kind.** `world`/`room` records on `discord.gg` or
  first-party `aitherium.com` services are exempt instead of being suspended for a
  backlink those hosts cannot serve.
- **`check.py --root records` judges the state**, and the re-check's state commit now
  triggers the Pages rebuild (`workflow_run`), so an invalidation reaches the live site.
- Rule numbers moved to **NI020-NI022** so this branch and `feat/discord-owner-proof`
  (NI011/NI012) do not claim the same number for different rules.

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
- New rule **NI020** validates `state/health.json` in `check.py` (NI021/NI022 add the
  baseline and artifact checks in 0.5.1).
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
