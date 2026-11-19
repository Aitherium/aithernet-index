# Changelog

## Unreleased

- New kind `discord` for a Discord community: a permanent invite (`url`), the server id
  and an optional member band in `listing`; topic tags at the top level. Rule NI011
  refuses anything that is not a `discord.gg` / `discord.com/invite` invite, a server id
  that is not a snowflake, or a listing that carries more than the guild and the band
  (no member lists, no personal data).
- New provenance method `discord-bot`, ranked with `owner-proven`: the Aither bot is IN
  the server and observed the requester hold Manage Server when they asked. Rule NI012
  refuses the stamp unless it is exactly `{at, by, method, guild, requested_by}`, the
  guild matches `listing.guild`, and `requested_by` is `discord:<user id>`.
- `verify.py` re-resolves a Discord invite through `discord.com/api/v10/invites/<code>`
  (public, no token) and marks the entry `stale` (tier 0) when it stops resolving or
  names another server. It never manufactures the `discord-bot` stamp.
- The site shows the badge **owner-proven by the Aither bot** on Discord entries.

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
