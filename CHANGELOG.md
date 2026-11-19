# Changelog

## Unreleased

- New kind `discord` for a Discord community: a permanent invite (`url`), the server id
  and an optional member band in `listing`; topic tags at the top level. Rule NI011
  refuses anything that is not a `discord.gg` / `discord.com/invite` invite or a server
  id that is not a snowflake. NI010 now restricts a Discord listing to exactly
  `{guild, member_band}`: a description, address, phone or email on one is a finding,
  so no free text and no personal data can reach a public record.
- New provenance method `discord-bot`, ranked with `owner-proven`: the Aither bot is IN
  the server and observed the requester hold Manage Server when they asked. Rule NI012
  refuses the stamp unless it is exactly `{at, by, method, guild, requested_by}`, the
  guild matches `listing.guild`, `requested_by` is `discord:<user id>`, and
  `provenance.added_by` is the account that runs the bot. A Discord entry cannot be
  proved by any other method — `owner-asserted` no longer ranks at tier 2 anywhere.
- The stamp is minted only for a "Submit a site" issue **authored by the bot's account**
  (`DISCORD_BOT_SUBMITTERS`). GitHub sets the issue author, so a `discord` issue from
  anyone else is refused outright; the form no longer offers the kind or its fields.
- `verify.py` re-resolves a Discord invite through `discord.com/api/v10/invites/<code>`
  (public, no token). Because that API proves nothing about permissions, it records
  liveness under `provenance.checked` and never moves the attestation date; it marks the
  entry `stale` (tier 0) when the invite stops resolving or names another server.
  `verify.py --discord-attest` (needs `DISCORD_BOT_TOKEN`) re-derives Manage Server and
  is the only thing that rewrites the stamp.
- `verify.py --stamp` no longer overwrites an unreachable site's provenance with a null
  method (which made `check.py` reject the intake's own record).
- `index.json` and entry pages publish the proof's `at`/`by`/`method` only, never the
  requesting manager's Discord user id.
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
