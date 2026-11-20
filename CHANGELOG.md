# Changelog

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
