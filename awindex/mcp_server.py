"""An MCP server for awindex: resolve .aither keywords and search the AitherNet Index.

    pip install "awindex[mcp]"

then point a client at `awindex mcp`:

    {"mcpServers": {"awindex": {"command": "awindex", "args": ["mcp"]}}}

Read-only. The index location is fixed when the server starts (a local checkout via
--root / AWINDEX_ROOT, else https://index.aitherium.com) and is never a tool argument,
so a model cannot point the server at a host of its choosing. Every answer carries the
entry's trust tier, which is computed from evidence and never typed in by a submitter.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

from . import cli, netindex

_INSTALL_HINT = 'awindex mcp needs the MCP SDK: pip install "awindex[mcp]"'
_INSTRUCTIONS = (
    "awindex answers from a hand-curated, git-reviewed map of the internet. Use "
    "index_resolve for an .aither keyword (like an old AOL keyword) and index_search to "
    "find reviewed sites, digital gardens, rooms and spaces. Each hit has a trust tier: "
    "submitted < reachable < owner-proven < vouched. Prefer higher tiers."
)
_MAX_QUERY = 256


class Tools:
    """The tool bodies, plain functions so they are testable without the MCP SDK."""

    def __init__(self, root: Optional[Path] = None, web: bool = False):
        self._idx = None if web else cli._local(root)

    def _rows(self) -> list:
        return cli._all(self._idx)

    def resolve(self, name: str) -> dict:
        name = (name or "").strip().lower().rstrip(".")
        if not name.endswith(netindex.NAME_SUFFIX):
            name += netindex.NAME_SUFFIX
        if self._idx is not None:
            hit = self._idx.resolve(name)
            if hit:
                hit["trust"] = netindex.TIERS[netindex.trust(self._idx.records[hit["id"]])]
        else:
            hit = cli._fetch(f"/n/{name}.json")
        return hit or {"name": name, "found": False}

    def search(self, query: str, limit: int = 10) -> list:
        query = (query or "")[:_MAX_QUERY]
        toks = [t for t in query.lower().split() if t]
        limit = max(1, min(int(limit), 50))
        scored = []
        for r in self._rows():
            hay = " ".join([r["id"], r["title"], *r.get("tags", []),
                            *r.get("names", [])]).lower()
            s = sum(1 for t in toks if t in hay)
            if s:
                scored.append((-s, r["id"], r))
        scored.sort(key=lambda x: (x[0], x[1]))
        return [{k: r.get(k) for k in ("id", "kind", "title", "url", "names", "tags", "trust")}
                for _, _, r in scored[:limit]]

    def show(self, entry_id: str) -> dict:
        for r in self._rows():
            if r["id"] == entry_id:
                return r
        return {"id": entry_id, "found": False}


def _build_mcp_server(name: str, instructions: str):
    """The 2.x MCPServer when present, else the 1.x FastMCP. Same tool surface."""
    try:
        from mcp.server import MCPServer  # type: ignore[attr-defined]
        return MCPServer(name=name, instructions=instructions)
    except ImportError:
        pass
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise ImportError(_INSTALL_HINT) from exc
    return FastMCP(name=name, instructions=instructions)


def build_server(root: Optional[Path] = None, web: bool = False):
    tools = Tools(root, web)
    server = _build_mcp_server("awindex", _INSTRUCTIONS)

    @server.tool()
    def index_resolve(name: str) -> dict:
        """Resolve an .aither keyword (e.g. "neocities" or "neocities.aither") to its route
        and trust tier. Returns {"found": false} when the keyword is not indexed."""
        return tools.resolve(name)

    @server.tool()
    def index_search(query: str, limit: int = 10) -> list:
        """Search reviewed entries (sites, digital gardens, rooms, spaces) by words.
        Each result carries its trust tier."""
        return tools.search(query, limit)

    @server.tool()
    def index_show(entry_id: str) -> dict:
        """One entry by id, with its links (edges) and how it was validated."""
        return tools.show(entry_id)

    return server


def main(root: Optional[Path] = None, web: bool = False) -> int:
    """Serve over stdio. Blocks until the client disconnects."""
    try:
        server = build_server(root, web)
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        asyncio.run(server.run_stdio_async())
    except KeyboardInterrupt:
        return 130
    return 0
