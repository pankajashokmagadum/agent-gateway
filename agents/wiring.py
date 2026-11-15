"""Three ways to put the gateway between an agent and its tools.

FDE_TOOLS=direct  (default) each tool function proposes to the gateway itself.
FDE_TOOLS=guard   tools are declarations only; an ADK before_tool_callback
                  intercepts every call and returns the gateway's reply. A tool
                  body never runs, so a tool added later without a gateway
                  call cannot act: unknown commands are denied.
FDE_TOOLS=mcp     the agent reaches its tools through an MCP server
                  (mcp_server/), one server process per agent identity, with
                  the gateway on the far side of the protocol boundary.

The decision is identical in all three. They differ only in where the
interception sits.
"""

from __future__ import annotations

import functools
import os
import sys

from .runtime import Runtime
from .tools import scoped_tools

MODES = ("direct", "guard", "mcp")


def mode() -> str:
    chosen = os.environ.get("FDE_TOOLS", "direct")
    if chosen not in MODES:
        raise ValueError(f"FDE_TOOLS must be one of {', '.join(MODES)}; got {chosen!r}")
    return chosen


def declaration_only(fn):
    """Same name, signature and docstring, so the model sees the same tool.
    The body refuses to run: in guard mode only the callback may answer."""
    @functools.wraps(fn)
    def stub(*args, **kwargs):
        raise RuntimeError(f"{fn.__name__} was executed without passing the gateway")
    return stub


def gateway_guard(rt: Runtime, agent_id: str):
    """An ADK before_tool_callback. Returning a dict replaces the tool call."""
    def before_tool(tool, args, tool_context):
        args = dict(args or {})
        dry_run = bool(args.pop("dry_run", False))
        return rt.propose(agent_id, tool.name, args, dry_run)
    return before_tool


def mcp_toolset(rt: Runtime, agent_id: str):
    from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
    from mcp import StdioServerParameters

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, FDE_USER=rt.username, FDE_AGENT=agent_id,
               PYTHONPATH=os.pathsep.join(filter(None, [root, os.environ.get("PYTHONPATH")])))
    return McpToolset(connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command=sys.executable, args=["-m", "mcp_server", "--agent", agent_id],
            env=env, cwd=root),
        timeout=30))


def attach(rt: Runtime, agent_id: str) -> dict:
    """Keyword arguments for Agent(...): its tools and, in guard mode, the callback."""
    chosen = mode()
    if chosen == "mcp":
        return {"tools": [mcp_toolset(rt, agent_id)]}
    tools = scoped_tools(rt, agent_id)
    if chosen == "guard":
        return {"tools": [declaration_only(fn) for fn in tools.values()],
                "before_tool_callback": gateway_guard(rt, agent_id)}
    return {"tools": list(tools.values())}
