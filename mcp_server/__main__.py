"""MCP server exposing one agent's commands. Every call goes through the gateway.

    python -m mcp_server --agent remediation-01          (stdio, the default)
    FDE_USER=tkim python -m mcp_server --agent inventory-01

One server process is one agent identity acting for one human sponsor. Both
are fixed by whoever starts the process (--agent, FDE_USER), never by the
client: an MCP client can choose which tool to call and with what arguments,
and nothing else. The tools listed are exactly the commands in that agent's
scope, and the gateway re-checks scope, sponsor, arguments, limits and
approvals on every call.

Several servers can run at once. They share the database and the hash-chained
audit log, which is locked per append.
"""

from __future__ import annotations

import argparse
import os
import sys

from agents.runtime import start
from agents.tools import scoped_tools

try:                                         # mcp 2.x
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:                          # mcp 1.x
    from mcp.server.fastmcp import FastMCP as Server


def build(agent_id: str, username: str = None) -> Server:
    rt = start(username)
    if agent_id not in rt.credentials:
        raise SystemExit(f"{agent_id!r} is not a registered agent")
    server = Server(
        f"fleet-{agent_id}",
        instructions=("Fleet operations for one agent. Each tool proposes an action; the reply "
                      "says ALLOW or DENY with reasons. A DENY means nothing happened."))
    for name, fn in scoped_tools(rt, agent_id).items():
        server.add_tool(fn, name=name)
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_server")
    parser.add_argument("--agent", default=os.environ.get("FDE_AGENT"),
                        help="agent identity this server acts as, e.g. remediation-01")
    parser.add_argument("--transport", default="stdio",
                        choices=("stdio", "sse", "streamable-http"))
    args = parser.parse_args(argv)
    if not args.agent:
        parser.error("--agent (or FDE_AGENT) is required")
    build(args.agent).run(transport=args.transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
