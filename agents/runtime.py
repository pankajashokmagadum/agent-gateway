"""Where agents meet the gateway.

One gateway, one human sponsor and one credential per agent, set up by
application code before any model runs. Models never see a credential or a
session id: the tool functions in tools.py close over them.

The sponsor comes from the FDE_USER environment variable, standing in for a
login. It is not, and must never be, something the conversation can set.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from gateway.gateway import Gateway
from rag import make_policy_search

DEFAULT_USER = "pnair"


@dataclass
class Runtime:
    gateway: Gateway
    username: str
    session_id: str
    credentials: dict

    def propose(self, agent_id: str, command: str, args: dict, dry_run: bool = False) -> dict:
        args = {k: v for k, v in args.items() if v is not None}
        return self.gateway.propose(self.session_id, agent_id, self.credentials[agent_id],
                                    command, args, dry_run=dry_run)


def start(username: Optional[str] = None, gateway: Optional[Gateway] = None) -> Runtime:
    username = username or os.environ.get("FDE_USER", DEFAULT_USER)
    if gateway is None:
        gateway = Gateway(policy_search=make_policy_search(
            os.environ.get("FDE_RETRIEVER", "auto")))
    elif gateway.policy_search is None:
        gateway.policy_search = make_policy_search(os.environ.get("FDE_RETRIEVER", "auto"))
    credentials = {agent_id: gateway.register_agent(agent_id)
                   for agent_id in gateway.registry.agents}
    return Runtime(gateway, username, gateway.open_session(username), credentials)
