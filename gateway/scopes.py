"""Who may do what: human authority levels, agent roles, and delegation.

Three independent limits apply to every action, and the gateway takes the
narrowest of them:

  the human's level     what the person sponsoring the session may do
  the agent's role      what this kind of agent is for
  the delegation chain  a sub-agent never exceeds the agent that delegated to it

All of it lives in code. Scope is policy, and a change to policy should be a
reviewed diff, not a row an agent might one day be able to write.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from .commands import COMMANDS, READS

TIER_RANK = {"access": 1, "edge": 2, "core": 3}


def lower_tier(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """The more restrictive of two write ceilings. None means no writes at all."""
    if a is None or b is None:
        return None
    return a if TIER_RANK[a] <= TIER_RANK[b] else b


@dataclass(frozen=True)
class Level:
    """Standing authority of a human, from users.auth_level."""
    write_ceiling: Optional[str]   # highest tier they may change without approval
    max_risk: int                  # 0 read, 1 reversible, 2 irreversible


LEVELS = {
    "viewer":   Level(None, 0),
    "engineer": Level("access", 1),
    "operator": Level("edge", 1),
    "admin":    Level("core", 2),
}
APPROVER_LEVEL = "admin"


@dataclass(frozen=True)
class Scope:
    commands: frozenset
    write_ceiling: Optional[str]
    max_risk: int

    def narrowed_by(self, other: "Scope") -> "Scope":
        return Scope(self.commands & other.commands,
                     lower_tier(self.write_ceiling, other.write_ceiling),
                     min(self.max_risk, other.max_risk))

    def within(self, other: "Scope") -> bool:
        return self.narrowed_by(other) == self


@dataclass(frozen=True)
class AgentSpec:
    agent_id: str
    role: str
    parent: Optional[str] = None


ROLES = {
    # The planner calls nothing itself. Its scope is the ceiling for the
    # agents it delegates to.
    "planner":     Scope(frozenset(COMMANDS), "edge", 2),
    "inventory":   Scope(READS, None, 0),
    "remediation": Scope(frozenset({2, 4, 5, 6, 7, 8, 9, 10, 11}), "edge", 2),
}

AGENTS = {
    "planner-01":     AgentSpec("planner-01", "planner"),
    "inventory-01":   AgentSpec("inventory-01", "inventory", parent="planner-01"),
    "remediation-01": AgentSpec("remediation-01", "remediation", parent="planner-01"),
}


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self, roles: Mapping[str, Scope] = ROLES,
                 agents: Mapping[str, AgentSpec] = AGENTS, check: bool = True):
        self.roles, self.agents = dict(roles), dict(agents)
        if check:
            self.check()

    def chain(self, agent_id: str) -> list:
        """The agent and its ancestors, root first."""
        seen, node = [], agent_id
        while node is not None:
            if node in seen or node not in self.agents:
                raise RegistryError(f"broken delegation chain at {node!r}")
            seen.append(node)
            node = self.agents[node].parent
        return list(reversed(seen))

    def effective_scope(self, agent_id: str) -> Scope:
        """Intersection of every role along the chain. It can only narrow."""
        chain = self.chain(agent_id)
        scope = self.roles[self.agents[chain[0]].role]
        for link in chain[1:]:
            scope = scope.narrowed_by(self.roles[self.agents[link].role])
        return scope

    def check(self) -> None:
        """Refuse to start if any agent is granted more than its parent."""
        for spec in self.agents.values():
            if spec.role not in self.roles:
                raise RegistryError(f"{spec.agent_id}: unknown role {spec.role!r}")
            self.chain(spec.agent_id)
            if spec.parent is not None:
                own = self.roles[spec.role]
                parent = self.effective_scope(spec.parent)
                if not own.within(parent):
                    raise RegistryError(
                        f"{spec.agent_id}: role {spec.role!r} exceeds the scope of "
                        f"its parent {spec.parent}")
